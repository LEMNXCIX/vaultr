//! Integration coverage for the **reset** paths over HTTP.
//!
//! `vltr reset` exists for someone who has lost their master password, which
//! makes one thing load-bearing and easy to get wrong: a tombstone is a
//! *metadata* write, so the remote can be emptied of live secrets by a device
//! that cannot decrypt a single byte it is wiping. These tests run that against
//! `support::Remote`, the stateful in-process PostgREST, and assert on the bytes
//! the client actually put on the wire — see the module docs of `support` for
//! why nothing here can reach the keyring or Supabase.
//!
//! The four tests, in order of how much they hold up:
//!
//! 1. `reset_remote` tombstones every row byte-for-byte, with no master key.
//! 2. The `pending_local_reset` marker survives a failed push and is cleared
//!    only once the wipe lands.
//! 3. Adopting the remote key re-pushes the **parents**, so the reset's own
//!    tombstones cannot delete the vault the user chose to keep (the silent
//!    data-loss bug; also the place where "reset", not "password changed" is
//!    proven).
//! 4. A `sync()` on a device with a pending reset finishes the wipe *and*
//!    completes, instead of aborting into a dead end.
//!
//! Every test serializes on `Remote`'s process-global env-var mutex, and builds
//! its vaults with `App::open_in_memory`, so `session::save_master_key(None,
//! ..)` short-circuits and the keyring is never consulted.

mod support;

use secrecy::SecretString;
use serde_json::Value;
use support::{block_on, Remote, Store};
use vltr_core::{App, CoreError};

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// An initialized, unlocked vault with one project, two environments and two
/// variables. In-memory on purpose: no `App` in this file can write a keyring
/// entry.
fn seeded_vault(password: &str) -> App {
    let mut app = App::open_in_memory().unwrap();
    app.init(secret(password)).unwrap();
    app.create_project("Fudi", None, None, None).unwrap();
    app.create_environment("Fudi", "staging").unwrap();
    app.set_variable("Fudi", "local", "TOKEN", "live-value", None)
        .unwrap();
    app.set_variable("Fudi", "staging", "TOKEN", "staging-value", None)
        .unwrap();
    app
}

/// The load-bearing shared assertion: a tombstone flips `deleted` and changes
/// **nothing else**.
///
/// `before` is what the server held when the wipe started, `after` what it holds
/// now. If a single `value_encrypted` or `nonce` byte moved, a device still
/// holding the pre-wipe key would find a row it can no longer read — which is
/// worse than the wipe, because it is silent.
///
/// Rows without ciphertext (projects, environments) are still asserted to come
/// back flagged deleted.
fn assert_tombstoned_preserving_ciphertext(before: &[Value], after: &[Value], what: &str) {
    assert_eq!(
        before.len(),
        after.len(),
        "{what}: the wipe must tombstone exactly the rows it found, not add or drop any"
    );
    for old in before {
        let id = old["id"].as_str().expect("every pushed row has an id");
        let new = after
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("{what}: row {id} disappeared from the remote"));
        assert_eq!(
            new["deleted"], true,
            "{what}: row {id} must come back flagged deleted, not dropped"
        );
        if old.get("value_encrypted").is_some() {
            assert_eq!(
                new["value_encrypted"], old["value_encrypted"],
                "{what}: row {id} must keep its ciphertext byte for byte — a changed \
                 blob is unreadable to every device that still holds the old key"
            );
            assert_eq!(
                new["nonce"], old["nonce"],
                "{what}: row {id} must keep its nonce byte for byte"
            );
        }
    }
}

/// Bodies of every `POST /rest/v1/<table>` after `mark`, keyed by table.
fn pushed_bodies(remote: &Remote, mark: usize, table: &str) -> Vec<Vec<Value>> {
    remote
        .rest_requests_after(mark)
        .into_iter()
        .filter(|r| r.method == "POST" && r.path == format!("/rest/v1/{table}"))
        .map(|r| serde_json::from_str::<Vec<Value>>(&r.body).expect("a JSON array of rows"))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. The whole premise: wipe the remote with no master key
// ---------------------------------------------------------------------------

/// `reset_remote` must empty the remote of live secrets on a device that holds
/// no key at all, and must do it by *not touching the bytes*: every row comes
/// back flagged deleted with its ciphertext and nonce identical to what was
/// pulled.
///
/// The setup is what makes the byte-identity assertion impossible to fake: a
/// second device rekeys first, so the ciphertexts the wipe tombstones are ones
/// this device cannot decrypt — it has neither the key nor, after `lock()`, any
/// key at all. An implementation that "helpfully" re-encrypted or cleared them
/// could not produce the original bytes here.
///
/// Also asserted, because they are what other devices read to make sense of the
/// wipe:
///
/// * `key_epoch = remote + 1`. The local epoch is a placeholder invented by
///   `reset_local` from a counter that has nothing to do with the server's, and
///   here the two disagree on purpose (`2` vs `2` remote+1 vs `3`) — an
///   implementation that echoed the local value would write `2` and *lower* the
///   server's.
/// * `key_change = "reset"`, which is the only thing that tells the next device
///   to ask instead of silently adopting.
/// * the **local** salt/verifier, never the row being replaced. Observable
///   behaviourally: a fresh device can bootstrap with the new password and
///   cannot with the old one.
/// * projects before environments before variables, or the server's FKs reject
///   the wipe.
///
/// Fails against: any impl that re-encrypts or clears `value_encrypted`/`nonce`
/// on tombstone; one that publishes the *remote* salt/verifier it is replacing;
/// one that writes `key_epoch = meta.key_epoch` (lower) or `remote.key_epoch`
/// (no bump at all); one that pushes children before parents; one that routes
/// `reset_remote` through `require_key()` (it would not even run locked).
#[test]
fn reset_remote_tombstones_every_row_without_a_master_key_and_changes_no_byte() {
    let remote = Remote::start();
    remote.login();

    // The device that lost its password.
    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");

    // Another device rekeys in the meantime. This does two things: it moves the
    // server's counter ahead of this device's local one, so `remote + 1` is
    // distinguishable from the local placeholder, and it replaces the variable
    // ciphertext with blobs this device cannot decrypt.
    let mut b = App::open_in_memory().unwrap();
    block_on(b.bootstrap_from_remote(secret("old-password"))).expect("bootstrap");
    block_on(b.sync()).expect("the other device pulls the rows");
    assert_eq!(b.rekey(secret("other-password")).unwrap(), 2);
    block_on(b.sync()).expect("the other device publishes the rekey");

    let (remote_epoch, salt_before, projects_before, envs_before, vars_before) = {
        let store = remote.store();
        (
            store
                .vault_epoch()
                .expect("the other device pushed vault meta"),
            store.vault_salt().expect("vault salt on the server"),
            store.projects().to_vec(),
            store.environments().to_vec(),
            store.variables().to_vec(),
        )
    };
    assert_eq!(remote_epoch, 2, "the rekey moved the server counter to 2");
    assert_eq!(vars_before.len(), 2);

    // The reset itself, run the way a user who cannot decrypt anything runs it.
    let local_placeholder = a.reset_local(secret("new-password")).unwrap();
    assert_eq!(
        local_placeholder, 2,
        "reset_local installs a placeholder advanced from the LOCAL epoch, which \
         happens to equal the remote's here — which is exactly why the test then \
         asserts the published epoch is neither value"
    );
    a.lock().unwrap();
    assert!(!a.is_unlocked(), "from here on this device holds no key");
    assert!(
        a.get_variable("Fudi", "local", "TOKEN").is_err(),
        "and it can read nothing: the rows are gone with the old key"
    );

    let mark = remote.request_mark();
    let count = block_on(a.reset_remote()).expect("the wipe must need no master key");
    assert_eq!(count, 5, "1 project + 2 environments + 2 variables");

    // Parents before children: the server enforces the same FKs.
    let rest = remote.rest_requests_after(mark);
    let push_order: Vec<&str> = rest
        .iter()
        .filter(|r| r.method == "POST" && r.path != "/rest/v1/vaults")
        .map(|r| r.path.as_str())
        .collect();
    assert_eq!(
        push_order,
        vec![
            "/rest/v1/projects",
            "/rest/v1/environments",
            "/rest/v1/variables"
        ],
        "the wipe must push projects before environments before variables; a \
         server that enforces FKs rejects the other order"
    );
    assert_eq!(
        pushed_bodies(&remote, mark, "vaults").len(),
        1,
        "the new vault meta goes out first, before any row"
    );

    // The server state.
    let store = remote.store();
    assert_tombstoned_preserving_ciphertext(&projects_before, store.projects(), "projects");
    assert_tombstoned_preserving_ciphertext(&envs_before, store.environments(), "environments");
    assert_tombstoned_preserving_ciphertext(&vars_before, store.variables(), "variables");
    assert_eq!(
        store.vault_epoch(),
        Some(remote_epoch + 1),
        "the reset must publish remote + 1 so the server counter only ever moves forward"
    );
    assert_ne!(
        store.vault_epoch(),
        Some(local_placeholder),
        "the local placeholder is not the server's epoch: writing it back would \
         LOWER the counter and break the next device's reset detection"
    );
    assert_eq!(
        store.vault_key_change().as_deref(),
        Some("reset"),
        "the only signal another device gets to ask the user instead of adopting"
    );
    assert_ne!(
        store.vault_salt().as_deref(),
        Some(salt_before.as_str()),
        "the meta of the row being wiped must not be echoed back, or the server \
         advertises a key domain nobody holds"
    );
    drop(store);

    // The published meta is a working key domain, and it is the reset device's:
    // derivable and verifiable from the remote row alone, with the NEW password
    // and with no other. The old domain is gone.
    let mut fresh = App::open_in_memory().unwrap();
    block_on(fresh.bootstrap_from_remote(secret("new-password")))
        .expect("the remote must advertise the reset device's own new domain");
    let mut stale = App::open_in_memory().unwrap();
    block_on(stale.bootstrap_from_remote(secret("old-password")))
        .expect_err("the pre-reset domain must no longer open the remote vault");

    // And locally: initialized, empty, marker cleared.
    assert!(a.is_initialized().unwrap());
    assert!(
        a.list_projects().unwrap().is_empty(),
        "reset_local must have left the local vault empty"
    );
    assert!(
        !a.pending_reset().unwrap(),
        "a landed wipe must clear pending_local_reset"
    );
}

// ---------------------------------------------------------------------------
// 2. The marker: the only thing that makes an interrupted wipe retryable
// ---------------------------------------------------------------------------

/// `pending_local_reset` is the whole retry mechanism: it is the only record
/// that the local vault moved to a new domain and the remote wipe still has to
/// happen. Clear it on the failure path and the wipe is stranded forever — the
/// device holds a new salt, the server holds the old one, and every later sync
/// aborts with `RemoteKeyChanged`, which is a dead end for the very user who
/// reset because they lost the password.
///
/// The three phases fail on three different breaks:
///
/// * a failed push leaves the marker set → phase 2 can happen at all;
/// * a successful push clears it → phase 3, where a leftover marker would send
///   the device back into the wipe branch and re-push the vault meta on a
///   settled vault;
/// * the failed push changed nothing on the server → phase 2's tombstones are
///   built from the original rows.
///
/// Fails against: an impl that removes the marker before/independently of a
/// successful push (phase 1 and 3); one that writes partial state on a failed
/// push (phase 1's untouched-server assertions); one that never removes it
/// (phase 3).
#[test]
fn the_pending_reset_marker_survives_a_failed_wipe_and_is_cleared_only_once_it_lands() {
    let remote = Remote::start();
    remote.login();

    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");
    a.reset_local(secret("new-password")).unwrap();
    assert!(a.pending_reset().unwrap(), "the reset set the marker");

    let (salt_before, epoch_before, vars_before) = {
        let store = remote.store();
        (
            store.vault_salt().expect("vault salt"),
            store.vault_epoch().expect("vault epoch"),
            store.variables().to_vec(),
        )
    };
    assert_eq!(epoch_before, 1);

    // Phase 1: the wipe's vault-meta push fails.
    remote.store().fail_next_vault_push(1);
    let err = block_on(a.reset_remote()).expect_err("the injected 500 must surface");
    assert!(
        matches!(err, CoreError::Sync(_)),
        "expected a transport error, got {err:?}"
    );
    assert!(
        a.pending_reset().unwrap(),
        "THE marker must survive a failed wipe: clearing it here strands the \
         reset permanently — nothing left to retry it and the next sync aborts \
         with RemoteKeyChanged"
    );
    {
        let store = remote.store();
        assert_eq!(
            store.vault_salt().as_deref(),
            Some(salt_before.as_str()),
            "a failed push must not have changed the server"
        );
        assert_eq!(
            store.variables(),
            vars_before.as_slice(),
            "a failed push must not have tombstoned anything"
        );
        for row in store.variables() {
            assert_eq!(row["deleted"], false, "the rows are still live");
        }
    }

    // Phase 2: the retry lands, and the marker goes with it.
    let count = block_on(a.reset_remote()).expect("the retry must finish the wipe");
    assert_eq!(count, 5, "1 project + 2 environments + 2 variables");
    assert!(
        !a.pending_reset().unwrap(),
        "a landed wipe must clear the marker, or every later sync re-enters the \
         wipe branch"
    );
    {
        let store = remote.store();
        assert_tombstoned_preserving_ciphertext(&vars_before, store.variables(), "variables");
        assert_eq!(store.vault_epoch(), Some(epoch_before + 1));
        assert_eq!(store.vault_key_change().as_deref(), Some("reset"));
    }

    // Phase 3: prove the marker is gone rather than merely inert — a settled
    // post-reset vault has nothing to announce, so a second `POST /vaults`
    // would be the marker's ghost re-running the wipe.
    let mark = remote.request_mark();
    block_on(a.sync()).expect("a settled post-reset vault syncs normally");
    let log = remote.rest_log_after(mark);
    assert!(
        !log.iter().any(|r| r == "POST /rest/v1/vaults"),
        "the marker is still set: the sync re-entered the wipe branch; log: {log:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Adoption re-pushes the parents (the silent data loss)
// ---------------------------------------------------------------------------

/// The bug this test exists for, end to end.
///
/// Adoption used to re-queue only variables. Projects and environments were
/// therefore never pushed, the pull that followed won LWW against the reset's
/// tombstones (whose `updated_at` was newer), `cascade_tombstones` took the
/// children — and the user, who had chosen "conservar lo local", was told
/// "Sincronización completada" with their project deleted.
///
/// The load-bearing assertions, in order of directness:
///
/// * adoption's retry **pushes** `projects` and `environments` rows, and every
///   one of them carries `deleted = false`. Against the bug there is no
///   `POST /rest/v1/projects` at all, so this fails before anything else is
///   even checked.
/// * what is left on the server after the retry has no tombstone on the parents.
/// * the retry reports `deleted_pulled == 0`: nothing was deleted, because the
///   user asked to keep it.
/// * the vault is still there afterwards, with both values readable.
///
/// It also carries the divergence assertion (brief item 5): the device left
/// behind by the reset is in an *older* domain, and the guard must answer
/// `RemoteReset` — carrying the reset's own `key_change` and the epoch the wipe
/// published — not `RemoteKeyChanged`. The difference is whether the CLI can
/// ask the user what to do, instead of demanding the password they just lost.
///
/// Fails against: adoption built on `apply_key_rotation` instead of
/// `apply_key_rotation_dirtying_parents` (the bug); an impl that pushes the
/// parents but forgets `deleted = false`; a merge that applies a remote
/// tombstone against a local row it just pushed.
#[test]
fn adopting_the_remote_key_re_pushes_the_parents_so_the_wipe_cannot_delete_them() {
    let remote = Remote::start();
    remote.login();

    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");

    // A second device, same domain, fully settled at the time of the reset.
    let mut b = App::open_in_memory().unwrap();
    block_on(b.bootstrap_from_remote(secret("old-password"))).expect("bootstrap");
    block_on(b.sync()).expect("the second device pulls the rows");
    // Twice, and the second one is what matters: a pulled row lands with
    // `synced_at = NULL`, so only the second sync pushes it and stamps it
    // synced. This is the state the bug needs — "a device that had already
    // synced", whose parents are clean and therefore not in the dirty set that
    // adoption used to re-queue. With only one sync the parents would still be
    // dirty for an unrelated reason and this test would pass against the bug.
    block_on(b.sync()).expect("the second device pushes and settles the rows");
    assert_eq!(b.list_projects().unwrap().len(), 1);
    assert_eq!(b.list_environments("Fudi").unwrap().len(), 2);

    // The first device resets and wipes the remote.
    a.reset_local(secret("new-password")).unwrap();
    block_on(a.reset_remote()).expect("the wipe");
    let reset_epoch = remote
        .store()
        .vault_epoch()
        .expect("the wipe published an epoch");
    assert_eq!(reset_epoch, 2);

    // The second device is now in an older domain and must be told about the
    // reset, not about a password change.
    let err = block_on(b.sync()).expect_err("a device left behind by a wipe");
    let CoreError::RemoteReset(info) = err else {
        panic!(
            "expected RemoteReset (the CLI can then ask the user), got {err:?} — \
             RemoteKeyChanged would send this user after a password they lost"
        );
    };
    assert_eq!(
        info.key_change.as_deref(),
        Some("reset"),
        "the divergence prompt reports what actually happened"
    );
    assert_eq!(info.remote_epoch, reset_epoch);
    assert!(info.key_changed_at.is_some(), "the reset is dated");
    assert!(
        info.remote_epoch > 1,
        "the remote counter is past this device's: that is what identifies the \
         reset rather than an ordinary rekey"
    );

    // "Keep local": adopt the remote's key, which re-encrypts this device's
    // variables under it.
    block_on(b.adopt_remote_key(secret("new-password"))).expect("adopt the remote key");

    let mark = remote.request_mark();
    let report = block_on(b.sync()).expect("the adoption retry must complete");
    assert_eq!(
        report.deleted_pulled, 0,
        "nothing may come back deleted: the user asked to keep this vault"
    );

    // (1) The parents were re-pushed, live.
    for table in ["projects", "environments"] {
        let bodies = pushed_bodies(&remote, mark, table);
        assert_eq!(
            bodies.len(),
            1,
            "adoption must re-push {table}: leaving the reset's tombstone in \
             place is what let the pull delete the user's project"
        );
        assert!(
            !bodies[0].is_empty(),
            "the {table} push must carry rows, not an empty array"
        );
        for row in &bodies[0] {
            assert_eq!(
                row["deleted"], false,
                "{table} {} must be pushed as live, not as a tombstone",
                row["id"]
            );
        }
    }
    assert_eq!(
        pushed_bodies(&remote, mark, "variables").len(),
        1,
        "the re-encrypted variables are pushed too"
    );

    // (2) No tombstone is left standing on the server for the parents.
    let store = remote.store();
    for row in store.projects().iter().chain(store.environments()) {
        assert_eq!(
            row["deleted"], false,
            "project/environment {} still carries the reset's tombstone on the \
             server, so the next device pulls the deletion back",
            row["id"]
        );
    }
    drop(store);

    // (3) The vault the user asked to keep is intact and readable.
    assert_eq!(
        b.list_projects().unwrap().len(),
        1,
        "the project must survive the sync that followed the adoption"
    );
    assert_eq!(
        b.get_variable("Fudi", "local", "TOKEN").unwrap().value,
        "live-value",
        "and its values, re-encrypted under the remote key, must still read"
    );
    assert_eq!(
        b.get_variable("Fudi", "staging", "TOKEN").unwrap().value,
        "staging-value",
        "cascade_tombstones must not have taken the children either"
    );
    assert_eq!(b.list_environments("Fudi").unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// 4. `sync()` finishes an interrupted wipe instead of dead-ending
// ---------------------------------------------------------------------------

/// A user who ran `reset --local` and then lost their connection has an
/// interrupted wipe: the local vault is already in the new domain and the server
/// is not. This sync must complete the wipe **and go on to sync normally**.
///
/// Left to the salt guard it aborts with `RemoteKeyChanged`, and the CLI matched
/// that error and asked for the *remote* master password — which this user has
/// just said they lost. A dead end with no way out and no error message that
/// says so.
///
/// The load-bearing assertion is that `sync()` returns `Ok` at all; against the
/// bug it returns `CoreError::RemoteKeyChanged` before touching a row. The
/// `pushed` count then pins down what the run was allowed to do: exactly one
/// vault-meta push plus one tombstone per row, so the wipe did not run twice
/// and the guard did not decide to publish the meta a second time.
///
/// Fails against: an impl that lets the salt guard see a pending reset (abort);
/// one that re-reads the remote meta only after the wipe and re-pushes it
/// (`pushed` too high); one that re-encrypts the tombstones (ciphertext
/// assertion).
#[test]
fn a_sync_with_a_pending_reset_finishes_the_wipe_and_then_completes() {
    let remote = Remote::start();
    remote.login();

    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");
    let (epoch_before, projects_before, envs_before, vars_before) = {
        let store = remote.store();
        (
            store.vault_epoch().expect("vault epoch"),
            store.projects().to_vec(),
            store.environments().to_vec(),
            store.variables().to_vec(),
        )
    };
    assert_eq!(epoch_before, 1);

    // The reset ran locally; the wipe never reached the server (offline, closed
    // laptop, killed process — all the same to the marker).
    a.reset_local(secret("new-password")).unwrap();
    assert!(a.pending_reset().unwrap());
    {
        let store = remote.store();
        assert_eq!(
            store.variables(),
            vars_before.as_slice(),
            "nothing has been wiped yet: this is an interrupted reset"
        );
    }

    let report = block_on(a.sync()).expect(
        "sync must finish the pending wipe AND complete — aborting with \
         RemoteKeyChanged would ask this user for the password they just lost",
    );
    assert_eq!(
        report.pushed, 6,
        "one vault-meta push plus 5 tombstones, and no second meta push once the \
         salt guard sees the post-wipe domain"
    );
    assert!(
        !a.pending_reset().unwrap(),
        "a finished wipe must clear the marker"
    );

    let store = remote.store();
    assert_tombstoned_preserving_ciphertext(&projects_before, store.projects(), "projects");
    assert_tombstoned_preserving_ciphertext(&envs_before, store.environments(), "environments");
    assert_tombstoned_preserving_ciphertext(&vars_before, store.variables(), "variables");
    assert_eq!(store.vault_epoch(), Some(epoch_before + 1));
    assert_eq!(store.vault_key_change().as_deref(), Some("reset"));

    // The same sync left this device able to sync again without a dead end: no
    // vault meta is announced (the marker is gone and the domains agree), and
    // whatever it does push is tombstones — the wipe device must never
    // resurrect what it just wiped when its own tombstones come back down.
    drop(store);
    let mark = remote.request_mark();
    block_on(a.sync()).expect("and the next sync is an ordinary one");
    let log = remote.rest_log_after(mark);
    assert!(
        !log.iter().any(|r| r == "POST /rest/v1/vaults"),
        "a settled post-reset vault has nothing to announce; a second meta push \
         means the wipe branch ran again; log: {log:?}"
    );
    let repushed: Vec<Value> = ["projects", "environments", "variables"]
        .iter()
        .flat_map(|t| pushed_bodies(&remote, mark, t))
        .flatten()
        .collect();
    assert!(
        !repushed.is_empty(),
        "the wipe's own tombstones were pulled into the emptied local vault, so \
         the next sync must carry them back as tombstones"
    );
    for row in &repushed {
        assert_eq!(
            row["deleted"], true,
            "row {} came back live after a wipe: the device that performed it \
             must not resurrect its own tombstones",
            row["id"]
        );
    }
}

// ---------- helpers ----------

/// Unused import guard: `Store` is referenced through `remote.store()`'s
/// return type in the test bodies above.
const _: fn(&Store) = |_| {};
