//! H1 — the pending-reset wipe must not need a master key.
//!
//! `crates/core/tests/reset_sync_http.rs` proves that `sync()` finishes an
//! interrupted wipe (its test 4, Ruling 14). It does so on a vault that
//! `reset_local` left **unlocked**, because `reset_local` installs the new key
//! in memory. That is the happy path and it hides the intersection this file
//! covers: the session and the reset meet at `vltr lock`.
//!
//! The scenario under review is the one the CLI can actually produce:
//!
//! ```text
//! vltr reset --local      # pending_local_reset set, new key installed
//! vltr lock               # master_key = None, session cleared
//! vltr sync               # must finish the wipe, with no key anywhere
//! ```
//!
//! [`App::sync`] finishes the wipe at `crates/core/src/sync/mod.rs:477`, before
//! any `require_key()`, on purpose: a tombstone is a metadata write and the
//! ciphertexts travel through untouched. Everything below asserts that this
//! half of the contract actually holds, so the only thing left to blame for a
//! password prompt is the CLI — see the report.
//!
//! Nothing here can reach the keyring: the vaults are `App::open_in_memory`, so
//! `session::save_master_key(None, ..)` short-circuits, and `Remote::start`
//! points `VLTR_SYNC_SESSION_FILE` at a temp file. See `support`'s module docs.

mod support;

use secrecy::SecretString;
use support::{block_on, Remote};
use vltr_core::{App, CoreError};

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

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

/// One project, two environments, two variables — the count the assertions
/// below are pinned to.
const ROWS: usize = 5;

// ---------------------------------------------------------------------------
// 1. The lock is on the other side of the wipe
// ---------------------------------------------------------------------------

/// `reset --local`, `lock`, `sync`: the wipe completes and the sync returns `Ok`
/// on a device that holds **no key at all** — not in memory, not in a session.
///
/// The load-bearing assertion is `sync().expect(...)`. It is armed so that it
/// cannot pass vacuously:
///
/// * `!a.is_unlocked()` is asserted immediately before, so a `require_key()`
///   hoisted above the pending-reset branch would abort the sync with
///   `CoreError::Locked` and fail here rather than silently doing less.
/// * the marker is asserted present, so a `sync()` that quietly skipped the
///   branch would have nothing to skip.
/// * `report.pushed == ROWS + 1` pins down that the wipe actually ran (one
///   vault-meta push plus one tombstone per row), so `Ok(())` cannot be the
///   cheap way to satisfy the first assertion.
/// * the store is read afterwards, not inferred from the report: every row must
///   come back `deleted`, and the remote must advertise the LOCAL (post-reset)
///   salt with `key_change = "reset"`. That is what a device still holding the
///   old key reads to understand the wipe.
///
/// Fails against: an impl that routes the pending-reset branch through
/// `require_key()`; one that aborts with `RemoteKeyChanged` before the wipe
/// (the Ruling 14 shape); one that reports `Ok` without doing the work.
#[test]
fn a_locked_device_still_finishes_the_pending_wipe_without_any_master_key() {
    let remote = Remote::start();
    remote.login();

    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");
    let (salt_before, epoch_before, projects_before, envs_before, vars_before) = {
        let store = remote.store();
        (
            store.vault_salt().expect("vault salt"),
            store.vault_epoch().expect("vault epoch"),
            store.projects().to_vec(),
            store.environments().to_vec(),
            store.variables().to_vec(),
        )
    };
    assert_eq!(epoch_before, 1);

    // `reset --local`: the new domain is installed locally, the remote is not
    // touched yet, and the marker is what makes the next sync finish the job.
    a.reset_local(secret("new-password")).unwrap();
    assert!(
        a.pending_reset().unwrap(),
        "precondition: the wipe is pending"
    );

    // `vltr lock`. From here this device holds nothing: `require_key()` is the
    // only way back to a key, and the session is gone.
    a.lock().unwrap();
    assert!(
        !a.is_unlocked(),
        "precondition: this device holds no key at all"
    );
    assert!(
        a.list_variables("Fudi", "local").is_err(),
        "precondition: and it can read nothing without one"
    );
    {
        let store = remote.store();
        assert_eq!(
            store.variables(),
            vars_before.as_slice(),
            "the wipe still has not landed: this is the interrupted reset"
        );
    }

    // `vltr sync`.
    let report = block_on(a.sync()).expect(
        "a locked device must still finish the pending wipe — a require_key() \
         anywhere ahead of the marker aborts here with Locked, and a salt guard \
         that sees the pending reset aborts with RemoteKeyChanged, which the CLI \
         turns into a request for the password the user just reset away",
    );
    assert_eq!(
        report.pushed,
        ROWS + 1,
        "one vault-meta push plus one tombstone per row: the wipe must actually \
         have run, not been skipped in favour of a cheap Ok"
    );
    assert!(
        !a.pending_reset().unwrap(),
        "a landed wipe must clear the marker"
    );

    let store = remote.store();
    assert_eq!(
        store.vault_epoch(),
        Some(epoch_before + 1),
        "remote + 1: the counter only ever moves forward"
    );
    assert_eq!(store.vault_key_change().as_deref(), Some("reset"));
    assert_ne!(
        store.vault_salt().as_deref(),
        Some(salt_before.as_str()),
        "the wipe publishes the LOCAL post-reset domain, so a device left behind \
         on the old one is told to ask rather than to adopt"
    );
    let live = ["projects", "environments", "variables"]
        .into_iter()
        .map(|t| match t {
            "projects" => store.projects().len(),
            "environments" => store.environments().len(),
            _ => store.variables().len(),
        })
        .sum::<usize>();
    assert_eq!(live, ROWS, "the wipe tombstones, it does not drop rows");
    // Every row the wipe found is flagged deleted, and none of them lost a byte:
    // a device still holding the pre-reset key must not find a blob it can no
    // longer read, which would be worse than the wipe because it is silent.
    for (what, before, after) in [
        ("projects", &projects_before, store.projects()),
        ("environments", &envs_before, store.environments()),
        ("variables", &vars_before, store.variables()),
    ] {
        assert_eq!(
            before.len(),
            after.len(),
            "{what}: the wipe must tombstone exactly the rows it found"
        );
        for old in before.iter() {
            let id = old["id"].as_str().expect("every pushed row has an id");
            let new = after
                .iter()
                .find(|r| r["id"] == id)
                .unwrap_or_else(|| panic!("{what}: row {id} disappeared from the remote"));
            assert_eq!(new["deleted"], true, "{what}: row {id} is not tombstoned");
            if old.get("value_encrypted").is_some() {
                assert_eq!(
                    new["value_encrypted"], old["value_encrypted"],
                    "{what}: row {id} must keep its ciphertext byte for byte"
                );
                assert_eq!(
                    new["nonce"], old["nonce"],
                    "{what}: row {id} must keep its nonce byte for byte"
                );
            }
        }
    }
    drop(store);

    // And the device that did it is still usable with its NEW password only.
    // `lock()` dropped the in-memory key, so this is a real unlock, not a
    // leftover `Some(_)`.
    a.unlock(secret("new-password"))
        .expect("the new password opens it");
    assert!(
        a.verify_password(secret("old-password")).is_err(),
        "the pre-reset password must not open the post-reset vault"
    );
    // No key, and still no key: the next sync is an ordinary one too. This is
    // the state a `vltr sync` that had to prompt would have left behind.
    a.lock().unwrap();
    block_on(a.sync()).expect("and a settled post-reset vault syncs locked too");
}

// ---------------------------------------------------------------------------
// 2. How much of `sync()` actually needs the key?
// ---------------------------------------------------------------------------

/// `App::sync` reads the master key in exactly one place: the verifier backfill
/// at `crates/core/src/sync/mod.rs:585`, reachable only when the salt guard
/// answers `Proceed` **and** the remote row carries no verifier
/// (`sync/guard.rs:85`). Every other thing it does — the wipe, the push, the
/// pull, the LWW merge, the cascade, the cursor — moves ciphertext and
/// metadata only.
///
/// This test pins the consequence: on a device that holds no key at all, an
/// ordinary `sync()` completes. The one exception is a remote that predates the
/// verifier migration, and that is asserted here too so the exception cannot
/// grow silently.
///
/// This is what makes the CLI gate indefensible rather than merely annoying:
/// `crates/cli/src/main.rs:647` runs `open_and_unlock` before every `vltr sync`,
/// which prompts for a master password on a locked vault — a prompt that buys
/// nothing, on the command whose whole purpose is to be run by someone who lost
/// the key.
///
/// Fails against: an impl that starts reading `require_key()` somewhere in the
/// ordinary path; one that silently drops the backfill (the backfill assertion
/// would still pass, but `remote.verifier_ct` stays `None` — asserted).
#[test]
fn sync_needs_no_master_key_outside_the_verifier_backfill() {
    let remote = Remote::start();
    remote.login();

    // No pending reset at all, no session, no in-memory key: this is `vltr
    // sync` on a device that was never unlocked on this boot.
    let mut a = seeded_vault("old-password");
    a.lock().unwrap();
    assert!(!a.is_unlocked(), "precondition: no key anywhere");
    assert!(!a.pending_reset().unwrap(), "precondition: no wipe pending");

    let report = block_on(a.sync()).expect(
        "an ordinary sync must not need the master key: nothing in it decrypts, \
         so requiring one at the CLI buys the user nothing",
    );
    assert_eq!(
        report.pushed,
        ROWS + 1,
        "one vault-meta push (this device has never synced: the salt guard \
         answers PushLocal) plus the {ROWS} rows. A count of 0 would mean the \
         push was skipped instead of run without a key"
    );
    assert_eq!(report.pulled, 0, "nothing new upstream yet");
    assert!(!a.is_unlocked(), "syncing must not unlock the vault");

    // The cursor settled: the first sync really did push *and* mark the rows
    // synced, so the second one has nothing to do. Read from the server, not
    // inferred, so it cannot be satisfied by a skipped push.
    {
        let store = remote.store();
        assert_eq!(store.projects().len(), 1);
        assert_eq!(store.environments().len(), 2);
        assert_eq!(store.variables().len(), 2);
    }
    let settled = block_on(a.sync()).expect("a second locked sync is an ordinary one");
    assert_eq!(settled.pushed, 0, "nothing left to push");
    assert_eq!(settled.pulled, 0, "nothing left to pull");

    // The one documented exception really is the exception: strip the verifier
    // from the remote row and the same locked sync now needs the key. That is
    // `CoreError::Locked`, not a silent skip — and it is unreachable from a
    // post-reset vault, whose `push_reset` always publishes a verifier.
    {
        let mut store = remote.store();
        let (salt, kdf) = (
            store.vault_salt().expect("salt"),
            store.vault().expect("row")["kdf_params"].clone(),
        );
        // `set_vault` writes a row with no verifier and no nonce — the shape a
        // vault predating the verifier migration left on the server.
        store.set_vault(&salt, kdf);
    }
    let err = block_on(a.sync()).expect_err(
        "a verifier-less remote row is the documented one case that needs the \
         key; if this now succeeds, the backfill requirement is gone",
    );
    assert!(
        matches!(err, CoreError::Locked),
        "expected Locked from the verifier backfill, got {err:?}"
    );
}
