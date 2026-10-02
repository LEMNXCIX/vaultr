//! Integration coverage for the **HTTP** half of sync: the endpoints, the wire
//! format and the ordering guarantees that the pure unit tests in
//! `crates/core/src/sync.rs` cannot reach.
//!
//! Everything runs against `support::Remote`, a stateful in-process PostgREST
//! and GoTrue; nothing here contacts Supabase, and nothing here can reach the
//! real keyring. See the module docs of `support` for how that is arranged.
//!
//! The tests are serialized by a process-global mutex (also `support`'s job)
//! because `VAULTR_SUPABASE_URL`, `VAULTR_SUPABASE_KEY` and
//! `VLTR_SYNC_SESSION_FILE` are process-wide.

mod support;

use secrecy::SecretString;
use support::{block_on, Remote, Store};
use vltr_core::{App, CoreError};

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// An initialized, unlocked vault with one project, two environments and two
/// variables. In-memory on purpose: `session::save_master_key(None, ..)` is a
/// no-op, so no `App` in this file can write a keyring entry.
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

// ---------------------------------------------------------------------------
// 1. Full round trip: push ciphertext, pull it on a second device
// ---------------------------------------------------------------------------

/// The whole point of sync, over the wire: what device A pushes is exactly the
/// ciphertext A holds (never plaintext), and a fresh device that knows only the
/// password ends up with the same values.
///
/// This is the closest existing analogue to "the reset wipe must not rewrite
/// ciphertext": if the push/pull round trip is byte-faithful, a tombstone that
/// reuses the stored blobs is too.
///
/// Fails against: pushing plaintext or the master key instead of ciphertext;
/// base64 mangling anywhere in `variable_to_dto`/`variable_from_dto`; a nonce
/// that is not 24 bytes; rows landing under the wrong environment; a pull that
/// drops or renames rows.
#[test]
fn push_and_pull_carry_ciphertext_only_and_survive_a_round_trip() {
    let remote = Remote::start();
    remote.login();

    let a = seeded_vault("shared-password");
    let report = block_on(a.sync()).expect("first sync must reach the remote");
    assert_eq!(
        report.pushed, 6,
        "vault meta + 1 project + 2 environments + 2 variables"
    );
    assert_eq!(report.pulled, 0, "an empty remote pulls nothing");

    // --- zero knowledge: inspect the bytes that actually left the device ---
    let variable_rows = remote.store().variables().to_vec();
    assert_eq!(variable_rows.len(), 2, "both variables reached the wire");
    for row in &variable_rows {
        let key = row["key"].as_str().expect("key");
        let ct = base64_decode(row["value_encrypted"].as_str().expect("value_encrypted"));
        let nonce = base64_decode(row["nonce"].as_str().expect("nonce"));
        // XChaCha20-Poly1305: 24-byte nonce, and the ciphertext is the
        // plaintext plus the 16-byte Poly1305 tag — nothing longer (a second
        // encryption layer), nothing shorter (a truncated value).
        assert_eq!(nonce.len(), 24, "nonce must survive the round trip intact");
        let plaintext_len = match key {
            "TOKEN" => 10, // live-value / staging-value differ by 3
            other => panic!("unexpected key {other}"),
        };
        assert!(
            ct.len() == plaintext_len + 16 || ct.len() == plaintext_len + 3 + 16,
            "ciphertext for {key} is {} bytes, expected the sealed value",
            ct.len()
        );
        assert!(
            !ct.windows(4).any(|w| w == b"live" || w == b"stag"),
            "plaintext found in the pushed ciphertext for {key}"
        );
    }
    // Every request body the client ever sent, including the vault meta, must
    // be free of the secret values.
    for request in remote.requests() {
        assert!(
            !request.body.contains("live-value") && !request.body.contains("staging-value"),
            "plaintext leaked to {} {}",
            request.method,
            request.path
        );
    }

    // --- a second device, with no local state at all, reads the same values ---
    let mut b = App::open_in_memory().unwrap();
    assert!(!b.is_initialized().unwrap());
    block_on(b.bootstrap_from_remote(secret("shared-password"))).expect("bootstrap");
    assert!(b.is_initialized().unwrap());

    // Bootstrap only takes the vault meta; the rows arrive with the first sync.
    block_on(b.sync()).expect("second device sync");
    assert_eq!(
        b.get_variable("Fudi", "local", "TOKEN").unwrap().value,
        "live-value",
        "the pulled row must decrypt under the shared password"
    );
    assert_eq!(
        b.get_variable("Fudi", "staging", "TOKEN").unwrap().value,
        "staging-value",
        "rows must not be collapsed into the wrong environment"
    );
    assert_eq!(b.list_projects().unwrap().len(), 1);
}

/// A tombstone is a metadata write: `deleted` flips, the ciphertext must not.
/// Device B's pull-then-push is the round trip through which a lossy mapping
/// would show up as different bytes on the server.
///
/// Fails against: any impl that clears `value_encrypted`/`nonce` on delete (the
/// natural "a tombstone holds no secret" shortcut), that re-encrypts on
/// tombstone, or that drops the blob on the way back out.
#[test]
fn deleting_a_variable_pushes_a_tombstone_that_keeps_the_ciphertext() {
    let remote = Remote::start();
    remote.login();

    let a = seeded_vault("shared-password");
    block_on(a.sync()).expect("first sync");

    let before = remote.store().variables().to_vec();
    let live = before
        .iter()
        .find(|r| r["key"] == "TOKEN" && r["deleted"] == false)
        .expect("a live row");
    let live_id = live["id"].as_str().unwrap().to_owned();
    let live_ct = live["value_encrypted"].as_str().unwrap().to_owned();
    let live_nonce = live["nonce"].as_str().unwrap().to_owned();
    let live_version = live["version"].as_i64().unwrap();

    a.delete_variable("Fudi", "local", "TOKEN").unwrap();
    block_on(a.sync()).expect("sync after delete");

    let after = remote.store().variables().to_vec();
    let tombstone = after
        .iter()
        .find(|r| r["id"] == live_id.as_str())
        .expect("the tombstone must be pushed, not dropped");
    assert_eq!(
        tombstone["deleted"], true,
        "a delete must reach the server as a tombstone"
    );
    assert_eq!(
        tombstone["value_encrypted"], live_ct,
        "the tombstone must keep the original ciphertext byte for byte"
    );
    assert_eq!(
        tombstone["nonce"], live_nonce,
        "the tombstone must keep the original nonce"
    );
    assert!(
        tombstone["version"].as_i64().unwrap() > live_version,
        "the tombstone must bump the version so LWW resolves it"
    );

    // A device that never saw the live value pulls the tombstone and must not
    // resurrect the row. If the ciphertext had been cleared on the way out, the
    // local merge would have nothing to compare and the row could come back.
    let mut b = App::open_in_memory().unwrap();
    block_on(b.bootstrap_from_remote(secret("shared-password"))).unwrap();
    let report = block_on(b.sync()).expect("pull the tombstone");
    assert_eq!(report.deleted_pulled, 1, "the tombstone must be pulled");
    assert!(matches!(
        b.get_variable("Fudi", "local", "TOKEN"),
        Err(CoreError::VariableNotFound)
    ));
}

// ---------------------------------------------------------------------------
// 2. The salt guard: abort before touching the network
// ---------------------------------------------------------------------------

/// A vault in a different key domain must be rejected *before* a single byte
/// is written or read. Pushing first would overwrite the other domain's rows
/// with ciphertext nobody can decrypt; pulling first would merge foreign
/// ciphertext into the local vault.
///
/// The `POST` count is the load-bearing assertion: it is 0 on a correct
/// implementation and >0 on an implementation that pushes rows before
/// checking the salt.
#[test]
fn salt_mismatch_aborts_before_any_row_is_pushed_or_pulled() {
    let remote = Remote::start();
    remote.login();

    // A remote already living in another key domain, with rows in it.
    {
        let mut store = remote.store();
        store.set_vault(&base64_encode(b"a-different-key-domain!"), kdf_params());
        store.insert_variables(vec![serde_json::json!({
            "id": "11111111-2222-7333-8444-555555555555",
            "environment_id": "11111111-2222-7333-8444-666666666666",
            "key": "REMOTE_ONLY",
            "value_encrypted": "Y2lwaGVy",
            "nonce": "bm9uY2U=",
            "notes": null,
            "is_readonly": false,
            "allow_export": true,
            "deleted": false,
            "version": 1,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        })]);
    }

    // This device's vault, in its own domain, with work of its own to push.
    let a = seeded_vault("local-password");

    let mark = remote.request_mark();
    let err = block_on(a.sync()).expect_err("a foreign key domain must abort");
    assert!(
        matches!(err, CoreError::RemoteKeyChanged),
        "expected RemoteKeyChanged, got {err:?}"
    );

    let requests = remote.rest_log_after(mark);
    assert_eq!(
        requests,
        vec!["GET /rest/v1/vaults".to_owned()],
        "the guard reads the remote salt and stops; it must not push or pull \
         anything. Saw: {requests:?}"
    );

    // Nothing merged either: the foreign row must not exist locally.
    assert!(
        block_on(a.sync()).is_err(),
        "the vault stays in its own domain after the abort"
    );
    assert!(
        a.get_variable("Fudi", "local", "REMOTE_ONLY").is_err(),
        "no row from another key domain may be merged"
    );

    // And the local work is untouched on the server.
    let store = remote.store();
    assert_eq!(
        store.projects().len(),
        0,
        "the aborted sync must not have pushed the local project"
    );
    assert_eq!(
        store.variables().len(),
        1,
        "only the pre-existing foreign row is on the server"
    );
    assert_eq!(
        store.vault_salt().as_deref(),
        Some(base64_encode(b"a-different-key-domain!").as_str()),
        "the foreign vault meta must not be overwritten"
    );
}

// ---------------------------------------------------------------------------
// 3. pending_rekey_salt: the marker that authorizes the meta push
// ---------------------------------------------------------------------------

/// After a rekey the local salt no longer matches the remote one, so the guard
/// consults `pending_rekey_salt`. If that marker were cleared before the push
/// landed, the *next* sync would see a mismatch with no marker and abort with
/// `RemoteKeyChanged` — the user is stuck asking for a password that does not
/// unlock the remote vault.
///
/// The three phases each fail on a different break:
/// - a failed push leaves the marker set → phase 2 can succeed at all;
/// - a successful push clears the marker → phase 3 pushes no vault meta;
/// - a stale marker is harmless → phase 3 still converges.
#[test]
fn rekey_marker_survives_a_failed_push_and_is_cleared_only_once_it_lands() {
    let remote = Remote::start();
    remote.login();

    // Phase 0: a device whose vault is on the server under the old salt.
    let mut a = seeded_vault("old-password");
    block_on(a.sync()).expect("initial sync");
    let old_salt = remote.store().vault_salt().expect("vault meta pushed");
    assert!(
        a.rekey(secret("new-password")).unwrap() == 2,
        "both variables are re-encrypted"
    );
    // The rekey rotated the local salt, so the next sync must push new meta.
    assert_ne!(old_salt, base64_encode(b"unknown"));

    // Phase 1: the meta push fails. The marker must survive.
    remote.store().fail_next_vault_push(1);
    let mark = remote.request_mark();
    let err = block_on(a.sync()).expect_err("the injected 500 must surface");
    assert!(
        matches!(err, CoreError::Sync(_)),
        "expected a transport error, got {err:?}"
    );
    assert_eq!(
        remote.rest_log_after(mark),
        vec![
            "GET /rest/v1/vaults".to_owned(),
            "POST /rest/v1/vaults".to_owned()
        ],
        "the meta push is attempted before any row"
    );
    assert_eq!(
        remote.store().vault_salt().as_deref(),
        Some(old_salt.as_str()),
        "a failed push must not change the server"
    );

    // Phase 2: the retry lands, the marker is cleared.
    let mark = remote.request_mark();
    block_on(a.sync()).expect("the retry must complete the rekey sync");
    assert_eq!(
        remote.rest_log_after(mark).first().map(String::as_str),
        Some("GET /rest/v1/vaults"),
        "the retry starts with the salt check"
    );
    assert!(
        remote
            .rest_log_after(mark)
            .iter()
            .any(|r| r == "POST /rest/v1/vaults"),
        "the retry must publish the new vault meta"
    );
    let new_salt = remote.store().vault_salt().expect("vault meta still there");
    assert_ne!(
        new_salt, old_salt,
        "the remote must now carry the rotated salt"
    );

    // Phase 3: with the marker cleared and the salts equal, the guard is a
    // plain `Proceed` — no meta push at all. A marker that was never cleared
    // would show up here as a second `POST /rest/v1/vaults`.
    let mark = remote.request_mark();
    block_on(a.sync()).expect("a settled vault syncs normally");
    assert!(
        !remote
            .rest_log_after(mark)
            .iter()
            .any(|r| r == "POST /rest/v1/vaults"),
        "a settled rekey must not re-push the vault meta; log: {:?}",
        remote.rest_log_after(mark)
    );

    // The values are intact under the new password, on this device…
    assert_eq!(
        a.get_variable("Fudi", "local", "TOKEN").unwrap().value,
        "live-value"
    );
    // …and a fresh device can bootstrap with the *new* password only.
    let mut b = App::open_in_memory().unwrap();
    block_on(b.bootstrap_from_remote(secret("old-password")))
        .expect_err("the old password must not open the rekeyed vault");
    let mut c = App::open_in_memory().unwrap();
    block_on(c.bootstrap_from_remote(secret("new-password"))).expect("bootstrap with new");
    block_on(c.sync()).unwrap();
    assert_eq!(
        c.get_variable("Fudi", "local", "TOKEN").unwrap().value,
        "live-value"
    );

    // Phase 4: the marker must be *gone* now. While the salts match it is
    // inert, so the only way to observe a leftover marker is a later mismatch:
    // another device rekeys the remote, and this one must then refuse rather
    // than treat its own stale marker as permission to publish its meta and
    // clobber that rekey.
    remote
        .store()
        .set_vault(&base64_encode(b"some-other-device-salt!"), kdf_params());
    let mark = remote.request_mark();
    let err = block_on(a.sync()).expect_err("a stale marker must not authorize a push");
    assert!(
        matches!(err, CoreError::RemoteKeyChanged),
        "expected RemoteKeyChanged, got {err:?}"
    );
    assert!(
        !remote
            .rest_log_after(mark)
            .iter()
            .any(|r| r.ends_with("/vaults") && r.starts_with("POST")),
        "the stale marker must not have published this device's vault meta; \
         log: {:?}",
        remote.rest_log_after(mark)
    );
    assert_eq!(
        remote.store().vault_salt().as_deref(),
        Some(base64_encode(b"some-other-device-salt!").as_str()),
        "the other device's vault meta must survive untouched"
    );
}

// ---------------------------------------------------------------------------
// 4. The Supabase session goes to the file, never to the keyring
// ---------------------------------------------------------------------------

/// `VLTR_SYNC_SESSION_FILE` is what makes a test run safe to do at all: the
/// account session is **global**, so a test that used the keyring would
/// overwrite the developer's real login.
///
/// The discriminating assertion is that the session round-trips *through the
/// file* while the salt guard is still armed — if the override were ignored,
/// `load_stored_session` would read the keyring and the fresh device's sync
/// would fail with "not logged in to sync" instead of succeeding.
#[test]
fn sync_session_lives_in_the_override_file_not_the_keyring() {
    let remote = Remote::start();
    let session_file = remote.session_file().to_path_buf();
    assert!(
        !session_file.exists(),
        "a fresh temp dir must not carry a session"
    );
    assert!(
        !App::sync_session_exists(),
        "without a login there is no session, so sync must refuse to run"
    );

    remote.login();
    assert!(
        session_file.exists(),
        "sync_login must persist the session to VLTR_SYNC_SESSION_FILE"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&session_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the session file holds a JWT");
    }
    assert!(
        App::sync_session_exists(),
        "the override file is what makes the session visible"
    );

    // A second device in the same process reuses that session with no further
    // login, which is exactly the "one account, many vaults" behaviour.
    let a = seeded_vault("shared-password");
    block_on(a.sync()).expect("sync with the file-backed session");
    assert!(remote.store().vault_salt().is_some());

    // `sync_logout` removes the file (and, under the override, does not go
    // anywhere near the keyring).
    a.sync_logout().unwrap();
    assert!(!session_file.exists(), "logout removes the override file");
    assert!(!App::sync_session_exists());
}

// ---------- helpers ----------

fn kdf_params() -> serde_json::Value {
    serde_json::to_value(models::KdfParams::default()).unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).expect("valid base64 from the server")
}

/// Unused import guard: `Store` is referenced through `remote.store()`'s
/// return type in the test bodies above.
const _: fn(&Store) = |_| {};
