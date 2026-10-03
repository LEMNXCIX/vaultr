//! `adopt_remote_key` must not decrypt rows nobody will ever read again.
//!
//! A tombstone is a *metadata* write. `reset_remote` keeps every
//! `value_encrypted` and `nonce` byte it found, because a device still holding
//! the pre-wipe key must be able to recognise the row (see
//! `reset_sync_http.rs`). That is exactly what makes those bytes dead weight on
//! the way back in: a reset's tombstones travel under the key they were written
//! with, and if that key is older than this device's, **no key anyone holds can
//! open them**.
//!
//! Adoption walked `Storage::all_variables` — every row, tombstones included —
//! and decrypted each one with `?`. So a single unreadable tombstone aborted the
//! whole adoption, always, on any vault that had ever synced a remote carrying
//! one. The divergence prompt's "conservar lo local" — the option that exists to
//! prevent data loss — was unreachable: the user could discard their data or
//! cancel, and the message ("wrong key or corrupted data") named a cause that
//! was not the cause.
//!
//! Two tests, from the fixture inwards:
//!
//! 1. `adopting_a_remote_key_survives_tombstones_this_device_cannot_decrypt` —
//!    the smallest thing that reproduces it: one live row plus tombstones whose
//!    ciphertext is unreadable, adoption, `Ok`.
//! 2. `a_device_left_behind_by_a_reset_adopts_the_remote_key_over_the_seeds_tombstones`
//!    — device B's actual case end to end, with **no fixture injection at all**:
//!    the unreadable tombstones arrive by pull, carrying the seed key that the
//!    first reset destroyed.
//!
//! # Neither test can reach the keyring
//!
//! The device vault is on disk (a second `Storage` handle is how these tests
//! read and write raw rows), so `adopt_remote_key` *does* call
//! `session::save_master_key(Some(path), ..)` — the one path in this file that
//! could touch a keyring. [`SessionFileOverride`] pins `VLTR_SESSION_FILE` at a
//! temp path for the whole test, which short-circuits that to a 0600 file
//! (`session.rs:381`). The account side is covered by `Remote::start`, which sets
//! `VLTR_SYNC_SESSION_FILE`. Nothing here talks to Supabase either.

mod support;

use crypto::{decrypt, derive_master_key, fill_random, MasterKey};
use rusqlite::params;
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use storage::Storage;
use support::{block_on, Remote};
use vltr_core::{App, CoreError};

const SESSION_FILE_ENV: &str = "VLTR_SESSION_FILE";

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

// ---------- Fixtures ----------

/// Point `VLTR_SESSION_FILE` at a temp path and take it back down on drop,
/// including on panic.
///
/// `Remote::start` already holds the process-global env mutex for the whole test
/// (it has to: `VAULTR_SUPABASE_URL` is process-wide), so setting a second
/// process-global env var while `remote` is alive cannot race another test.
struct SessionFileOverride(Option<PathBuf>);

impl SessionFileOverride {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vaultr-adopt-tombstones-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::env::set_var(SESSION_FILE_ENV, &path);
        Self(Some(path))
    }
}

impl Drop for SessionFileOverride {
    fn drop(&mut self) {
        std::env::remove_var(SESSION_FILE_ENV);
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A second handle on a device's vault file, for the rows `App` hides.
///
/// Tombstones are unreachable through `App` on purpose (`get_variable` and
/// `list_variables` filter `deleted = 0`), and adoption is decided on exactly
/// the rows `App` hides — so reading them needs storage.
fn rows(db: &Path) -> Vec<models::Variable> {
    Storage::open(db)
        .expect("second handle on the device vault")
        .all_variables()
        .expect("every variable row, tombstones included")
}

/// The device's own master key, derived from the password it is unlocked with.
///
/// This is how a test proves a row is *unreadable to this device* without
/// trusting the fixture: the key is the one `adopt_remote_key` decrypts with
/// (`old_key = self.require_key()`), derived from the salt `vault_meta` holds.
fn device_key(db: &Path, password: &str) -> MasterKey {
    let meta = Storage::open(db)
        .expect("second handle on the device vault")
        .get_vault_meta()
        .expect("vault_meta");
    derive_master_key(&secret(password), &meta.salt, &meta.kdf_params).expect("derive")
}

/// `(value_encrypted, nonce)` of the variable row with this key, live or not.
fn row_bytes(db: &Path, key: &str) -> (Vec<u8>, Vec<u8>) {
    let var = rows(db)
        .into_iter()
        .find(|v| v.key == key)
        .unwrap_or_else(|| panic!("no variable row named {key}"));
    (var.value_encrypted, var.nonce)
}

/// `(id, value_encrypted, nonce)` of every tombstone, keyed for a
/// byte-for-byte comparison across an operation.
fn tombstone_bytes(db: &Path) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>, Vec<u8>)> = rows(db)
        .into_iter()
        .filter(|v| v.deleted)
        .map(|v| (v.id.to_string(), v.value_encrypted, v.nonce))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// `(key, value_encrypted, nonce)` of every live variable row.
fn live_bytes(db: &Path) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>, Vec<u8>)> = rows(db)
        .into_iter()
        .filter(|v| !v.deleted)
        .map(|v| (v.key.clone(), v.value_encrypted, v.nonce))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Replace the ciphertext of every tombstone with bytes no key can open.
///
/// The sizes are the real ones (24-byte nonce, ciphertext plus the 16-byte tag)
/// so the rejection is Poly1305's — `decryption failed` — exactly as it was in
/// the end-to-end run, and not a nonce-length error, which would be a different
/// bug.
///
/// What this models is not a corruption but a *reachable state*: a reset
/// tombstones rows without touching their ciphertext, so a tombstone pulled from
/// a remote that has since rotated its key carries a ciphertext the pulling
/// device can never open. Test 2 reaches that state with no injection at all.
fn scramble_tombstones(db: &Path) -> usize {
    let storage = Storage::open(db).expect("second handle on the device vault");
    let ids: Vec<String> = storage
        .all_variables()
        .expect("rows")
        .into_iter()
        .filter(|v| v.deleted)
        .map(|v| v.id.to_string())
        .collect();
    for id in &ids {
        let mut nonce = vec![0u8; 24];
        let mut ciphertext = vec![0u8; 48];
        fill_random(&mut nonce);
        fill_random(&mut ciphertext);
        storage
            .conn()
            .execute(
                "UPDATE variables SET value_encrypted = ?1, nonce = ?2 WHERE id = ?3",
                params![ciphertext, nonce, id],
            )
            .expect("overwrite the tombstone ciphertext");
    }
    ids.len()
}

// ---------------------------------------------------------------------------
// 1. The smallest reproduction
// ---------------------------------------------------------------------------

/// Adoption over a vault holding tombstones it cannot decrypt must succeed and
/// preserve the live variables.
///
/// Against the bug this fails at `expect("adopt the remote key")` with
/// `decryption failed (wrong key or corrupted data)` — the `?` on `decrypt`
/// inside the adoption loop, cutting on the first tombstone. The password is
/// right, the live row decrypts, and the only unreadable rows are the ones
/// adoption was never going to read anyway.
///
/// Fails against: adoption that decrypts every row `all_variables` returns (the
/// bug); an impl that filters on something other than `deleted` (the live row
/// would be skipped and lost); an impl that swallows the error with
/// `if let Ok(..)` and so leaves a vault whose verifier and contents disagree.
#[test]
fn adopting_a_remote_key_survives_tombstones_this_device_cannot_decrypt() {
    let remote = Remote::start();
    remote.login();
    let _session = SessionFileOverride::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");

    // A device seeds the vault and syncs it.
    let mut a = App::open_in_memory().expect("A");
    a.init(secret("seed-password")).expect("init");
    a.create_project("Fudi", None, None, None).expect("project");
    for (key, value) in [
        ("A_LIVE", "a-value-one"),
        ("A_GONE_ONE", "a-value-two"),
        ("A_GONE_TWO", "a-value-three"),
    ] {
        a.set_variable("Fudi", "local", key, value, None)
            .expect("variable");
    }
    block_on(a.sync()).expect("initial sync");

    // B joins that key domain and pulls the rows.
    let mut b = App::open(&db).expect("B");
    block_on(b.bootstrap_from_remote(secret("seed-password"))).expect("bootstrap");
    block_on(b.sync()).expect("B pulls the rows");
    assert_eq!(b.list_variables("Fudi", "local").unwrap().len(), 3);

    // B deletes two of them. `delete_variable` is a tombstone: the row stays and
    // keeps its ciphertext, which is what the next step takes away.
    b.delete_variable("Fudi", "local", "A_GONE_ONE")
        .expect("delete");
    b.delete_variable("Fudi", "local", "A_GONE_TWO")
        .expect("delete");
    assert_eq!(
        scramble_tombstones(&db),
        2,
        "both deleted rows must be tombstoned"
    );

    // The fixture, checked rather than assumed: B's own key opens the live row
    // and cannot open either tombstone. If this passed vacuously the test would
    // prove nothing about the bug.
    let old_key = device_key(&db, "seed-password");
    let live_before = row_bytes(&db, "A_LIVE");
    assert_eq!(
        decrypt(&old_key, &live_before.0, &live_before.1)
            .expect("the live row is readable")
            .as_str(),
        "a-value-one"
    );
    let unreadable: Vec<String> = rows(&db)
        .into_iter()
        .filter(|v| v.deleted)
        .map(|v| v.key)
        .collect();
    assert_eq!(unreadable.len(), 2, "two tombstones to trip over");
    for key in &unreadable {
        let (ct, nonce) = row_bytes(&db, key);
        assert!(
            decrypt(&old_key, &ct, &nonce).is_err(),
            "tombstone {key} must be unreadable to this device, or the test does \
             not reproduce anything"
        );
    }

    // The remote moves to a new domain, so adoption is a real key change and not
    // a no-op that would pass either way.
    a.reset_local(secret("remote-password")).expect("A resets");
    block_on(a.sync()).expect("the wipe lands");
    assert!(
        matches!(block_on(b.sync()), Err(CoreError::RemoteReset(_))),
        "B is now in an older domain, which is what makes the CLI offer adoption"
    );

    let tombstones_before = tombstone_bytes(&db);

    // ---- The line the bug lives on. ----
    block_on(b.adopt_remote_key(secret("remote-password"))).expect("adopt the remote key");

    // The live variable survived, and it is now readable under the NEW key only.
    assert_eq!(
        b.get_variable("Fudi", "local", "A_LIVE")
            .expect("still there")
            .value,
        "a-value-one",
        "the row adoption was called to protect must survive it"
    );
    let live_after = row_bytes(&db, "A_LIVE");
    assert_ne!(
        live_before.0, live_after.0,
        "the live row must have been re-encrypted under the adopted key"
    );
    let new_key = device_key(&db, "remote-password");
    assert_eq!(
        decrypt(&new_key, &live_after.0, &live_after.1)
            .expect("the live row opens under the adopted key")
            .as_str(),
        "a-value-one"
    );
    assert!(
        decrypt(&old_key, &live_after.0, &live_after.1).is_err(),
        "and no longer under the key it had before: adoption moved the domain"
    );

    // The tombstones were left exactly as they were. Adoption never had to read
    // them, so it must not have touched them — the same invariant a reset keeps.
    assert_eq!(
        tombstone_bytes(&db),
        tombstones_before,
        "a tombstone's ciphertext and nonce must survive adoption byte for byte"
    );
}

// ---------------------------------------------------------------------------
// 2. Device B's case, reached with no injection at all
// ---------------------------------------------------------------------------

/// The end-to-end run's shape: a remote reset tombstones the seed's rows
/// without re-encrypting them, a second device pulls those tombstones, and the
/// remote is reset *again* — leaving that device in an older domain, with live
/// rows it can read and tombstones it cannot.
///
/// Nothing here writes a ciphertext by hand. The four tombstones carry the seed
/// key's ciphertext because the reset that tombstoned them kept those bytes, and
/// no device holds the seed key any more — which is asserted below, from B's own
/// key, before adoption is called.
///
/// Fails against: the bug (`decryption failed` at the adoption loop); an impl
/// that "fixes" it by skipping live rows too (the live values come back empty);
/// one that re-encrypts the tombstones (the byte assertion).
#[test]
fn a_device_left_behind_by_a_reset_adopts_the_remote_key_over_the_seeds_tombstones() {
    let remote = Remote::start();
    remote.login();
    let _session = SessionFileOverride::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");

    // ---- A seeds a vault and syncs it. ----
    let mut a = App::open_in_memory().expect("A");
    a.init(secret("seed-password")).expect("init");
    a.create_project("Fudi", None, None, None).expect("project");
    for (n, key) in ["OLD_ONE", "OLD_TWO", "OLD_THREE", "OLD_FOUR"]
        .into_iter()
        .enumerate()
    {
        a.set_variable("Fudi", "local", key, &format!("old-{n}"), None)
            .expect("seed variable");
    }
    block_on(a.sync()).expect("initial sync");

    // ---- The first reset. Its tombstones keep the seed key's ciphertext. ----
    a.reset_local(secret("gen1-password")).expect("A resets");
    block_on(a.sync()).expect("the first wipe lands");

    // ---- A works again, in the new domain. ----
    a.create_project("Fudi", None, None, None)
        .expect("project again (a fresh id: the old one is now a tombstone)");
    for (key, value) in [
        ("B_KEY", "b-value-one"),
        ("B_TWO", "b-value-two"),
        ("B_THREE", "b-value-three"),
    ] {
        a.set_variable("Fudi", "local", key, value, None)
            .expect("new variable");
    }
    block_on(a.sync()).expect("push the new rows");

    // ---- B joins and pulls: four tombstones it cannot read, three it can. ----
    let mut b = App::open(&db).expect("B");
    block_on(b.bootstrap_from_remote(secret("gen1-password"))).expect("bootstrap");
    block_on(b.sync()).expect("B pulls");

    let b_rows = rows(&db);
    assert_eq!(
        b_rows.iter().filter(|v| v.deleted).count(),
        4,
        "the reset's tombstones came down by pull, tombstones included"
    );
    assert_eq!(
        b_rows.iter().filter(|v| !v.deleted).count(),
        3,
        "and the rows written under the current key"
    );

    // The fixture, checked from B's own key: the three live rows open, the four
    // tombstones do not. This is the "104 total / 3 live / 101 tombstones" split
    // from the end-to-end run — and nobody, A included, holds the key those four
    // would need.
    let b_key = device_key(&db, "gen1-password");
    let live_values: Vec<(String, String)> = b_rows
        .iter()
        .filter(|v| !v.deleted)
        .map(|v| {
            let opened = decrypt(&b_key, &v.value_encrypted, &v.nonce)
                .unwrap_or_else(|e| panic!("live row {} must be readable: {e}", v.key));
            (v.key.clone(), opened.to_string())
        })
        .collect();
    for var in b_rows.iter().filter(|v| v.deleted) {
        assert!(
            decrypt(&b_key, &var.value_encrypted, &var.nonce).is_err(),
            "tombstone {} must be unreadable to B, or this test reproduces nothing",
            var.key
        );
    }
    let mut live_values = live_values;
    live_values.sort();
    assert_eq!(
        live_values,
        vec![
            ("B_KEY".to_owned(), "b-value-one".to_owned()),
            ("B_THREE".to_owned(), "b-value-three".to_owned()),
            ("B_TWO".to_owned(), "b-value-two".to_owned()),
        ],
        "B's three live values, read from its own rows before the adoption"
    );

    let live_before = live_bytes(&db);
    let tombstones_before = tombstone_bytes(&db);

    // ---- The second reset: the remote leaves B's domain for good. ----
    a.reset_local(secret("gen2-password"))
        .expect("A resets again");
    block_on(a.sync()).expect("the second wipe lands");

    let err = block_on(b.sync()).expect_err("B is left behind by a wipe");
    let CoreError::RemoteReset(_) = err else {
        panic!("expected RemoteReset, got {err:?}");
    };

    // ---- "Keep local": the path that was unreachable. ----
    block_on(b.adopt_remote_key(secret("gen2-password"))).expect("adopt the remote key");

    // Every live value B had must still read, after the adoption, under the
    // adopted key.
    let new_key = device_key(&db, "gen2-password");
    for (key, old_ct, old_nonce) in &live_before {
        let (new_ct, new_nonce) = row_bytes(&db, key);
        assert_ne!(
            *old_ct, new_ct,
            "{key} must be re-encrypted under the adopted key"
        );
        assert_ne!(*old_nonce, new_nonce);
        assert_eq!(
            decrypt(&new_key, &new_ct, &new_nonce)
                .unwrap_or_else(|e| panic!("{key} must open under the adopted key: {e}"))
                .as_str(),
            b.get_variable("Fudi", "local", key)
                .unwrap_or_else(|_| panic!("{key} must still be there"))
                .value,
            "the adopted key and the value the user reads must agree"
        );
        assert!(
            decrypt(&b_key, &new_ct, &new_nonce).is_err(),
            "{key} must not open under the key it had before"
        );
    }
    assert_eq!(b.list_projects().unwrap().len(), 1);

    assert_eq!(
        tombstone_bytes(&db),
        tombstones_before,
        "the seed's tombstones must be adopted over, not rewritten"
    );
}
