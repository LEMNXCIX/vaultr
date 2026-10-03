//! `rekey` must not decrypt rows nobody will ever read again — the same shape
//! `adopt_remote_key` had, and the same fix.
//!
//! A tombstone is a *metadata* write. A reset keeps every `value_encrypted` and
//! `nonce` byte it found, so a device that pulls those rows is holding
//! ciphertext written under a key domain that nobody holds any more: the reset
//! that wrote it destroyed that key. This is reachable without any corruption
//! at all, on any device that has ever synced a remote that reset.
//!
//! `App::rekey` walked `Storage::all_variables` — every row, tombstones
//! included — and decrypted each one with `?`. So one such tombstone made
//! `vltr rekey` impossible, forever, on that device: there is no prompt to
//! decline, no `--force`, no other command that rotates the master key. The
//! message it gave was "decryption failed (wrong key or corrupted data)", which
//! names corruption the vault does not have and omits the one thing the user
//! could act on.
//!
//! Note this is *worse* than the adoption case, which had an escape hatch. If
//! the remote has NOT moved on since the tombstone was pulled, `sync` succeeds
//! silently and no prompt ever appears — so there is nothing to reach for.
//!
//! Two tests, the decision and its boundary:
//!
//! 1. `rekey_rotates_the_password_over_tombstones_it_cannot_decrypt` — the
//!    behaviour: unreadable tombstones are left alone, the live row moves.
//! 2. `a_live_row_rekey_cannot_decrypt_still_refuses_and_changes_nothing` —
//!    the deliberate asymmetry. Only `deleted` rows are skipped; a live row
//!    that will not decrypt is still a hard error, and it leaves the vault
//!    untouched.
//!
//! # How the fixture is built, and why it is not "corruption"
//!
//! The unreachable rows here are written with a *real* older-domain key, not
//! with random bytes. `old_domain_key` derives a master key from its own salt
//! and the vault's real KDF params, then encrypts a value with it — so each
//! tombstone carries a genuine, correct ciphertext of an older domain, which is
//! exactly what a pulled reset-tombstone is. Both tests assert the row opens
//! under that key and not under this device's, so the fixture cannot pass
//! vacuously and cannot be mistaken for bit-rot. `tests/adopt_tombstones.rs`
//! reaches the same state with no injection at all, through a live server; this
//! file reaches it without one so it stays a fast unit test.
//!
//! # Neither test can reach the keyring
//!
//! The vault is on disk (a second `Storage` handle is how these tests read and
//! write raw rows), and `rekey` *does* call `session::save_master_key`.
//! [`SessionFileOverride`] pins `VLTR_SESSION_FILE` at a temp path for the whole
//! test, which bypasses the keyring entirely (`session.rs:261`). `rekey` needs a
//! real unlock, so the `lock`/`unlock` cycle below is the realistic shape —
//! through a temp file, not `@us`.

use crypto::{decrypt, derive_master_key, encrypt, MasterKey};
use rusqlite::params;
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use storage::Storage;
use vltr_core::{App, CoreError};

const SESSION_FILE_ENV: &str = "VLTR_SESSION_FILE";

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// The password this device is unlocked with throughout both tests.
const CURRENT_PASSWORD: &str = "gen1-password";
/// The password the user is rotating TO.
const NEW_PASSWORD: &str = "gen2-password";

// ---------- Session isolation ----------

/// Point `VLTR_SESSION_FILE` at a temp path and take it back down on drop,
/// including on panic.
///
/// A non-blank override **disables the keyring** for the master-key session
/// (`session::session_file_override`), so a test run cannot borrow the user's
/// `@us` whatever happens here.
struct SessionFileOverride(Option<PathBuf>);

impl SessionFileOverride {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vaultr-rekey-tombstones-{}-{}.json",
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

// ---------- Fixtures ----------

/// A second handle on the device's vault file, for the rows `App` hides.
///
/// Tombstones are unreachable through `App` on purpose (`get_variable` and
/// `list_variables` filter `deleted = 0`), and rekey is decided on exactly the
/// rows `App` hides — so reading and rewriting them needs storage.
fn rows(db: &Path) -> Vec<models::Variable> {
    Storage::open(db)
        .expect("second handle on the device vault")
        .all_variables()
        .expect("every variable row, tombstones included")
}

/// `(value_encrypted, nonce)` of the row with this key, live or not.
fn row_bytes(db: &Path, key: &str) -> (Vec<u8>, Vec<u8>) {
    let var = rows(db)
        .into_iter()
        .find(|v| v.key == key)
        .unwrap_or_else(|| panic!("no variable row named {key}"));
    (var.value_encrypted, var.nonce)
}

/// `(id, value_encrypted, nonce)` of every tombstone, keyed for a
/// byte-for-byte comparison across the operation.
fn tombstone_bytes(db: &Path) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>, Vec<u8>)> = rows(db)
        .into_iter()
        .filter(|v| v.deleted)
        .map(|v| (v.id.to_string(), v.value_encrypted, v.nonce))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The key `rekey` decrypts with (`old_key = self.require_key()`), derived from
/// the salt and KDF params `vault_meta` actually holds.
///
/// Derived from the vault rather than captured from the `App`, so the test
/// cannot pass by holding a key the vault does not agree with.
fn device_key(db: &Path, password: &str) -> MasterKey {
    let meta = Storage::open(db)
        .expect("second handle on the device vault")
        .get_vault_meta()
        .expect("vault_meta");
    derive_master_key(&secret(password), &meta.salt, &meta.kdf_params).expect("derive")
}

/// A real master key from an **older domain**: this vault's own KDF params (a
/// rotation keeps them — see [`App::rekey`]) under a fixed salt from before.
///
/// The salt is a constant, not `generate_salt()`. This helper is called more
/// than once per test, to re-check a row *after* the operation, and a fresh
/// salt each time would hand back a different key — so every such check would
/// fail for a reason that has nothing to do with the vault, or, worse, pass for
/// the wrong reason. A fixture that lies about which key wrote a row is worse
/// than no fixture.
fn old_domain_key(db: &Path) -> MasterKey {
    const OLD_SALT: [u8; 16] = *b"gen0-salt-16byte";
    let meta = Storage::open(db)
        .expect("second handle on the device vault")
        .get_vault_meta()
        .expect("vault_meta");
    derive_master_key(&secret("gen0-password"), &OLD_SALT, &meta.kdf_params).expect("derive")
}

/// Rewrite the named rows' ciphertext with a genuine older-domain ciphertext.
///
/// This models what a pull delivers, not corruption: a reset marks rows deleted
/// and leaves their `value_encrypted`/`nonce` exactly as it found them, so a
/// device that pulls them afterwards holds ciphertext from a domain whose key
/// the reset destroyed. The bytes written here are a correct `encrypt` under
/// that older key, which is what makes the difference between "wrong key" and
/// "corrupted data" a fact rather than a guess.
fn age_rows_into_the_old_domain(db: &Path, keys: &[&str], old_key: &MasterKey) {
    let storage = Storage::open(db).expect("second handle on the device vault");
    let ids: Vec<String> = storage
        .all_variables()
        .expect("rows")
        .into_iter()
        .filter(|v| keys.contains(&v.key.as_str()))
        .map(|v| v.id.to_string())
        .collect();
    assert_eq!(
        ids.len(),
        keys.len(),
        "every named row must exist to be aged: {keys:?}"
    );
    for id in &ids {
        let (ciphertext, nonce) =
            encrypt(old_key, "written-by-a-domain-this-device-does-not-hold").expect("encrypt");
        storage
            .conn()
            .execute(
                "UPDATE variables SET value_encrypted = ?1, nonce = ?2 WHERE id = ?3",
                params![ciphertext, nonce, id],
            )
            .expect("overwrite the row ciphertext");
    }
}

/// Assert a row is a *live* older-domain row: this device's key cannot open it,
/// the older domain's key can.
///
/// Both halves matter. Without the first the test would pass vacuously; without
/// the second the unreadability could be corruption instead of the key
/// mismatch this is about, which is precisely the confusion the fix exists to
/// stop.
fn assert_unreadable_here_readable_there(db: &Path, key: &str, old_key: &MasterKey) {
    let (ct, nonce) = row_bytes(db, key);
    assert!(
        decrypt(&device_key(db, CURRENT_PASSWORD), &ct, &nonce).is_err(),
        "{key} must be unreadable to this device, or the test reproduces nothing"
    );
    assert!(
        decrypt(old_key, &ct, &nonce).is_ok(),
        "{key} must be a valid older-domain ciphertext, not corruption: the whole \
         point is that this is a wrong key and nothing else"
    );
}

/// A device vault holding one live row and two tombstones aged into a domain
/// nobody holds — the state a pull leaves behind after a remote reset.
///
/// Returns `(App, PathBuf)`. The `App` is unlocked, as a real `vltr rekey` finds
/// it: `init` left it holding the key.
fn vault_with_aged_rows(db: &Path) -> App {
    let mut app = App::open(db).expect("open");
    app.init(secret(CURRENT_PASSWORD)).expect("init");
    app.create_project("Fudi", None, None, None)
        .expect("project");
    for (key, value) in [
        ("LIVE", "live-value"),
        ("GONE_ONE", "gone-one-value"),
        ("GONE_TWO", "gone-two-value"),
    ] {
        app.set_variable("Fudi", "local", key, value, None)
            .expect("variable");
    }
    // `delete_variable` is a tombstone: the row stays and keeps its ciphertext,
    // which is what the next step replaces.
    app.delete_variable("Fudi", "local", "GONE_ONE")
        .expect("delete");
    app.delete_variable("Fudi", "local", "GONE_TWO")
        .expect("delete");

    let old_key = old_domain_key(db);
    age_rows_into_the_old_domain(db, &["GONE_ONE", "GONE_TWO"], &old_key);

    // The fixture, checked from the vault's own key.
    assert_unreadable_here_readable_there(db, "GONE_ONE", &old_key);
    assert_unreadable_here_readable_there(db, "GONE_TWO", &old_key);
    let (live_ct, live_nonce) = row_bytes(db, "LIVE");
    assert_eq!(
        decrypt(&device_key(db, CURRENT_PASSWORD), &live_ct, &live_nonce)
            .expect("the live row is readable")
            .as_str(),
        "live-value",
        "the live row must be readable, or a rekey that touched nothing would pass"
    );
    app
}

// ---------------------------------------------------------------------------
// 1. The behaviour
// ---------------------------------------------------------------------------

/// Rekey over a vault holding tombstones it cannot decrypt must rotate the
/// password, move the live row, and leave the tombstones untouched.
///
/// Against the bug this fails at `expect("rekey")` with `decryption failed
/// (wrong key or corrupted data)` — the `?` on `decrypt` inside the rekey loop,
/// cutting on the first tombstone, after the user had already typed the new
/// password twice. The vault is left exactly as it was, so the retry fails the
/// same way, forever.
///
/// Fails against: rekey that decrypts every row `all_variables` returns (the
/// bug); an impl that filters on something other than `deleted` (the live value
/// would be stranded under the old key and lost); one that swallows the failure
/// with `if let Ok(..)` and so leaves a vault whose verifier and contents
/// disagree; one that *deleted* the unreadable rows instead of skipping them
/// (the `deleted` flags, and the rows themselves, would vanish).
#[test]
fn rekey_rotates_the_password_over_tombstones_it_cannot_decrypt() {
    let _session = SessionFileOverride::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");

    let mut app = vault_with_aged_rows(&db);

    // The full lock/unlock cycle a real `vltr rekey` runs: it prompts for the
    // current password and unlocks first (`crates/cli/src/main.rs:506`).
    app.lock().expect("lock");
    app.unlock(secret(CURRENT_PASSWORD)).expect("unlock");

    let salt_before = Storage::open(&db)
        .expect("handle")
        .get_vault_meta()
        .expect("meta")
        .salt;
    let live_before = row_bytes(&db, "LIVE");
    let tombstones_before = tombstone_bytes(&db);
    assert_eq!(tombstones_before.len(), 2, "two tombstones to trip over");

    // ---- The line the bug lives on. ----
    let count = app.rekey(secret(NEW_PASSWORD)).expect("rekey");

    assert_eq!(
        count, 1,
        "the count is what the CLI prints as \"variables re-encrypted\", and it \
         must be the number of live rows moved — a user with 1 secret and 2 \
         tombstones has 1 variable, not 3"
    );

    // The rotation actually landed: new password opens the vault, old one does
    // not, and the salt moved.
    assert!(
        app.verify_password(secret(NEW_PASSWORD)).is_ok(),
        "the new password must open the vault"
    );
    assert!(
        app.verify_password(secret(CURRENT_PASSWORD)).is_err(),
        "and the old one must not"
    );
    let salt_after = Storage::open(&db)
        .expect("handle")
        .get_vault_meta()
        .expect("meta")
        .salt;
    assert_ne!(salt_before, salt_after, "a rekey rotates the salt");

    // Close/reopen under the new password: the live value survives it.
    app.lock().expect("lock");
    app.unlock(secret(NEW_PASSWORD)).expect("unlock");
    assert_eq!(
        app.get_variable("Fudi", "local", "LIVE")
            .expect("the row rekey was called to protect must survive it")
            .value,
        "live-value"
    );
    let live_after = row_bytes(&db, "LIVE");
    assert_ne!(
        live_before.0, live_after.0,
        "the live row must have been re-encrypted under the new key"
    );
    let new_key = device_key(&db, NEW_PASSWORD);
    assert_eq!(
        decrypt(&new_key, &live_after.0, &live_after.1)
            .expect("the live row opens under the new key")
            .as_str(),
        "live-value",
        "the key the user will type and the value the user reads must agree"
    );
    assert!(
        decrypt(
            &device_key(&db, CURRENT_PASSWORD),
            &live_after.0,
            &live_after.1
        )
        .is_err(),
        "and no longer under the key it had before"
    );

    // The tombstones are still tombstones, still listed nowhere, and their bytes
    // are untouched — the same invariant a reset and an adoption keep. Rekey did
    // not have to read them, so it must not have rewritten them.
    assert_eq!(
        tombstone_bytes(&db),
        tombstones_before,
        "a tombstone's ciphertext and nonce must survive a rekey byte for byte"
    );
    assert_eq!(
        tombstone_bytes(&db)
            .iter()
            .filter(|(_, ct, _)| !ct.is_empty())
            .count(),
        2,
        "and must still be there at all: skipping is not deleting"
    );
    // Skipping loses nothing, and this is the proof rather than the assertion:
    // the only key on earth that could ever read those rows still can.
    assert!(
        decrypt(
            &old_domain_key(&db),
            &tombstone_bytes(&db)[0].1,
            &tombstone_bytes(&db)[0].2
        )
        .is_ok(),
        "the older domain must still open its own tombstones: a rekey that \
         cannot read them must leave them for whoever can"
    );

    app.lock().expect("leave no session behind");
}

// ---------------------------------------------------------------------------
// 2. The boundary
// ---------------------------------------------------------------------------

/// A **live** row rekey cannot decrypt must still refuse, and must change
/// nothing while doing so.
///
/// This is the deliberate asymmetry, and it is the half that makes skipping
/// safe. `deleted = true` means "nobody will read this again", so skipping one
/// loses nothing. A live row means the opposite: it is a secret the user
/// believes they have. Refusing is the only honest answer, because rekeying
/// around it would leave a vault whose verifier advertises one key over a row
/// encrypted under another — the silent divergence this codebase has already
/// paid for twice.
///
/// And the refusal has to be atomic. `rekey` derives the new key, decrypts
/// everything, and only then writes; so a failure here happens before
/// `apply_key_rotation` and the vault is untouched. That is checked from the
/// outside — the user's old password still works and the value still reads — so
/// the test does not pass merely because the error was raised.
///
/// Fails against: a `let Ok(..) = decrypt(..) else { continue }` (no error);
/// a rekey that writes `vault_meta` before decrypting (the salt moves and the
/// old password stops working); one that skips unreadable rows regardless of
/// `deleted` (the live row would be silently stranded under the old key, and
/// the new password would decrypt to nothing).
#[test]
fn a_live_row_rekey_cannot_decrypt_still_refuses_and_changes_nothing() {
    let _session = SessionFileOverride::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vault.db");

    let mut app = vault_with_aged_rows(&db);

    // The live row — not a tombstone — is the one that cannot be read.
    let old_key = old_domain_key(&db);
    age_rows_into_the_old_domain(&db, &["LIVE"], &old_key);
    assert_unreadable_here_readable_there(&db, "LIVE", &old_key);

    let meta_before = Storage::open(&db)
        .expect("handle")
        .get_vault_meta()
        .expect("meta");
    let live_before = row_bytes(&db, "LIVE");

    // ---- The refusal. ----
    let err = app
        .rekey(secret(NEW_PASSWORD))
        .expect_err("a live row that will not decrypt must stop the rotation");

    let CoreError::Crypto(crypto::CryptoError::Decryption) = err else {
        panic!("expected a decryption failure, got {err:?}");
    };

    // Nothing moved. The vault is still the vault the user's password opens.
    let meta_after = Storage::open(&db)
        .expect("handle")
        .get_vault_meta()
        .expect("meta");
    assert_eq!(
        meta_after.salt, meta_before.salt,
        "a refused rekey must not have rotated the salt"
    );
    assert_eq!(
        meta_after.key_epoch, meta_before.key_epoch,
        "nor advanced the epoch"
    );
    assert_eq!(
        meta_after.verifier_ct, meta_before.verifier_ct,
        "nor re-encrypted the verifier"
    );
    assert!(
        app.verify_password(secret(CURRENT_PASSWORD)).is_ok(),
        "the old password must still open the vault the user did not ask to change"
    );
    assert!(
        app.verify_password(secret(NEW_PASSWORD)).is_err(),
        "and the rekey that failed must not have left its password half-installed"
    );
    assert!(
        app.is_unlocked(),
        "the in-memory key must still be the one the vault describes"
    );

    // The rows are untouched too — including the tombstones, which were
    // readable-by-nobody but not touched.
    assert_eq!(
        row_bytes(&db, "LIVE"),
        live_before,
        "a refused rekey must not have rewritten the row it could not read"
    );
    assert_eq!(tombstone_bytes(&db).len(), 2, "nor dropped the tombstones");

    app.lock().expect("leave no session behind");
}
