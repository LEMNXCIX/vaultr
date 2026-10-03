//! H2 / H3 — the master key changed, so the session holding it has to change
//! with it. Nobody examined that intersection.
//!
//! Three sites change the key and all three swallow the session save into
//! `App::last_session_error`:
//!
//! * `reset_local` — `crates/core/src/lib.rs:312`
//! * `adopt_remote_key` — `crates/core/src/sync/mod.rs:269`
//! * `discard_local_and_adopt` — `crates/core/src/sync/mod.rs:338`
//!
//! `session::save_master_key` has two ways to leave the stored session
//! describing the wrong vault (`crates/core/src/session.rs:297`): it returns
//! `Err` when the keyring and the fallback both fail, and it returns `Ok(())
//! doing nothing` when `db_path()` is `None`. Neither reaches the user — see the
//! report for the line-by-line answer about the CLI.
//!
//! # Fault injection, and why the bytes are restored instead
//!
//! These tests rebuild the state a failed save leaves behind by restoring the
//! session file's previous bytes, rather than by making the write fail. That is
//! deliberate:
//!
//! * `save_master_key` with `VLTR_SESSION_FILE` set never touches the keyring
//!   (`session.rs:302`), so that override is the only route to a real failure
//!   that does not consult the user's keyring — and it only fails when the
//!   filesystem refuses the write.
//! * The only asymmetric read/write failures are permission-based, and the
//!   mandated `unshare --user --map-root-user` sandbox maps the runner to root,
//!   which bypasses them. A `chmod 0400` session file is still writable there,
//!   so a permission-based injection would pass vacuously inside the sandbox and
//!   fail outside it. Restoring the bytes yields the same state and is portable.
//!
//! # Nothing here can reach the keyring
//!
//! Both session overrides are set for the whole file — `VLTR_SESSION_FILE` owns
//! the master-key session (`session.rs:302`) and `VLTR_SYNC_SESSION_FILE` owns
//! the account session — so no entry is ever written to `@us`. Nothing here
//! talks to Supabase either.

use crypto::MasterKey;
use secrecy::SecretString;
use vltr_core::session::SessionStore;
use vltr_core::App;

const SYNC_SESSION_FILE_ENV: &str = "VLTR_SYNC_SESSION_FILE";
const SESSION_FILE_ENV: &str = "VLTR_SESSION_FILE";

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// `VLTR_SESSION_FILE` is process-global; serialise the tests that set it.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The `key_hex` the session file stores — the exact bytes `load_master_key`
/// hands to `unlock_with_key`.
fn stored_key_hex(path: &std::path::Path) -> String {
    let raw = std::fs::read_to_string(path).expect("session file");
    serde_json::from_str::<serde_json::Value>(&raw).expect("payload is JSON")["key_hex"]
        .as_str()
        .expect("payload carries key_hex")
        .to_owned()
}

fn master_key_from_hex(hex_str: &str) -> MasterKey {
    let bytes = hex::decode(hex_str).expect("hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    MasterKey::from(arr)
}

/// A real vault on disk, with the two session overrides pinned at temp paths.
struct Fixture {
    _dir: tempfile::TempDir,
    db: std::path::PathBuf,
    session: std::path::PathBuf,
    _env: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let env = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vault.db");
        let session = dir.path().join("session.json");
        std::env::set_var(SESSION_FILE_ENV, &session);
        std::env::set_var(SYNC_SESSION_FILE_ENV, dir.path().join("sync.json"));
        Self {
            _dir: dir,
            db,
            session,
            _env: env,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::env::remove_var(SESSION_FILE_ENV);
        std::env::remove_var(SYNC_SESSION_FILE_ENV);
    }
}

// ---------------------------------------------------------------------------
// H2a — the stale session looks healthy
// ---------------------------------------------------------------------------

/// The state a failed `save_master_key` leaves behind, asserted end to end.
///
/// Setup: a real vault and a real session file. After `reset_local` the vault is
/// encrypted under the **new** key; the session file is then restored to the
/// bytes it held before, which is exactly what a save that returned `Err` (or
/// one that never ran) leaves on disk.
///
/// The load-bearing pair is the first two assertions, and they are opposites:
///
/// * `has_keyring_session()?` / `session_store()?` say a live session exists.
///   That is the **only** thing `print_session_status` looks at
///   (`crates/cli/src/main.rs:1043-1048`), and its `Some(..)` arms return
///   without ever reading `take_session_error()`.
/// * `try_unlock_from_session()` fails, because the key that session stores
///   cannot decrypt the vault verifier any more, and the same is true of those
///   32 bytes handed straight to `unlock_with_key`.
///
/// So the session reports itself healthy and is worth nothing at the same time,
/// and nothing above `core` says so. That is H2's "silent by construction".
#[test]
fn a_stale_session_left_behind_by_a_failed_save_reports_healthy_and_opens_nothing() {
    let fx = Fixture::new();

    let mut app = App::open(&fx.db).expect("open");
    app.init(secret("old-password")).expect("init");
    app.create_project("Fudi", None, None, None).unwrap();
    app.set_variable("Fudi", "local", "TOKEN", "live-value", None)
        .unwrap();

    // The session the reset is about to invalidate.
    let stale_bytes = std::fs::read(&fx.session).expect("init saved a session");
    let stale_hex = stored_key_hex(&fx.session);
    assert_eq!(
        app.take_session_error(),
        None,
        "precondition: `init` saved its session (the override file is writable), \
         so nothing is pending here and every signal below is about the reset"
    );

    // `reset_local` — the key changes. The verifier is now encrypted under the
    // new key and the old one is gone for good.
    app.reset_local(secret("new-password"))
        .expect("reset_local");
    assert!(app.is_unlocked(), "the in-memory key is the new one");
    assert!(app.verify_password(secret("new-password")).is_ok());
    assert!(app.verify_password(secret("old-password")).is_err());

    // The state under review: the save that would have replaced the session did
    // not land, so the old bytes are still on disk.
    std::fs::write(&fx.session, &stale_bytes).expect("restore the stale session");

    // --- The signals the CLI uses ------------------------------------------------
    let mut probe = App::open(&fx.db).expect("a fresh process on the same vault");
    assert!(
        probe.has_keyring_session().expect("inspect"),
        "a session store IS present — this is the condition `print_session_status` \
         returns on, so it reports nothing at all about a save that failed"
    );
    assert_eq!(
        probe.session_store().expect("store"),
        Some(SessionStore::Memory),
        "same, and specifically the store arm `print_session_status` takes"
    );

    // --- What that session is actually worth -------------------------------------
    let err = probe
        .try_unlock_from_session()
        .expect_err("the stored key predates the reset and cannot open the vault");
    assert!(
        matches!(err, vltr_core::CoreError::InvalidPassword(_)),
        "expected invalid_password from the verifier check, got {err:?}"
    );
    assert!(!probe.is_unlocked());

    // Direct, with no session machinery in the way: the 32 bytes on disk are
    // rejected by the very vault they claim to open.
    let mut probe2 = App::open(&fx.db).expect("a second fresh process");
    let err = probe2
        .unlock_with_key(master_key_from_hex(&stale_hex))
        .expect_err("the stored session key cannot decrypt the vault it names");
    assert!(matches!(err, vltr_core::CoreError::InvalidPassword(_)));

    // And the session survives that rejection. It should not: a key that cannot
    // decrypt the verifier is provably not the key of this vault, and leaving it
    // behind poisons every later command for the rest of its 30-minute TTL. See
    // `a_session_key_that_cannot_decrypt_the_verifier_is_cleared` for the
    // minimal repro; this assertion is the consequence.
    assert!(
        !probe.has_keyring_session().expect("inspect again"),
        "a rejected session key must not stay in the store: while it does, every \
         command re-probes it, fails, and reports 'invalid master password' \
         instead of asking for the password — and `unlock_with_key` is the one \
         place that could have cleared it"
    );
}

// ---------------------------------------------------------------------------
// H2b — the stale session is never cleared  ← RED
// ---------------------------------------------------------------------------

/// The minimal repro of H2b, with no fault injection and no HTTP: a session key
/// that cannot decrypt the vault verifier must be dropped.
///
/// `unlock_with_key` clearly intends to — `crates/core/src/lib.rs:332-334` calls
/// `session::clear_session` and returns the same error the caller already gets.
/// But it only reaches there when the marker **decrypts** to something other
/// than `VAULT_VERIFIER_MESSAGE`. A real key change makes the decrypt **fail**,
/// and line 331's `?` returns first. The clear is unreachable for exactly the
/// case it was written for.
///
/// Consequence, asserted below: after a key change whose session save failed,
/// the stale session stays on disk for its full sliding TTL, and every command
/// in that window gets `InvalidPassword` from `try_unlock_from_session`
/// (`crates/cli/src/main.rs:1022`) — which `open_and_unlock` propagates with
/// `?`. So `vltr ls` dies with "invalid master password" instead of prompting,
/// for 30 minutes, with no explanation.
///
/// Fails against: the current early return at `lib.rs:330-331`. The fix is to
/// clear the session on *either* rejection path — i.e. drop the `?` at 331 and
/// fold both cases into one `clear_session` + error.
#[test]
fn a_session_key_that_cannot_decrypt_the_verifier_is_cleared() {
    let fx = Fixture::new();

    let mut app = App::open(&fx.db).expect("open");
    app.init(secret("old-password")).expect("init");
    let stale_bytes = std::fs::read(&fx.session).expect("init saved a session");
    let stale_hex = stored_key_hex(&fx.session);

    // The key changes; the session is never updated (the failed save).
    app.reset_local(secret("new-password"))
        .expect("reset_local");
    std::fs::write(&fx.session, &stale_bytes).expect("the save never landed");
    assert!(
        App::open(&fx.db).unwrap().has_keyring_session().unwrap(),
        "precondition: a session store exists"
    );

    let mut app = App::open(&fx.db).expect("open");
    let err = app
        .unlock_with_key(master_key_from_hex(&stale_hex))
        .expect_err("the old key no longer opens the vault");
    assert!(matches!(err, vltr_core::CoreError::InvalidPassword(_)));

    assert!(
        !app.has_keyring_session().expect("inspect"),
        "THE BUG: `unlock_with_key` returns at lib.rs:331, before the \
         `clear_session` at lib.rs:333. A key proven not to belong to this vault \
         stays in the session, so every command keeps re-probing it and keeps \
         answering 'invalid master password' for the rest of its 30-minute TTL — \
         instead of falling through to the password prompt"
    );

    // What the user gets in the meantime. Not a prompt: an error, from
    // `open_and_unlock`'s `?` at main.rs:1022 — and for as long as the TTL lasts,
    // because nothing clears the session.
    let mut later = App::open(&fx.db).expect("open");
    assert!(
        !later.try_unlock_from_session().expect(
            "a cleared session must read as a plain miss so `open_and_unlock` \
             falls through to `prompt_password`"
        ),
        "a stale session turns every command into 'invalid master password' \
         instead of a prompt, and the password that would work is the one just set"
    );
}

// ---------------------------------------------------------------------------
// H2c — H2 × H1: the failure lands on the command that needed no key  ← RED
// ---------------------------------------------------------------------------

/// The two findings meet. The stale session is silently kept, and the command
/// that runs next is `vltr sync` — which `crates/cli/src/main.rs:647` gates
/// behind `open_and_unlock`, i.e. behind a master-password prompt.
///
/// So the user who ran `reset --local` because they lost their password, and
/// whose session save failed, cannot run the one command that would have
/// finished the wipe: `open_and_unlock`'s `?` turns `InvalidPassword` into a
/// hard error. And even with a working session, `main.rs:647` demands a
/// password for a sync that
/// `reset_locked_sync.rs::sync_needs_no_master_key_outside_the_verifier_backfill`
/// proves needs none.
///
/// Fails against: H2b's early return, and the unconditional `open_and_unlock`
/// at `main.rs:647`.
#[test]
fn the_stale_session_blocks_the_sync_that_would_have_finished_the_wipe() {
    let fx = Fixture::new();

    let mut app = App::open(&fx.db).expect("open");
    app.init(secret("old-password")).expect("init");
    let stale_bytes = std::fs::read(&fx.session).expect("init saved a session");
    app.reset_local(secret("new-password"))
        .expect("reset_local");
    assert!(app.pending_reset().expect("a wipe is pending"));
    std::fs::write(&fx.session, &stale_bytes).expect("the save never landed");

    // First command after the reset, from a fresh process: `vltr sync` runs
    // `open_and_unlock`, whose `?` propagates this error out of `main`.
    let mut probe = App::open(&fx.db).expect("open");
    let err = probe.try_unlock_from_session().expect_err("stale session");
    assert!(matches!(err, vltr_core::CoreError::InvalidPassword(_)));

    // Second command, and every one after it for the TTL: the store was never
    // cleared, so the prompt is never reached.
    let mut probe = App::open(&fx.db).expect("open");
    assert!(
        !probe.try_unlock_from_session().expect(
            "a cleared session must read as a plain miss, so `open_and_unlock` \
             reaches `prompt_password` instead of failing on the stale entry"
        ),
        "`vltr sync` must be able to reach the prompt — or, better, must not need \
         one — but a stale session turns the pending-reset wipe into a hard \
         'invalid master password' error instead"
    );

    // The vault itself is fine and the wipe is not what broke: this is purely the
    // session lying about which key this vault uses.
    probe
        .unlock(secret("new-password"))
        .expect("the new password still opens it");
    assert!(probe
        .pending_reset()
        .expect("and the wipe is still pending"));
}

// ---------------------------------------------------------------------------
// H3 — `db_path() == None`
// ---------------------------------------------------------------------------

/// `save_master_key` returns `Ok(())` without writing anything when
/// `db_path()` is `None` (`crates/core/src/session.rs:298`) — H2's second
/// branch. Whether that is reachable with a vault a user can act on is H3's
/// question.
///
/// It is not. `Storage::db_path` is `None` only for `open_in_memory`
/// (`crates/storage/src/lib.rs:103`) and `Storage::open` always stores
/// `Some(path)` (`crates/storage/src/lib.rs:94`). Every `App` the CLI builds
/// goes through `App::open` (`crates/cli/src/main.rs:193`), so a real vault
/// always has a path and the `Ok`-while-doing-nothing branch is dead outside
/// tests.
///
/// Asserted from the outside, so it fails if `Storage::open` ever gains a way to
/// return a pathless vault.
#[test]
fn db_path_is_none_only_for_in_memory_storage() {
    let fx = Fixture::new();

    let file_backed = App::open(&fx.db).expect("open");
    assert_eq!(
        file_backed.db_path(),
        Some(fx.db.as_path()),
        "a vault a user can act on must have a path, or every session it saves \
         would silently do nothing"
    );

    // And the in-memory branch really is a silent no-op rather than an error.
    let mut in_memory = App::open_in_memory().expect("open");
    assert_eq!(in_memory.db_path(), None);
    in_memory.init(secret("pw")).expect("init");
    assert_eq!(
        in_memory.take_session_error(),
        None,
        "`save_master_key(None, ..)` returns Ok and writes nothing: the failure \
         H2 calls 'Ok while doing nothing' is exactly this, and it leaves no \
         trace at all — which is why it only matters for tests, never for a user"
    );
}
