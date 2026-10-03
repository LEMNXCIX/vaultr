//! Session store for the master key: OS keyring first, 0600 local session file fallback.
//! Sliding 30-minute TTL in both backends.

use crate::CoreError;
use crypto::MasterKey;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use models::constants::{KEYRING_ACCOUNT, KEYRING_SERVICE, SESSION_TTL_SECS};

/// Where the current session lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStore {
    Keyring,
    Memory,
}

impl fmt::Display for SessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keyring => "OS keyring",
            Self::Memory => "local session file",
        })
    }
}

/// Snapshot of an existing session (does not refresh the TTL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    pub remaining_secs: u64,
    pub store: SessionStore,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionPayload {
    /// Hex-encoded 32-byte master key.
    key_hex: String,
    /// Unix timestamp (seconds) when the session expires.
    expires_at: u64,
}

/// Length in hex chars of the per-database session account (64 bits).
const ACCOUNT_HEX_LEN: usize = 16;

/// Absolute, canonicalized form of a database path, used as hash input.
///
/// Absolute first, or two vaults with the same name in different directories
/// would collide. Only the parent is canonicalized: on `init` the file itself
/// does not exist yet. Any failure falls back to the plain absolute path — a
/// stable account beats a panic.
fn canonical_db_path(path: &Path) -> PathBuf {
    // `std::path::absolute` needs Rust 1.79; the MSRV here is 1.75.
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    match absolute.parent() {
        Some(parent) => match (parent.canonicalize(), absolute.file_name()) {
            (Ok(canonical), Some(name)) => canonical.join(name),
            _ => absolute,
        },
        None => absolute,
    }
}

/// Session identifier unique per database, always 16 hex chars.
///
/// The keyring account cannot be a literal: with one global account, `lock` on
/// any vault clears every other vault's session and `init` on a new database
/// overwrites the real one. SHA-256 of the canonical path, truncated — enough
/// to separate local vaults, and it keeps the path out of the keyring
/// metadata, which any process holding the key can read.
fn session_account(db_path: &Path) -> String {
    let canonical = canonical_db_path(db_path);
    // Exact bytes on unix; lossy elsewhere (Windows paths are rarely
    // non-UTF-8, and `as_encoded_bytes` would not be stable across releases).
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        canonical.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = canonical.to_string_lossy().into_owned().into_bytes();

    let digest = hex::encode(Sha256::digest(&bytes));
    digest[..ACCOUNT_HEX_LEN].to_string()
}

fn entry(db_path: &Path) -> Result<Entry, CoreError> {
    #[cfg(test)]
    keyring_probe::record();
    let account = format!("{KEYRING_ACCOUNT}-{}", session_account(db_path));
    Entry::new(KEYRING_SERVICE, &account).map_err(|e| CoreError::Other(format!("keyring: {e}")))
}

/// Test-only count of keyring requests made by this thread. The override tests
/// need to prove the keyring was skipped *without* touching the real one, and
/// "the session round-tripped" cannot show that: a run that consulted the
/// keyring would still leave the user's own session intact (it is
/// per-database), but it would also mean the override does not own the
/// session — and on a machine whose keyring works, `save` would write the real
/// entry for that vault.
#[cfg(test)]
mod keyring_probe {
    use std::cell::Cell;

    thread_local! {
        pub static KEYRING_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub fn calls() -> usize {
        KEYRING_CALLS.with(Cell::get)
    }

    pub fn record() {
        KEYRING_CALLS.with(|calls| calls.set(calls.get() + 1));
    }
}

#[cfg(test)]
fn keyring_calls() -> usize {
    keyring_probe::calls()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_payload(key: &MasterKey) -> SessionPayload {
    SessionPayload {
        key_hex: hex::encode(key.as_ref()),
        expires_at: now_unix().saturating_add(SESSION_TTL_SECS),
    }
}

fn payload_seconds_remaining(payload: &SessionPayload) -> Option<u64> {
    payload
        .expires_at
        .checked_sub(now_unix())
        .filter(|&secs| secs > 0)
}

fn decode_key(key_hex: &str) -> Option<MasterKey> {
    let bytes = hex::decode(key_hex.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Zeroizing::new(arr))
}

/// `VLTR_SESSION_FILE` override, or `None` when it is unset, empty or
/// whitespace-only.
///
/// An empty value is not a path: `export VLTR_SESSION_FILE=` in a `.env` or a
/// shell profile is a common accident, and honoring it would point the session
/// file at the current directory instead of the per-database fallback. Blank
/// therefore means "not set". A non-blank value is used verbatim, including a
/// non-UTF-8 path.
///
/// A non-blank value also **disables the keyring**, the same way
/// `VLTR_SYNC_SESSION_FILE` does for the account session: it owns the whole
/// session, not just the file half. Redirecting only the fallback would still
/// consult — and write — the real entry, which is useless for the two things
/// the override exists for: a test run cannot borrow the user's keyring, and a
/// machine with no usable keyring has no fallback to redirect. See
/// [`save_master_key`].
fn session_file_override() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("VLTR_SESSION_FILE")?;
    if raw.to_str().is_some_and(|raw| raw.trim().is_empty()) {
        return None;
    }
    Some(std::path::PathBuf::from(raw))
}

/// Path of the fallback session file for one database. Overridable via
/// `VLTR_SESSION_FILE` (tests and debugging), which replaces the whole path.
///
/// Otherwise the name carries the per-database account: a fixed filename would
/// make every vault share one session file.
fn session_file_path(db_path: &Path) -> Result<std::path::PathBuf, CoreError> {
    if let Some(path) = session_file_override() {
        return Ok(path);
    }
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| CoreError::Other("cannot determine Vaultr data directory".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("session-{}.json", session_account(db_path))))
}

pub(crate) fn write_0600(path: &std::path::Path, data: &str) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data.as_bytes())?;
        // ponytail: chmod tras crear cubre filesystems que ignoran mode() en create
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?; // Windows: ACLs fuera de scope del MVP
    Ok(())
}

fn save_memory_file(db_path: &Path, key: &MasterKey) -> Result<(), CoreError> {
    let path = session_file_path(db_path)?;
    let json = serde_json::to_string(&build_payload(key))
        .map_err(|e| CoreError::Other(format!("serialize session: {e}")))?;
    write_0600(&path, &json)
}

/// Read the session file. Expired or corrupt → delete it and return None.
/// Valid → refresh the sliding TTL before returning the key.
fn load_memory_file(db_path: &Path) -> Result<Option<MasterKey>, CoreError> {
    let path = session_file_path(db_path)?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let payload: SessionPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
    };
    if payload_seconds_remaining(&payload).is_none() {
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    }
    let Some(key) = decode_key(&payload.key_hex) else {
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    };
    // Sliding TTL: extend on every successful use.
    let _ = save_memory_file(db_path, &key);
    Ok(Some(key))
}

fn memory_seconds_remaining(db_path: &Path) -> Result<Option<u64>, CoreError> {
    let path = session_file_path(db_path)?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match serde_json::from_str::<SessionPayload>(&raw) {
        Ok(payload) => match payload_seconds_remaining(&payload) {
            Some(secs) => Ok(Some(secs)),
            None => {
                let _ = std::fs::remove_file(&path);
                Ok(None)
            }
        },
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            Ok(None)
        }
    }
}

fn stop_memory_file(db_path: &Path) -> Result<(), CoreError> {
    let _ = std::fs::remove_file(session_file_path(db_path)?);
    Ok(())
}

/// Persist the master key of `db_path` with a fresh 30-minute TTL.
/// Prefers the OS keyring; falls back to a 0600 session file next to the vault data.
///
/// `db_path = None` (in-memory storage) persists nothing: there is no database
/// to scope the session to, so a global entry would let an in-memory vault
/// overwrite any real one.
///
/// `VLTR_SESSION_FILE` set to a non-blank path bypasses the keyring entirely
/// (see [`session_file_override`]).
pub fn save_master_key(db_path: Option<&Path>, key: &MasterKey) -> Result<(), CoreError> {
    let Some(db_path) = db_path else {
        return Ok(());
    };
    // Override: solo el archivo, el keyring no se toca.
    if session_file_override().is_some() {
        return save_memory_file(db_path, key);
    }
    if save_keyring(db_path, key) {
        let _ = stop_memory_file(db_path);
        return Ok(());
    }
    save_memory_file(db_path, key)
}

/// Load the master key of `db_path` if a session exists and is not expired.
/// On success, **refreshes** the TTL (sliding expiration).
pub fn load_master_key(db_path: Option<&Path>) -> Result<Option<MasterKey>, CoreError> {
    let Some(db_path) = db_path else {
        return Ok(None);
    };
    // Override: se lee el archivo, el keyring no se toca.
    if session_file_override().is_some() {
        return load_memory_file(db_path);
    }
    if let Some(key) = load_keyring(db_path)? {
        return Ok(Some(key));
    }
    load_memory_file(db_path)
}

/// Clear the persisted session of `db_path` only.
pub fn clear_session(db_path: Option<&Path>) -> Result<(), CoreError> {
    let Some(db_path) = db_path else {
        return Ok(());
    };
    // Override: se borra el archivo y el keyring no se toca.
    if session_file_override().is_some() {
        return stop_memory_file(db_path);
    }
    let _ = clear_keyring(db_path);
    let _ = stop_memory_file(db_path);
    Ok(())
}

/// Inspect the current session of `db_path` without refreshing its TTL.
pub fn inspect(db_path: Option<&Path>) -> Result<Option<SessionInfo>, CoreError> {
    let Some(db_path) = db_path else {
        return Ok(None);
    };
    // Con override la sesión vive en el archivo: reportar "OS keyring" sería
    // mentir, porque ni `load_master_key` ni `clear_session` lo mirarían.
    if session_file_override().is_none() {
        if let Some(remaining_secs) = keyring_seconds_remaining(db_path)? {
            return Ok(Some(SessionInfo {
                remaining_secs,
                store: SessionStore::Keyring,
            }));
        }
    }
    if let Some(remaining_secs) = memory_seconds_remaining(db_path)? {
        return Ok(Some(SessionInfo {
            remaining_secs,
            store: SessionStore::Memory,
        }));
    }
    Ok(None)
}

fn save_keyring(db_path: &Path, key: &MasterKey) -> bool {
    let Ok(entry) = entry(db_path) else {
        return false;
    };
    let Ok(json) = serde_json::to_string(&build_payload(key)) else {
        return false;
    };
    if entry.set_password(&json).is_err() {
        return false;
    }
    // Confirm the credential is readable; some backends accept writes that
    // cannot be loaded later (typical on WSL without a running keyring).
    match entry.get_password() {
        Ok(raw) if raw == json => true,
        _ => {
            let _ = entry.delete_credential();
            false
        }
    }
}

fn load_keyring(db_path: &Path) -> Result<Option<MasterKey>, CoreError> {
    let entry = match entry(db_path) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };

    let raw = match entry.get_password() {
        Ok(s) => s,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(_) => return Ok(None),
    };

    let payload: SessionPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            // Legacy plain-hex sessions or corrupt data → clear.
            let _ = clear_keyring(db_path);
            return Ok(None);
        }
    };

    if payload_seconds_remaining(&payload).is_none() {
        let _ = clear_keyring(db_path);
        return Ok(None);
    }

    let Some(key) = decode_key(&payload.key_hex) else {
        let _ = clear_keyring(db_path);
        return Ok(None);
    };

    // Sliding TTL: extend on every successful use.
    let _ = entry
        .set_password(&serde_json::to_string(&build_payload(&key)).unwrap_or_else(|_| raw.clone()));

    Ok(Some(key))
}

fn clear_keyring(db_path: &Path) -> Result<(), CoreError> {
    let entry = match entry(db_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Ok(()),
    }
}

fn keyring_seconds_remaining(db_path: &Path) -> Result<Option<u64>, CoreError> {
    let entry = match entry(db_path) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let raw = match entry.get_password() {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let payload: SessionPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    Ok(payload_seconds_remaining(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VLTR_SESSION_FILE` is process-global: the tests that read or write it
    /// must not run concurrently with each other.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn expired_payload_has_no_remaining_time() {
        let payload = SessionPayload {
            key_hex: "00".repeat(32),
            expires_at: now_unix().saturating_sub(1),
        };
        assert!(payload_seconds_remaining(&payload).is_none());
    }

    #[test]
    fn fresh_payload_has_remaining_time() {
        let payload = SessionPayload {
            key_hex: "00".repeat(32),
            expires_at: now_unix().saturating_add(60),
        };
        let remaining = payload_seconds_remaining(&payload).unwrap();
        assert!(remaining > 0 && remaining <= 60);
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        assert!(decode_key("00").is_none());
        assert!(decode_key(&"00".repeat(32)).is_some());
    }

    #[test]
    fn memory_file_roundtrip_and_expiry() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let path = dir.path().join("session.json");
        std::env::set_var("VLTR_SESSION_FILE", &path);

        // The override wins over the per-database file name.
        assert_eq!(session_file_path(&db).unwrap(), path);

        let key = decode_key(&"ab".repeat(32)).unwrap();
        save_memory_file(&db, &key).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
        }

        let loaded = load_memory_file(&db).unwrap().expect("roundtrip works");
        assert_eq!(loaded.as_ref(), key.as_ref());

        // Expired payload → load returns None and deletes the file.
        let expired = SessionPayload {
            key_hex: "ab".repeat(32),
            expires_at: now_unix().saturating_sub(1),
        };
        std::fs::write(&path, serde_json::to_string(&expired).unwrap()).unwrap();
        assert!(load_memory_file(&db).unwrap().is_none());
        assert!(!path.exists(), "expired session file must be deleted");

        // stop removes any leftover file.
        save_memory_file(&db, &key).unwrap();
        stop_memory_file(&db).unwrap();
        assert!(!path.exists());

        std::env::remove_var("VLTR_SESSION_FILE");
    }

    #[test]
    fn blank_session_file_override_is_treated_as_unset() {
        let _guard = env_lock();
        let db = Path::new("/srv/one/vault.db");
        std::env::remove_var("VLTR_SESSION_FILE");
        let fallback = session_file_path(db).unwrap();

        // `export VLTR_SESSION_FILE=` must not redirect the session file to
        // the current directory.
        std::env::set_var("VLTR_SESSION_FILE", "");
        assert_eq!(
            session_file_path(db).unwrap(),
            fallback,
            "empty must fall back"
        );

        std::env::set_var("VLTR_SESSION_FILE", "   ");
        assert_eq!(
            session_file_path(db).unwrap(),
            fallback,
            "whitespace must fall back"
        );

        std::env::remove_var("VLTR_SESSION_FILE");
    }

    #[test]
    fn session_account_is_stable_and_sixteen_hex_chars() {
        let account = session_account(Path::new("/home/dev/vaultr/vault.db"));
        assert_eq!(
            account,
            session_account(Path::new("/home/dev/vaultr/vault.db")),
            "the same database must always map to the same account"
        );
        assert_eq!(account.len(), 16);
        assert!(
            account.chars().all(|c| c.is_ascii_hexdigit()),
            "account must be hex, got {account:?}"
        );
    }

    #[test]
    fn session_account_separates_same_named_vaults_in_different_dirs() {
        // The case the global account broke: one vault per path, any filename.
        let a = session_account(Path::new("/srv/one/vault.db"));
        let b = session_account(Path::new("/srv/two/vault.db"));
        assert_ne!(
            a, b,
            "vaults in different directories must not share a session"
        );
    }

    #[test]
    fn session_file_is_per_database() {
        let _guard = env_lock();
        std::env::remove_var("VLTR_SESSION_FILE");
        let one = session_file_path(Path::new("/srv/one/vault.db")).unwrap();
        let two = session_file_path(Path::new("/srv/two/vault.db")).unwrap();
        assert_ne!(
            one, two,
            "two vaults must not share the fallback session file"
        );
        let name = one.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            name,
            format!(
                "session-{}.json",
                session_account(Path::new("/srv/one/vault.db"))
            ),
            "the file name must carry the per-database account"
        );
    }

    #[test]
    fn no_database_means_no_persisted_session() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        std::env::set_var("VLTR_SESSION_FILE", &path);

        let key = decode_key(&"cd".repeat(32)).unwrap();
        // In-memory storage has no path to key a session on: nothing is
        // written to the keyring, and nothing to disk either.
        save_master_key(None, &key).unwrap();
        assert!(!path.exists(), "in-memory save must not touch the disk");
        assert!(load_master_key(None).unwrap().is_none());
        assert!(inspect(None).unwrap().is_none());
        clear_session(None).unwrap();

        std::env::remove_var("VLTR_SESSION_FILE");
    }

    #[test]
    fn session_file_override_owns_the_session_and_skips_the_keyring() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let path = dir.path().join("session.json");
        std::env::set_var("VLTR_SESSION_FILE", &path);

        // Control: the probe must observe a keyring request, otherwise the
        // assertion at the end of this test would pass vacuously.
        // `Entry::new` only builds the entry, it never reaches the backend —
        // counting it is enough to prove the keyring *path* was not taken.
        let before = keyring_calls();
        let _ = entry(&db);
        assert_eq!(
            keyring_calls(),
            before + 1,
            "probe must observe a keyring request"
        );

        let key = decode_key(&"1f".repeat(32)).unwrap();
        save_master_key(Some(&db), &key).unwrap();
        assert!(path.exists(), "override must be the file that gets written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
        }

        let loaded = load_master_key(Some(&db))
            .unwrap()
            .expect("override file must be read back");
        assert_eq!(loaded.as_ref(), key.as_ref());

        clear_session(Some(&db)).unwrap();
        assert!(!path.exists(), "clear must remove the override file");
        assert!(load_master_key(Some(&db)).unwrap().is_none());

        // The load-bearing assertion: none of the above asked for the keyring.
        assert_eq!(
            keyring_calls(),
            before + 1,
            "the override must bypass the keyring entirely"
        );

        std::env::remove_var("VLTR_SESSION_FILE");
    }

    #[test]
    fn session_file_override_keeps_inspect_off_the_keyring() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let path = dir.path().join("session.json");
        std::env::set_var("VLTR_SESSION_FILE", &path);

        let key = decode_key(&"2e".repeat(32)).unwrap();
        save_master_key(Some(&db), &key).unwrap();

        // `vltr status` goes through `inspect`; reporting a keyring store that
        // the load path would never consult is the same bug in read form.
        let before = keyring_calls();
        let info = inspect(Some(&db)).unwrap().expect("session is active");
        assert_eq!(info.store, SessionStore::Memory);
        assert!(info.remaining_secs > 0);
        assert_eq!(
            keyring_calls(),
            before,
            "inspect must not consult the keyring under the override"
        );

        clear_session(Some(&db)).unwrap();
        std::env::remove_var("VLTR_SESSION_FILE");
    }

    #[test]
    fn unset_or_blank_session_file_override_still_prefers_the_keyring() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");

        // `save_master_key` is deliberately NOT called here: without the
        // override it would write the *real* keyring entry for this vault,
        // which is exactly what the override exists to prevent.
        for value in [None, Some(""), Some("   ")] {
            match value {
                Some(v) => std::env::set_var("VLTR_SESSION_FILE", v),
                None => std::env::remove_var("VLTR_SESSION_FILE"),
            }
            assert!(
                session_file_override().is_none(),
                "blank/unset must not be an override: {value:?}"
            );

            let before = keyring_calls();
            assert!(load_master_key(Some(&db)).unwrap().is_none());
            assert_eq!(
                keyring_calls(),
                before + 1,
                "load consults the keyring first: {value:?}"
            );

            let before = keyring_calls();
            assert!(
                inspect(Some(&db)).unwrap().is_none(),
                "no session was stored for {value:?}"
            );
            assert_eq!(
                keyring_calls(),
                before + 1,
                "inspect consults the keyring first: {value:?}"
            );

            let before = keyring_calls();
            clear_session(Some(&db)).unwrap();
            assert_eq!(
                keyring_calls(),
                before + 1,
                "clear consults the keyring first: {value:?}"
            );
        }

        std::env::remove_var("VLTR_SESSION_FILE");
    }
}
