//! Session store for the master key: OS keyring first, 0600 local session file fallback.
//! Sliding 30-minute TTL in both backends.

use crate::CoreError;
use crypto::MasterKey;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
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

fn entry() -> Result<Entry, CoreError> {
    Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| CoreError::Other(format!("keyring: {e}")))
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

/// Path of the fallback session file. Overridable via `VLTR_SESSION_FILE`
/// (tests and debugging).
fn session_file_path() -> Result<std::path::PathBuf, CoreError> {
    if let Some(path) = std::env::var_os("VLTR_SESSION_FILE") {
        return Ok(std::path::PathBuf::from(path));
    }
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| CoreError::Other("cannot determine Vaultr data directory".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("session.json"))
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

fn save_memory_file(key: &MasterKey) -> Result<(), CoreError> {
    let path = session_file_path()?;
    let json = serde_json::to_string(&build_payload(key))
        .map_err(|e| CoreError::Other(format!("serialize session: {e}")))?;
    write_0600(&path, &json)
}

/// Read the session file. Expired or corrupt → delete it and return None.
/// Valid → refresh the sliding TTL before returning the key.
fn load_memory_file() -> Result<Option<MasterKey>, CoreError> {
    let path = session_file_path()?;
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
    let _ = save_memory_file(&key);
    Ok(Some(key))
}

fn memory_seconds_remaining() -> Result<Option<u64>, CoreError> {
    let path = session_file_path()?;
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

fn stop_memory_file() -> Result<(), CoreError> {
    let _ = std::fs::remove_file(session_file_path()?);
    Ok(())
}

/// Persist the master key with a fresh 30-minute TTL.
/// Prefers the OS keyring; falls back to a 0600 session file next to the vault data.
pub fn save_master_key(key: &MasterKey) -> Result<SessionStore, CoreError> {
    if save_keyring(key) {
        let _ = stop_memory_file();
        return Ok(SessionStore::Keyring);
    }
    save_memory_file(key)?;
    Ok(SessionStore::Memory)
}

/// Load the master key if a session exists and is not expired.
/// On success, **refreshes** the TTL (sliding expiration).
pub fn load_master_key() -> Result<Option<MasterKey>, CoreError> {
    if let Some(key) = load_keyring()? {
        return Ok(Some(key));
    }
    load_memory_file()
}

pub fn clear_session() -> Result<(), CoreError> {
    let _ = clear_keyring();
    let _ = stop_memory_file();
    Ok(())
}

/// Inspect the current session without refreshing its TTL.
pub fn inspect() -> Result<Option<SessionInfo>, CoreError> {
    if let Some(remaining_secs) = keyring_seconds_remaining()? {
        return Ok(Some(SessionInfo {
            remaining_secs,
            store: SessionStore::Keyring,
        }));
    }
    if let Some(remaining_secs) = memory_seconds_remaining()? {
        return Ok(Some(SessionInfo {
            remaining_secs,
            store: SessionStore::Memory,
        }));
    }
    Ok(None)
}

fn save_keyring(key: &MasterKey) -> bool {
    let Ok(entry) = entry() else {
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

fn load_keyring() -> Result<Option<MasterKey>, CoreError> {
    let entry = match entry() {
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
            let _ = clear_keyring();
            return Ok(None);
        }
    };

    if payload_seconds_remaining(&payload).is_none() {
        let _ = clear_keyring();
        return Ok(None);
    }

    let Some(key) = decode_key(&payload.key_hex) else {
        let _ = clear_keyring();
        return Ok(None);
    };

    // Sliding TTL: extend on every successful use.
    let _ = entry
        .set_password(&serde_json::to_string(&build_payload(&key)).unwrap_or_else(|_| raw.clone()));

    Ok(Some(key))
}

fn clear_keyring() -> Result<(), CoreError> {
    let entry = match entry() {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Ok(()),
    }
}

fn keyring_seconds_remaining() -> Result<Option<u64>, CoreError> {
    let entry = match entry() {
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        std::env::set_var("VLTR_SESSION_FILE", &path);

        let key = decode_key(&"ab".repeat(32)).unwrap();
        save_memory_file(&key).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
        }

        let loaded = load_memory_file().unwrap().expect("roundtrip works");
        assert_eq!(loaded.as_ref(), key.as_ref());

        // Expired payload → load returns None and deletes the file.
        let expired = SessionPayload {
            key_hex: "ab".repeat(32),
            expires_at: now_unix().saturating_sub(1),
        };
        std::fs::write(&path, serde_json::to_string(&expired).unwrap()).unwrap();
        assert!(load_memory_file().unwrap().is_none());
        assert!(!path.exists(), "expired session file must be deleted");

        // stop removes any leftover file.
        save_memory_file(&key).unwrap();
        stop_memory_file().unwrap();
        assert!(!path.exists());

        std::env::remove_var("VLTR_SESSION_FILE");
    }
}
