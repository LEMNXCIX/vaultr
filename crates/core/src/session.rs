//! OS keyring session with 30-minute sliding TTL.

use crate::CoreError;
use crypto::MasterKey;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use models::constants::{KEYRING_ACCOUNT, KEYRING_SERVICE, SESSION_TTL_SECS};

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

fn write_payload(payload: &SessionPayload) -> Result<(), CoreError> {
    let entry = match entry() {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    let json = match serde_json::to_string(payload) {
        Ok(j) => j,
        Err(_) => return Ok(()),
    };
    let _ = entry.set_password(&json);
    Ok(())
}

/// Persist master key with a fresh 30-minute TTL.
pub fn save_master_key(key: &MasterKey) -> Result<(), CoreError> {
    write_payload(&build_payload(key))
}

/// Load master key if session exists and is not expired.
/// On success, **refreshes** the TTL (sliding expiration).
pub fn load_master_key() -> Result<Option<MasterKey>, CoreError> {
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
            let _ = clear_session();
            return Ok(None);
        }
    };

    if now_unix() >= payload.expires_at {
        let _ = clear_session();
        return Ok(None);
    }

    let bytes = match hex::decode(payload.key_hex.trim()) {
        Ok(b) if b.len() == 32 /* KEY_LEN */ => b,
        _ => {
            let _ = clear_session();
            return Ok(None);
        }
    };

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let key = Zeroizing::new(arr);

    // Sliding TTL: extend on every successful use.
    let _ = write_payload(&build_payload(&key));

    Ok(Some(key))
}

pub fn clear_session() -> Result<(), CoreError> {
    let entry = match entry() {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Ok(()),
    }
}

pub fn has_session() -> Result<bool, CoreError> {
    // Do not refresh TTL when only probing.
    Ok(seconds_remaining()?.is_some())
}

/// Seconds remaining in the current session, if any (without refreshing).
/// Used for `status` display.
pub fn seconds_remaining() -> Result<Option<u64>, CoreError> {
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
    let now = now_unix();
    if now >= payload.expires_at {
        Ok(None)
    } else {
        Ok(Some(payload.expires_at - now))
    }
}
