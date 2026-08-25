//! Session store for the master key: OS keyring first, in-memory agent fallback.
//! Sliding 30-minute TTL in both backends.

use crate::CoreError;
use crypto::MasterKey;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
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
            Self::Memory => "in-memory agent",
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

#[derive(Debug, Serialize, Deserialize)]
struct AgentDescriptor {
    port: u16,
    token_hex: String,
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

fn agent_path() -> Result<std::path::PathBuf, CoreError> {
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or_else(|| CoreError::Other("cannot determine Vaultr data directory".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("session-agent.json"))
}

/// Persist the master key with a fresh 30-minute TTL.
/// Prefers the OS keyring; starts the local memory agent if the keyring is unavailable.
pub fn save_master_key(key: &MasterKey) -> Result<SessionStore, CoreError> {
    if save_keyring(key) {
        let _ = stop_memory_agent();
        return Ok(SessionStore::Keyring);
    }
    // The agent is a hidden subcommand of the `vltr` binary. Skip it from
    // unit-test harnesses so we do not spawn leftover processes.
    if !is_cli_binary() {
        return Err(CoreError::Other(
            "OS keyring unavailable and memory agent requires the vltr binary".into(),
        ));
    }
    start_memory_agent(key)?;
    Ok(SessionStore::Memory)
}

fn is_cli_binary() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| name == "vltr")
}

/// Load the master key if a session exists and is not expired.
/// On success, **refreshes** the TTL (sliding expiration).
pub fn load_master_key() -> Result<Option<MasterKey>, CoreError> {
    if let Some(key) = load_keyring()? {
        return Ok(Some(key));
    }
    load_memory_agent()
}

pub fn clear_session() -> Result<(), CoreError> {
    let _ = clear_keyring();
    let _ = stop_memory_agent();
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

fn start_memory_agent(key: &MasterKey) -> Result<(), CoreError> {
    let _ = stop_memory_agent();
    let mut token = [0u8; 32];
    crypto::fill_random(&mut token);
    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .arg("__session-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CoreError::Other("agent stdin unavailable".into()))?;
    stdin.write_all(&token)?;
    stdin.write_all(key.as_ref())?;
    drop(stdin);
    for _ in 0..20 {
        if read_agent_descriptor()?.is_some() {
            return Ok(());
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(CoreError::Other("session agent did not start".into()))
}

pub fn serve_memory_agent() -> Result<(), CoreError> {
    let mut bootstrap = Zeroizing::new([0u8; 64]);
    std::io::stdin().read_exact(&mut *bootstrap)?;
    let token = &bootstrap[..32];
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bootstrap[32..]);
    let key = Zeroizing::new(key_bytes);
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let mut descriptor = AgentDescriptor {
        port: listener.local_addr()?.port(),
        token_hex: hex::encode(token),
        expires_at: now_unix().saturating_add(SESSION_TTL_SECS),
    };
    write_agent_descriptor(&descriptor)?;
    loop {
        if now_unix() >= descriptor.expires_at {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut request = [0u8; 33];
                if stream.read_exact(&mut request).is_ok() && request[..32] == *token {
                    if request[32] == 1 {
                        let _ = stream.write_all(b"OK");
                        break;
                    }
                    let _ = stream.write_all(key.as_ref());
                    descriptor.expires_at = now_unix().saturating_add(SESSION_TTL_SECS);
                    write_agent_descriptor(&descriptor)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _ = std::fs::remove_file(agent_path()?);
    Ok(())
}

fn read_agent_descriptor() -> Result<Option<AgentDescriptor>, CoreError> {
    let path = agent_path()?;
    match std::fs::read_to_string(path) {
        Ok(raw) => Ok(serde_json::from_str(&raw).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_agent_descriptor(descriptor: &AgentDescriptor) -> Result<(), CoreError> {
    let path = agent_path()?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&serde_json::to_vec(descriptor).map_err(|e| CoreError::Other(e.to_string()))?)?;
    Ok(())
}

fn load_memory_agent() -> Result<Option<MasterKey>, CoreError> {
    let Some(descriptor) = read_agent_descriptor()? else {
        return Ok(None);
    };
    if now_unix() >= descriptor.expires_at {
        let _ = std::fs::remove_file(agent_path()?);
        return Ok(None);
    }
    let token = match hex::decode(descriptor.token_hex) {
        Ok(value) if value.len() == 32 => value,
        _ => return Ok(None),
    };
    let mut stream = match TcpStream::connect_timeout(
        &(std::net::Ipv4Addr::LOCALHOST, descriptor.port).into(),
        std::time::Duration::from_millis(200),
    ) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };
    stream.write_all(&token)?;
    stream.write_all(&[0])?;
    let mut bytes = [0u8; 32];
    if stream.read_exact(&mut bytes).is_err() {
        return Ok(None);
    }
    Ok(Some(Zeroizing::new(bytes)))
}

fn memory_seconds_remaining() -> Result<Option<u64>, CoreError> {
    if let Some(descriptor) = read_agent_descriptor()? {
        let now = now_unix();
        if now < descriptor.expires_at {
            return Ok(Some(descriptor.expires_at - now));
        }
        let _ = std::fs::remove_file(agent_path()?);
    }
    Ok(None)
}

fn stop_memory_agent() -> Result<(), CoreError> {
    if let Some(descriptor) = read_agent_descriptor()? {
        if let Ok(token) = hex::decode(descriptor.token_hex) {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", descriptor.port)) {
                let _ = stream.write_all(&token);
                let _ = stream.write_all(&[1]);
            }
        }
    }
    let _ = std::fs::remove_file(agent_path()?);
    Ok(())
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
}
