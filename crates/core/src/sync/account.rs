use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{KEYRING_ACCOUNT_SUPABASE, REFRESH_MARGIN_SECS, SUPABASE_KEY_ENV, SUPABASE_URL_ENV};
use crate::CoreError;
use sync::{Session, SyncClient};

// ---------- Supabase session persistence (OS keyring, file fallback) ----------

#[derive(Serialize, Deserialize)]
pub(super) struct StoredSession {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) expires_in: u64,
    /// `sub` del JWT (owner_id de las filas).
    pub(super) user_id: String,
    /// Unix seconds when the tokens were persisted.
    pub(super) saved_at: u64,
}

impl fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the tokens.
        f.debug_struct("StoredSession")
            .field("expires_in", &self.expires_in)
            .field("saved_at", &self.saved_at)
            .finish_non_exhaustive()
    }
}

/// Keyring entry for the account's Supabase session. Account-global on purpose
/// (see [`KEYRING_ACCOUNT_SUPABASE`]), so it takes no database.
pub(super) fn supabase_entry() -> Result<Entry, CoreError> {
    #[cfg(test)]
    keyring_probe::record();
    Entry::new(models::constants::KEYRING_SERVICE, KEYRING_ACCOUNT_SUPABASE).map_err(|e| {
        CoreError::Other(format!(
            "OS keyring unavailable ({e}); sync requires it to store the Supabase session"
        ))
    })
}

/// `VLTR_SYNC_SESSION_FILE` override, or `None` when it is unset, empty or
/// whitespace-only — same rule and same reason as
/// [`crate::session::session_file_override`]: `export VLTR_SYNC_SESSION_FILE=`
/// is an accident, not a path, and honoring it would write the account session
/// to the current directory.
///
/// Like `VLTR_SESSION_FILE` for the master key, this also *disables the
/// keyring* (see [`KEYRING_ACCOUNT_SUPABASE`]): that account entry is global and
/// shared by every vault, so a test run cannot use it without overwriting the
/// user's real login. It exists so tests — and machines with no usable keyring —
/// can run the sync paths against a file they own.
pub(super) fn sync_session_file_override() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("VLTR_SYNC_SESSION_FILE")?;
    if raw.to_str().is_some_and(|raw| raw.trim().is_empty()) {
        return None;
    }
    Some(std::path::PathBuf::from(raw))
}

/// Fallback file for the account's Supabase session. Fixed name, same reason as
/// the keyring account: one login for the account, shared by every vault.
/// Overridable via `VLTR_SYNC_SESSION_FILE`, which replaces the whole path.
pub(super) fn supabase_session_file() -> Result<std::path::PathBuf, CoreError> {
    if let Some(path) = sync_session_file_override() {
        return Ok(path);
    }
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| CoreError::Other("cannot determine Vaultr data directory".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("sync-session.json"))
}

fn save_supabase_file(stored: &StoredSession) -> Result<(), CoreError> {
    let path = supabase_session_file()?;
    let json = serde_json::to_string(stored).map_err(|e| CoreError::Other(e.to_string()))?;
    crate::session::write_0600(&path, &json)
}

fn load_supabase_file() -> Result<Option<StoredSession>, CoreError> {
    let path = supabase_session_file()?;
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CoreError::Other(format!("sync session file: {e}"))),
    };
    serde_json::from_str(&raw).map(Some).map_err(|_| {
        CoreError::Other("corrupt Supabase session file; run 'vltr login' again".into())
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persist the account's `session`.
pub(super) fn save_supabase_session(session: &Session) -> Result<(), CoreError> {
    let stored = StoredSession {
        access_token: session.access_token.clone(),
        refresh_token: session.refresh_token.clone(),
        expires_in: session.expires_in,
        user_id: session.user_id.clone(),
        saved_at: now_unix(),
    };
    // Keyring primero (con verificación de lectura); archivo 0600 como
    // fallback (mismo patrón que la master key).
    let json = serde_json::to_string(&stored).map_err(|e| CoreError::Other(e.to_string()))?;
    // Override: el keyring no se toca en absoluto (ver
    // `sync_session_file_override`).
    if sync_session_file_override().is_some() {
        return save_supabase_file(&stored);
    }
    if let Ok(entry) = supabase_entry() {
        if entry.set_password(&json).is_ok()
            && entry.get_password().map(|r| r == json).unwrap_or(false)
        {
            return Ok(());
        }
        let _ = entry.delete_credential();
    }
    save_supabase_file(&stored)
}

/// Load the account's stored Supabase session.
pub(super) fn load_stored_session() -> Result<Option<StoredSession>, CoreError> {
    if sync_session_file_override().is_some() {
        return load_supabase_file();
    }
    if let Ok(entry) = supabase_entry() {
        match entry.get_password() {
            Ok(raw) => {
                let stored: StoredSession = serde_json::from_str(&raw).map_err(|_| {
                    CoreError::Other(
                        "corrupt Supabase session in keyring; run 'vltr login' again".into(),
                    )
                })?;
                return Ok(Some(stored));
            }
            Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(CoreError::Other(format!("keyring: {e}"))),
        }
    }
    load_supabase_file()
}

/// Log the account out of sync everywhere. Not per-vault on purpose
/// ([`KEYRING_ACCOUNT_SUPABASE`]).
pub(super) fn clear_supabase_session() -> Result<(), CoreError> {
    // Override: se borra el archivo y el keyring no se toca. Sin override esto
    // no borra el archivo de fallback, igual que antes.
    if let Some(path) = sync_session_file_override() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let entry = supabase_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Ok(()), // ponytail: best-effort clear; a stuck backend must not block logout
    }
}

/// Supabase credentials: env vars first, then `<data_dir>/sync.json`
/// (`{"url":"...","key":"..."}`, modo 0600 recomendado). El archivo evita
/// depender del entorno en cron/scripts.
pub(super) fn read_sync_config() -> Option<(String, String)> {
    if let (Ok(url), Ok(key)) = (
        std::env::var(SUPABASE_URL_ENV),
        std::env::var(SUPABASE_KEY_ENV),
    ) {
        if !url.is_empty() && !key.is_empty() {
            return Some((url, key));
        }
    }
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")?;
    let path = dir.data_dir().join("sync.json");
    let raw = std::fs::read_to_string(path).ok()?;
    #[derive(serde::Deserialize)]
    struct Conf {
        url: String,
        key: String,
    }
    let conf: Conf = serde_json::from_str(&raw).ok()?;
    (!conf.url.is_empty() && !conf.key.is_empty()).then_some((conf.url, conf.key))
}

pub(super) fn sync_client() -> Result<SyncClient, CoreError> {
    let (url, key) = read_sync_config().ok_or_else(|| {
        CoreError::Other(format!(
            "sync not configured; set {SUPABASE_URL_ENV} and {SUPABASE_KEY_ENV} or create sync.json"
        ))
    })?;
    SyncClient::new(&url, &key).map_err(CoreError::from)
}

/// The account's stored session, with refresh if the access token expired.
pub(super) async fn fresh_session(client: &SyncClient) -> Result<Session, CoreError> {
    let stored = load_stored_session()?
        .ok_or_else(|| CoreError::Other("not logged in to sync; run 'vltr login' first".into()))?;
    if stored.saved_at.saturating_add(stored.expires_in) > now_unix() + REFRESH_MARGIN_SECS {
        return Ok(Session {
            access_token: stored.access_token,
            refresh_token: stored.refresh_token,
            expires_in: stored.expires_in,
            user_id: stored.user_id,
        });
    }
    let refreshed = client.refresh(&stored.refresh_token).await.map_err(|e| {
        CoreError::Other(format!(
            "session refresh failed ({e}); run 'vltr login' again"
        ))
    })?;
    save_supabase_session(&refreshed)?;
    Ok(refreshed)
}

#[cfg(test)]
pub(super) fn keyring_calls() -> usize {
    keyring_probe::calls()
}

/// Test-only count of keyring requests made by this thread. The override tests
/// need to prove the keyring was skipped *without* touching the real one, and
/// "the session round-tripped" cannot show that: a run that consulted the
/// keyring and overwrote the account session would still look like a pass.
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
