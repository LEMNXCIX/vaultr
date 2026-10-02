//! Sync orchestration: push dirty rows, pull since cursor, LWW merge,
//! tombstone cascade and bootstrap for new devices.
//!
//! Zero-knowledge: this module moves ciphertexts only — nothing here decrypts
//! or sends plaintext values.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use keyring::Entry;
use models::{Environment, Id, KdfParams, Project, Variable};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use storage::{Storage, SyncState, SyncTable};

use crate::{App, CoreError};
use crypto::{decrypt, derive_master_key, encrypt, MasterKey};
use sync::{EnvironmentRow, ProjectRow, Session, SyncClient, VariableRow};

pub const SUPABASE_URL_ENV: &str = "VAULTR_SUPABASE_URL";
pub const SUPABASE_KEY_ENV: &str = "VAULTR_SUPABASE_KEY";
/// Keyring account holding the Supabase JWT session (service = KEYRING_SERVICE).
const KEYRING_ACCOUNT_SUPABASE: &str = "supabase-session";
/// `sync_state` cursor key for incremental pull.
const CURSOR_KEY: &str = "last_pull";
/// `sync_state` marker set by `rekey`: hex of the local salt THIS device
/// rotated. A salt mismatch with this marker present authorizes pushing the
/// new local vault meta; without it the mismatch aborts the sync.
pub const PENDING_REKEY_SALT_KEY: &str = "pending_rekey_salt";
/// Refresh the access token this many seconds before it expires.
const REFRESH_MARGIN_SECS: u64 = 60;

// ---------- Report ----------

#[derive(Debug, Default)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts_won_remote: Vec<String>,
    pub deleted_pulled: usize,
    /// Pulled rows whose parent row is unknown locally; they are skipped
    /// instead of hard-failing sync with a FK violation.
    pub skipped_orphans: usize,
}

impl fmt::Display for SyncReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} subidas, {} bajadas", self.pushed, self.pulled)?;
        if !self.conflicts_won_remote.is_empty() {
            write!(
                f,
                ", {} actualizados remotamente: {}",
                self.conflicts_won_remote.len(),
                self.conflicts_won_remote.join(", ")
            )?;
        }
        if self.deleted_pulled > 0 {
            write!(f, ", {} borrados", self.deleted_pulled)?;
        }
        if self.skipped_orphans > 0 {
            write!(f, ", {} huérfanos omitidos", self.skipped_orphans)?;
        }
        Ok(())
    }
}

// ---------- Supabase session persistence (OS keyring, file fallback) ----------

#[derive(Serialize, Deserialize)]
struct StoredSession {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    /// `sub` del JWT (owner_id de las filas).
    user_id: String,
    /// Unix seconds when the tokens were persisted.
    saved_at: u64,
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

fn supabase_entry() -> Result<Entry, CoreError> {
    Entry::new(models::constants::KEYRING_SERVICE, KEYRING_ACCOUNT_SUPABASE).map_err(|e| {
        CoreError::Other(format!(
            "OS keyring unavailable ({e}); sync requires it to store the Supabase session"
        ))
    })
}

fn supabase_session_file() -> Result<std::path::PathBuf, CoreError> {
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

fn save_supabase_session(session: &Session) -> Result<(), CoreError> {
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

fn load_stored_session() -> Result<Option<StoredSession>, CoreError> {
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

fn clear_supabase_session() -> Result<(), CoreError> {
    let entry = supabase_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Ok(()), // ponytail: best-effort clear; a stuck backend must not block logout
    }
}

/// Supabase credentials: env vars first, then `<data_dir>/sync.json`
/// (`{"url":"...","key":"..."}`, modo 0600 recomendado). El archivo evita
/// depender del entorno en cron/scripts.
fn read_sync_config() -> Option<(String, String)> {
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

fn sync_client() -> Result<SyncClient, CoreError> {
    let (url, key) = read_sync_config().ok_or_else(|| {
        CoreError::Other(format!(
            "sync not configured; set {SUPABASE_URL_ENV} and {SUPABASE_KEY_ENV} or create sync.json"
        ))
    })?;
    SyncClient::new(&url, &key).map_err(CoreError::from)
}

/// Stored session with refresh if the access token expired.
async fn fresh_session(client: &SyncClient) -> Result<Session, CoreError> {
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

// ---------- base64 + mapping ----------

fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, CoreError> {
    B64.decode(s)
        .map_err(|e| CoreError::Other(format!("invalid base64 from server: {e}")))
}

fn parse_id(s: &str) -> Result<Id, CoreError> {
    s.parse::<Id>()
        .map_err(|e| CoreError::Other(format!("invalid id '{s}' from server: {e}")))
}

fn project_to_dto(p: &Project) -> ProjectRow {
    ProjectRow {
        owner_id: None,
        id: p.id.to_string(),
        name: p.name.clone(),
        description: p.description.clone(),
        color: p.color.clone(),
        icon: p.icon.clone(),
        deleted: p.deleted,
        version: p.version,
        updated_at: Some(p.updated_at),
    }
}

fn environment_to_dto(e: &Environment) -> EnvironmentRow {
    EnvironmentRow {
        owner_id: None,
        id: e.id.to_string(),
        project_id: e.project_id.to_string(),
        name: e.name.clone(),
        is_default: e.is_default,
        sort_order: e.sort_order,
        deleted: e.deleted,
        updated_at: Some(e.updated_at),
    }
}

fn variable_to_dto(v: &Variable) -> VariableRow {
    VariableRow {
        owner_id: None,
        id: v.id.to_string(),
        environment_id: v.environment_id.to_string(),
        key: v.key.clone(),
        value_encrypted: b64_encode(&v.value_encrypted),
        nonce: b64_encode(&v.nonce),
        notes: v.notes.clone(),
        is_readonly: v.is_readonly,
        allow_export: v.allow_export,
        deleted: v.deleted,
        version: v.version,
        updated_at: Some(v.updated_at),
    }
}

fn project_from_dto(r: &ProjectRow) -> Result<Project, CoreError> {
    Ok(Project {
        id: parse_id(&r.id)?,
        name: r.name.clone(),
        description: r.description.clone(),
        color: r.color.clone(),
        icon: r.icon.clone(),
        created_at: r.updated_at.unwrap_or_else(Utc::now),
        updated_at: r.updated_at.ok_or_else(|| {
            CoreError::Other("server row without updated_at cannot be merged".into())
        })?,
        owner_id: None,
        version: r.version,
        deleted: r.deleted,
    })
}

fn environment_from_dto(r: &EnvironmentRow) -> Result<Environment, CoreError> {
    let ts = r
        .updated_at
        .ok_or_else(|| CoreError::Other("server row without updated_at cannot be merged".into()))?;
    Ok(Environment {
        id: parse_id(&r.id)?,
        project_id: parse_id(&r.project_id)?,
        name: r.name.clone(),
        is_default: r.is_default,
        sort_order: r.sort_order,
        created_at: ts,
        updated_at: ts,
        deleted: r.deleted,
    })
}

fn variable_from_dto(r: &VariableRow) -> Result<Variable, CoreError> {
    let ts = r
        .updated_at
        .ok_or_else(|| CoreError::Other("server row without updated_at cannot be merged".into()))?;
    Ok(Variable {
        id: parse_id(&r.id)?,
        environment_id: parse_id(&r.environment_id)?,
        key: r.key.clone(),
        value_encrypted: b64_decode(&r.value_encrypted)?,
        nonce: b64_decode(&r.nonce)?,
        notes: r.notes.clone(),
        is_readonly: r.is_readonly,
        allow_export: r.allow_export,
        created_at: ts,
        updated_at: ts,
        version: r.version,
        deleted: r.deleted,
    })
}

/// LWW decision: apply the remote row iff strictly newer than local.
/// Missing local row → apply. Missing timestamps → keep local (conservative).
fn remote_wins(remote_ts: Option<DateTime<Utc>>, local_ts: Option<DateTime<Utc>>) -> bool {
    match (remote_ts, local_ts) {
        (Some(remote), Some(local)) => remote > local,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// New pull cursor: max of previous cursor and every timestamp seen this run.
fn next_cursor(
    prev: Option<DateTime<Utc>>,
    seen: &[Option<DateTime<Utc>>],
) -> Option<DateTime<Utc>> {
    seen.iter()
        .flatten()
        .copied()
        .fold(prev, |acc, ts| match acc {
            Some(cur) if cur >= ts => Some(cur),
            _ => Some(ts),
        })
}

// ---------- Salt guard (pure) ----------

/// What `sync` must do with the remote vault meta before touching any row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaltAction {
    /// Server has no vault: push the local meta (first sync from this device).
    PushLocal,
    /// Local and remote salts match: proceed with the normal sync.
    Proceed,
    /// This device rekeyed (marker matches the local salt): push the new
    /// local meta first — rows pushed afterwards are encrypted under it.
    PushRekey,
    /// Remote key changed elsewhere: abort WITHOUT pushing or pulling.
    RemoteKeyChanged,
}

/// Decide how to reconcile local and remote vault salts.
///
/// The salt is not secret; it only identifies the key domain. Mixing rows
/// from two domains leaves ciphertexts nobody can decrypt, so any mismatch
/// without a matching local rekey marker must stop the sync.
fn salt_action(
    local_salt: &[u8],
    remote_salt_b64: Option<&str>,
    pending_marker: Option<&str>,
) -> SaltAction {
    let Some(remote) = remote_salt_b64 else {
        return SaltAction::PushLocal;
    };
    if remote == b64_encode(local_salt) {
        return SaltAction::Proceed;
    }
    if pending_marker.is_some_and(|m| m == hex::encode(local_salt)) {
        return SaltAction::PushRekey;
    }
    SaltAction::RemoteKeyChanged
}

// ---------- Merge (pure-ish: Storage in, rows applied) ----------

/// Result of merging one pulled row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeOutcome {
    /// Remote lost LWW (or had no timestamp); local row untouched.
    LocalKept,
    /// Remote applied; `true` when it was a tombstone.
    Applied(bool),
    /// Parent row unknown locally; skipped to avoid an FK violation.
    SkippedOrphan,
}

impl MergeOutcome {
    fn pulled_and_deleted(self) -> Option<bool> {
        match self {
            MergeOutcome::Applied(deleted) => Some(deleted),
            _ => None,
        }
    }
}

fn merge_project(storage: &Storage, row: &ProjectRow) -> Result<MergeOutcome, CoreError> {
    let id = parse_id(&row.id)?;
    let local_ts = storage.find_project_by_id(id)?.map(|p| p.updated_at);
    if !remote_wins(row.updated_at, local_ts) {
        return Ok(MergeOutcome::LocalKept);
    }
    storage.upsert_pulled_project(&project_from_dto(row)?)?;
    Ok(MergeOutcome::Applied(row.deleted))
}

fn merge_environment(storage: &Storage, row: &EnvironmentRow) -> Result<MergeOutcome, CoreError> {
    let id = parse_id(&row.id)?;
    let project_id = parse_id(&row.project_id)?;
    // Orphan guard: applying a child whose parent is unknown locally would
    // violate the FK; skip instead of failing the whole sync.
    if !storage.find_project_by_id(project_id)?.is_some() {
        return Ok(MergeOutcome::SkippedOrphan);
    }
    let local_ts = storage.find_environment_by_id(id)?.map(|e| e.updated_at);
    if !remote_wins(row.updated_at, local_ts) {
        return Ok(MergeOutcome::LocalKept);
    }
    storage.upsert_pulled_environment(&environment_from_dto(row)?)?;
    Ok(MergeOutcome::Applied(row.deleted))
}

fn merge_variable(storage: &Storage, row: &VariableRow) -> Result<MergeOutcome, CoreError> {
    let id = parse_id(&row.id)?;
    let environment_id = parse_id(&row.environment_id)?;
    if !storage.find_environment_by_id(environment_id)?.is_some() {
        return Ok(MergeOutcome::SkippedOrphan);
    }
    let local_ts = storage.find_variable_by_id(id)?.map(|v| v.updated_at);
    if !remote_wins(row.updated_at, local_ts) {
        return Ok(MergeOutcome::LocalKept);
    }
    storage.upsert_pulled_variable(&variable_from_dto(row)?)?;
    Ok(MergeOutcome::Applied(row.deleted))
}

// ---------- App methods ----------

/// Verify a derived key against a sample of remote variable ciphertexts.
/// Prefers a live row, falling back to any row (tombstones still carry a
/// ciphertext). An empty sample — remote exists but has no variables yet —
/// is accepted: there is nothing to check against. Pure; unit-testable.
fn verify_key_against_sample(key: &MasterKey, sample: &[VariableRow]) -> Result<(), CoreError> {
    let Some(first) = sample
        .iter()
        .find(|r| !r.deleted)
        .or_else(|| sample.first())
    else {
        return Ok(());
    };
    let ct = b64_decode(&first.value_encrypted)?;
    let nonce = b64_decode(&first.nonce)?;
    if decrypt(key, &ct, &nonce).is_err() {
        return Err(CoreError::InvalidPassword(
            "la contraseña no descifra el vault remoto; revísala e inténtalo de nuevo".into(),
        ));
    }
    Ok(())
}

/// Pull one page of remote variables and verify `key` against a sample.
async fn verify_password_against_remote(
    client: &SyncClient,
    session: &Session,
    key: &MasterKey,
) -> Result<(), CoreError> {
    let sample = client
        .pull_page::<VariableRow>(session, "variables")
        .await?;
    verify_key_against_sample(key, &sample)
}

impl App {
    /// True when the Supabase env vars are present (sync is configurable).
    pub fn sync_available_config() -> bool {
        read_sync_config().is_some()
    }

    /// True when a vault exists on the server (requires a stored session).
    pub async fn remote_has_vault() -> Result<bool, CoreError> {
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        Ok(client.get_vault(&session).await?.is_some())
    }

    /// Log in to Supabase and persist the JWT session in the OS keyring.
    pub async fn sync_login(&self, email: &str, password: &str) -> Result<(), CoreError> {
        let client = sync_client()?;
        let session = client
            .login(email, password)
            .await
            .map_err(|e| CoreError::Other(format!("supabase login failed: {e}")))?;
        save_supabase_session(&session)
    }

    /// Create a Supabase account. Returns `true` when the response carried a
    /// session (email confirmation disabled — it is persisted like a login),
    /// `false` when the account awaits email confirmation.
    pub async fn sync_signup(&self, email: &str, password: &str) -> Result<bool, CoreError> {
        let client = sync_client()?;
        let session = client
            .signup(email, password)
            .await
            .map_err(|e| CoreError::Other(format!("supabase signup failed: {e}")))?;
        match session {
            Some(session) => {
                save_supabase_session(&session)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Remove the stored Supabase session.
    pub fn sync_logout(&self) -> Result<(), CoreError> {
        clear_supabase_session()
    }

    /// True when sync env vars are set and a Supabase session exists.
    pub fn sync_enabled(&self) -> bool {
        std::env::var(SUPABASE_URL_ENV).is_ok_and(|v| !v.is_empty())
            && std::env::var(SUPABASE_KEY_ENV).is_ok_and(|v| !v.is_empty())
            && matches!(load_stored_session(), Ok(Some(_)))
    }

    /// True when a Supabase session is stored (keyring or fallback file),
    /// regardless of how sync is configured. Unlike [`App::sync_enabled`],
    /// this checks the session alone — env vars / sync.json are irrelevant.
    pub fn sync_session_exists() -> bool {
        matches!(load_stored_session(), Ok(Some(_)))
    }

    /// New device: take the vault metadata from the server, initialize the
    /// local vault with it and unlock. Fails if a local vault already exists.
    /// The master-key session is intentionally NOT persisted.
    pub async fn bootstrap_from_remote(&mut self, password: SecretString) -> Result<(), CoreError> {
        if self.storage.is_initialized()? {
            return Err(CoreError::Other(
                "local vault already initialized; bootstrap only works on empty devices".into(),
            ));
        }
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let vault = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;

        let salt = b64_decode(&vault.salt)?;
        let kdf_params: KdfParams = serde_json::from_value(vault.kdf_params)
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;

        // No verifier travels over the wire; derive locally and verify
        // against a real remote ciphertext before touching the local vault.
        let key = derive_master_key(&password, &salt, &kdf_params)?;
        verify_password_against_remote(&client, &session, &key).await?;

        let (verifier_ct, verifier_nonce) =
            encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage
            .init_vault(&salt, &kdf_params, &verifier_ct, &verifier_nonce)?;
        self.master_key = Some(key);
        Ok(())
    }

    /// Adopt the remote vault's key after a `RemoteKeyChanged` abort.
    ///
    /// `password` must be the one currently protecting the REMOTE vault: its
    /// salt + kdf params derive the new key, verified against a remote sample
    /// ciphertext before anything local is touched. Every local variable is
    /// then re-encrypted under that key (the old in-memory key decrypts the
    /// local rows — the independent-init case included) and `vault_meta` is
    /// replaced by the remote one, so the next sync finds matching salts.
    /// The pull cursor is deliberately untouched: rows merge normally on the
    /// re-run. No rekey marker is needed — local now equals remote.
    /// The vault must be unlocked.
    pub async fn adopt_remote_key(&mut self, password: SecretString) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let vault = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;

        let remote_salt = b64_decode(&vault.salt)?;
        let kdf_params: KdfParams = serde_json::from_value(vault.kdf_params)
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;

        let new_key = derive_master_key(&password, &remote_salt, &kdf_params)?;
        verify_password_against_remote(&client, &session, &new_key).await?;

        let old_key = self.require_key()?;
        let variables = self.storage.all_variables()?;
        let mut reencrypted = Vec::with_capacity(variables.len());
        for var in &variables {
            let plaintext = decrypt(old_key, &var.value_encrypted, &var.nonce)?;
            let (ciphertext, nonce) = encrypt(&new_key, plaintext.as_str())?;
            reencrypted.push((var.id, ciphertext, nonce));
        }

        let (verifier_ct, verifier_nonce) =
            encrypt(&new_key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.apply_key_rotation(
            &reencrypted,
            &remote_salt,
            &kdf_params,
            &verifier_ct,
            &verifier_nonce,
        )?;

        self.last_session_error = crate::session::save_master_key(&new_key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(new_key);
        Ok(())
    }

    /// Two-way sync: salt guard → cascade → push dirty → pull since cursor →
    /// LWW merge → cascade → persist cursor. Moves ciphertext only.
    pub async fn sync(&self) -> Result<SyncReport, CoreError> {
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let mut report = SyncReport::default();

        // ---- Salt guard: decide BEFORE anything is pushed or pulled. ----
        // A salt mismatch means two key domains (another device rekeyed, or
        // this vault was initialized independently); merging rows across them
        // would corrupt decryption on every device.
        let remote_vault = client.get_vault(&session).await?;
        let mut vault_push: Option<(String, String)> = None;
        let mut clear_rekey_marker = false;
        if self.storage.is_initialized()? {
            let meta = self.storage.get_vault_meta()?;
            let pending = SyncState::get(self.storage.conn(), PENDING_REKEY_SALT_KEY)?;
            let action = salt_action(
                &meta.salt,
                remote_vault.as_ref().map(|v| v.salt.as_str()),
                pending.as_deref(),
            );
            match action {
                SaltAction::Proceed => {}
                SaltAction::PushLocal | SaltAction::PushRekey => {
                    vault_push = Some((
                        b64_encode(&meta.salt),
                        serde_json::to_string(&meta.kdf_params)?,
                    ));
                    clear_rekey_marker = action == SaltAction::PushRekey;
                }
                SaltAction::RemoteKeyChanged => return Err(CoreError::RemoteKeyChanged),
            }
        }

        // Local-only delete chains (project deleted but children live) would
        // otherwise leave live children under dead parents on the server.
        self.storage.cascade_tombstones(Utc::now())?;

        // ---- Push: vault meta first (rows below are encrypted under the key
        // it describes), then dirty rows. ----
        if let Some((salt_b64, kdf_json)) = vault_push {
            client.push_vault(&session, &salt_b64, &kdf_json).await?;
            report.pushed += 1;
            if clear_rekey_marker {
                // Clear only after the push landed: on network failure the
                // marker must survive so the next sync can retry. A stale
                // marker (salts equal) is inert — the guard only reads it on
                // a mismatch, and the next rekey overwrites it.
                SyncState::remove(self.storage.conn(), PENDING_REKEY_SALT_KEY)?;
            }
        }

        let projects = self.storage.dirty_projects()?;
        let environments = self.storage.dirty_environments()?;
        let variables = self.storage.dirty_variables()?;

        let mut project_dtos: Vec<ProjectRow> = projects.iter().map(project_to_dto).collect();
        let mut environment_dtos: Vec<EnvironmentRow> =
            environments.iter().map(environment_to_dto).collect();
        let mut variable_dtos: Vec<VariableRow> = variables.iter().map(variable_to_dto).collect();

        // El DEFAULT auth.uid() de columna no es fiable: estampar owner_id.
        let uid = Some(session.user_id.clone());
        for r in &mut project_dtos {
            r.owner_id = uid.clone();
        }
        for r in &mut environment_dtos {
            r.owner_id = uid.clone();
        }
        for r in &mut variable_dtos {
            r.owner_id = uid.clone();
        }

        // Order matters: parents before children so FKs hold server-side.
        client
            .push_rows(&session, "projects", &project_dtos)
            .await?;
        client
            .push_rows(&session, "environments", &environment_dtos)
            .await?;
        client
            .push_rows(&session, "variables", &variable_dtos)
            .await?;

        let now = Utc::now();
        self.storage.mark_synced(
            SyncTable::Projects,
            &projects.iter().map(|p| p.id).collect::<Vec<_>>(),
            now,
        )?;
        self.storage.mark_synced(
            SyncTable::Environments,
            &environments.iter().map(|e| e.id).collect::<Vec<_>>(),
            now,
        )?;
        self.storage.mark_synced(
            SyncTable::Variables,
            &variables.iter().map(|v| v.id).collect::<Vec<_>>(),
            now,
        )?;
        report.pushed += projects.len() + environments.len() + variables.len();

        // ---- Pull since cursor. ----
        let prev_cursor = SyncState::get(self.storage.conn(), CURSOR_KEY)?
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&Utc));
        let since = prev_cursor.map(|c| c.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true));

        let mut seen: Vec<Option<DateTime<Utc>>> = Vec::new();

        let pulled_projects: Vec<ProjectRow> = client
            .pull_rows(&session, "projects", since.as_deref())
            .await?;
        for row in &pulled_projects {
            seen.push(row.updated_at);
            if let Some(deleted) = merge_project(&self.storage, row)?.pulled_and_deleted() {
                report.pulled += 1;
                if deleted {
                    report.deleted_pulled += 1;
                }
                report.conflicts_won_remote.push(row.id.clone());
            }
        }

        let pulled_environments: Vec<EnvironmentRow> = client
            .pull_rows(&session, "environments", since.as_deref())
            .await?;
        for row in &pulled_environments {
            seen.push(row.updated_at);
            // Skipped orphans do not advance the cursor: the row is retried
            // (and applies) once its parent arrives.
            match merge_environment(&self.storage, row)? {
                MergeOutcome::SkippedOrphan => {
                    report.skipped_orphans += 1;
                    seen.pop();
                }
                outcome => {
                    if let Some(deleted) = outcome.pulled_and_deleted() {
                        report.pulled += 1;
                        if deleted {
                            report.deleted_pulled += 1;
                        }
                        report.conflicts_won_remote.push(row.id.clone());
                    }
                }
            }
        }

        let pulled_variables: Vec<VariableRow> = client
            .pull_rows(&session, "variables", since.as_deref())
            .await?;
        for row in &pulled_variables {
            seen.push(row.updated_at);
            match merge_variable(&self.storage, row)? {
                MergeOutcome::SkippedOrphan => {
                    report.skipped_orphans += 1;
                    seen.pop();
                }
                outcome => {
                    if let Some(deleted) = outcome.pulled_and_deleted() {
                        report.pulled += 1;
                        if deleted {
                            report.deleted_pulled += 1;
                        }
                        report.conflicts_won_remote.push(row.id.clone());
                    }
                }
            }
        }

        // Pulled tombstones must not leave live children locally either; the
        // cascaded children become dirty and heal the server on next push.
        self.storage.cascade_tombstones(Utc::now())?;

        // ---- Cursor. ----
        if let Some(cursor) = next_cursor(prev_cursor, &seen) {
            SyncState::set(self.storage.conn(), CURSOR_KEY, &cursor.to_rfc3339())?;
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use storage::Storage;

    fn ts(mins: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
            + chrono::Duration::minutes(i64::from(mins))
    }

    fn sample_project(id: Id, updated: DateTime<Utc>, deleted: bool) -> Project {
        Project {
            id,
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            created_at: updated,
            updated_at: updated,
            owner_id: None,
            version: 1,
            deleted,
        }
    }

    fn sample_env(id: Id, project_id: Id, updated: DateTime<Utc>) -> Environment {
        Environment {
            id,
            project_id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: updated,
            updated_at: updated,
            deleted: false,
        }
    }

    fn sample_var(id: Id, env_id: Id, updated: DateTime<Utc>) -> Variable {
        Variable {
            id,
            environment_id: env_id,
            key: "K".into(),
            value_encrypted: vec![1, 2, 3],
            nonce: vec![0; 24],
            notes: None,
            is_readonly: false,
            allow_export: true,
            created_at: updated,
            updated_at: updated,
            version: 1,
            deleted: false,
        }
    }

    #[test]
    fn lww_remote_newer_wins_both_directions() {
        let storage = Storage::open_in_memory().unwrap();
        let id = uuid::Uuid::now_v7();

        // Local older → remote wins, full overwrite including name/version.
        storage
            .create_project(&sample_project(id, ts(10), false))
            .unwrap();
        let newer = ProjectRow {
            owner_id: None,
            id: id.to_string(),
            name: "Renamed".into(),
            description: Some("from remote".into()),
            color: None,
            icon: None,
            deleted: false,
            version: 4,
            updated_at: Some(ts(20)),
        };
        assert_eq!(
            merge_project(&storage, &newer).unwrap(),
            MergeOutcome::Applied(false)
        );
        let merged = storage.find_project_by_id(id).unwrap().unwrap();
        assert_eq!(merged.name, "Renamed");
        assert_eq!(merged.version, 4);

        // Local newer → remote loses, local untouched.
        let older = ProjectRow {
            owner_id: None,
            id: id.to_string(),
            name: "Stale".into(),
            description: None,
            color: None,
            icon: None,
            deleted: true,
            version: 2,
            updated_at: Some(ts(15)),
        };
        assert_eq!(
            merge_project(&storage, &older).unwrap(),
            MergeOutcome::LocalKept
        );
        assert_eq!(
            storage.find_project_by_id(id).unwrap().unwrap().name,
            "Renamed"
        );
    }

    #[test]
    fn lww_missing_local_row_is_inserted_missing_remote_ts_loses() {
        let storage = Storage::open_in_memory().unwrap();
        let id = uuid::Uuid::now_v7();

        // Missing locally → insert.
        let row = ProjectRow {
            owner_id: None,
            id: id.to_string(),
            name: "New".into(),
            description: None,
            color: None,
            icon: None,
            deleted: false,
            version: 1,
            updated_at: Some(ts(5)),
        };
        assert_eq!(
            merge_project(&storage, &row).unwrap(),
            MergeOutcome::Applied(false)
        );

        // Remote without updated_at → conservative keep-local.
        let no_ts = ProjectRow {
            updated_at: None,
            ..row
        };
        assert_eq!(
            merge_project(&storage, &no_ts).unwrap(),
            MergeOutcome::LocalKept
        );
    }

    #[test]
    fn tombstone_pull_cascades_children() {
        let storage = Storage::open_in_memory().unwrap();
        let pid = uuid::Uuid::now_v7();
        let eid = uuid::Uuid::now_v7();
        let vid = uuid::Uuid::now_v7();
        storage
            .create_project(&sample_project(pid, ts(10), false))
            .unwrap();
        storage
            .create_environment(&sample_env(eid, pid, ts(10)))
            .unwrap();
        storage
            .create_variable(&sample_var(vid, eid, ts(10)))
            .unwrap();

        // Pull: parent tombstoned remotely, strictly newer than local.
        let tombstone = ProjectRow {
            owner_id: None,
            id: pid.to_string(),
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            deleted: true,
            version: 2,
            updated_at: Some(ts(30)),
        };
        assert_eq!(
            merge_project(&storage, &tombstone).unwrap(),
            MergeOutcome::Applied(true)
        );

        // Cascade pass (runs inside sync right after merge).
        let cascaded = storage.cascade_tombstones(ts(31)).unwrap();
        assert_eq!(cascaded, 2, "env + var must be soft-deleted");

        assert!(
            storage
                .find_environment_by_id(eid)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert!(storage.find_variable_by_id(vid).unwrap().unwrap().deleted);

        // Cascaded children are dirty → they propagate as tombstones on push.
        assert_eq!(storage.dirty_environments().unwrap().len(), 1);
        assert_eq!(storage.dirty_variables().unwrap().len(), 1);
    }

    #[test]
    fn salt_guard_covers_all_four_branches() {
        let local = [9u8; 16];
        let local_b64 = b64_encode(&local);
        let local_hex = hex::encode(local);
        let other_b64 = b64_encode(&[8u8; 16]);

        // Remote has no vault → push local meta (first sync).
        assert_eq!(salt_action(&local, None, None), SaltAction::PushLocal);
        assert_eq!(
            salt_action(&local, None, Some(&local_hex)),
            SaltAction::PushLocal
        );

        // Salts equal → normal sync regardless of a (stale) marker.
        assert_eq!(
            salt_action(&local, Some(&local_b64), None),
            SaltAction::Proceed
        );
        assert_eq!(
            salt_action(&local, Some(&local_b64), Some(&local_hex)),
            SaltAction::Proceed
        );

        // Salts differ + marker matches THIS device's salt → rekeyed here:
        // push the new meta before the rows.
        assert_eq!(
            salt_action(&local, Some(&other_b64), Some(&local_hex)),
            SaltAction::PushRekey
        );

        // Salts differ, no marker → abort, nothing pushed or pulled.
        assert_eq!(
            salt_action(&local, Some(&other_b64), None),
            SaltAction::RemoteKeyChanged
        );
        // A marker for a different salt must not authorize the push.
        assert_eq!(
            salt_action(&local, Some(&other_b64), Some("deadbeef")),
            SaltAction::RemoteKeyChanged
        );
    }

    #[test]
    fn cursor_advances_to_max_seen_never_regresses() {
        let prev = Some(ts(50));
        let seen = vec![
            Some(ts(10)),
            Some(ts(90)),
            None, // row without ts must not poison the cursor
            Some(ts(70)),
        ];
        assert_eq!(next_cursor(prev, &seen), Some(ts(90)));
        assert_eq!(next_cursor(None, &seen), Some(ts(90)));
        assert_eq!(next_cursor(prev, &[]), prev);
        assert_eq!(next_cursor(None, &[None]), None);
    }

    #[test]
    fn dto_mapping_roundtrip_preserves_fields_and_blobs() {
        let vid = uuid::Uuid::now_v7();
        let eid = uuid::Uuid::now_v7();
        let mut var = sample_var(vid, eid, ts(42));
        var.value_encrypted = vec![9, 8, 7, 6, 5];
        var.nonce = vec![1; 24];

        let dto = variable_to_dto(&var);
        assert_eq!(dto.value_encrypted, b64_encode(&[9, 8, 7, 6, 5]));
        let back = variable_from_dto(&dto).unwrap();
        assert_eq!(back.id, var.id);
        assert_eq!(back.environment_id, var.environment_id);
        assert_eq!(back.key, var.key);
        assert_eq!(back.value_encrypted, var.value_encrypted);
        assert_eq!(back.nonce, var.nonce);
        assert_eq!(back.version, var.version);
        assert_eq!(back.deleted, var.deleted);
        assert_eq!(back.updated_at, var.updated_at);
    }

    #[test]
    fn report_display_mentions_counts() {
        let report = SyncReport {
            pushed: 3,
            pulled: 5,
            conflicts_won_remote: vec!["a".into(), "b".into()],
            deleted_pulled: 1,
            skipped_orphans: 0,
        };
        assert_eq!(
            report.to_string(),
            "3 subidas, 5 bajadas, 2 actualizados remotamente: a, b, 1 borrados"
        );
        let with_orphans = SyncReport {
            skipped_orphans: 2,
            ..report
        };
        assert_eq!(
            with_orphans.to_string(),
            "3 subidas, 5 bajadas, 2 actualizados remotamente: a, b, 1 borrados, 2 huérfanos omitidos"
        );
    }

    #[test]
    fn orphaned_children_are_skipped_not_hard_failures() {
        let storage = Storage::open_in_memory().unwrap();
        let pid = uuid::Uuid::now_v7();
        storage
            .create_project(&sample_project(pid, ts(10), false))
            .unwrap();
        // No environment row locally.

        let orphan_env = EnvironmentRow {
            owner_id: None,
            id: uuid::Uuid::now_v7().to_string(),
            project_id: uuid::Uuid::now_v7().to_string(), // unknown project
            name: "staging".into(),
            is_default: false,
            sort_order: 0,
            deleted: false,
            updated_at: Some(ts(20)),
        };
        assert_eq!(
            merge_environment(&storage, &orphan_env).unwrap(),
            MergeOutcome::SkippedOrphan
        );
        assert!(storage
            .find_environment_by_id(parse_id(&orphan_env.id).unwrap())
            .unwrap()
            .is_none());

        // Known parent → applies normally.
        let child_env = EnvironmentRow {
            owner_id: None,
            id: uuid::Uuid::now_v7().to_string(),
            project_id: pid.to_string(),
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            deleted: false,
            updated_at: Some(ts(20)),
        };
        assert_eq!(
            merge_environment(&storage, &child_env).unwrap(),
            MergeOutcome::Applied(false)
        );

        // Variable whose environment is unknown → skipped.
        let orphan_var = VariableRow {
            owner_id: None,
            id: uuid::Uuid::now_v7().to_string(),
            environment_id: uuid::Uuid::now_v7().to_string(), // unknown env
            key: "K".into(),
            value_encrypted: b64_encode(&[1, 2, 3]),
            nonce: b64_encode(&[0; 24]),
            notes: None,
            is_readonly: false,
            allow_export: true,
            deleted: false,
            version: 1,
            updated_at: Some(ts(20)),
        };
        assert_eq!(
            merge_variable(&storage, &orphan_var).unwrap(),
            MergeOutcome::SkippedOrphan
        );
    }

    #[test]
    fn remote_sample_verification_accepts_right_key_and_empty_sample() {
        use crypto::{derive_master_key, encrypt};

        let password = SecretString::new("correct-horse".into());
        let salt = [7u8; 16];
        let params = KdfParams {
            m_cost: 2048,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        let good_key = derive_master_key(&password, &salt, &params).unwrap();
        let wrong_key =
            derive_master_key(&SecretString::new("wrong".into()), &salt, &params).unwrap();

        // A remote variable encrypted by the vault owner.
        let (ct, nonce) = encrypt(&good_key, "secret-value").unwrap();
        let row = VariableRow {
            owner_id: None,
            id: "018f0000-0000-7000-8000-000000000001".into(),
            environment_id: "018f0000-0000-7000-8000-000000000002".into(),
            key: "K".into(),
            value_encrypted: b64_encode(&ct),
            nonce: b64_encode(&nonce),
            notes: None,
            is_readonly: false,
            allow_export: true,
            deleted: false,
            version: 1,
            updated_at: None,
        };

        // Right password decrypts the remote sample.
        assert!(verify_key_against_sample(&good_key, std::slice::from_ref(&row)).is_ok());

        // Wrong password derives a different key → typed invalid-password error.
        assert!(matches!(
            verify_key_against_sample(&wrong_key, std::slice::from_ref(&row)),
            Err(CoreError::InvalidPassword(_))
        ));

        // Zero variables remotely → nothing to verify (accepted path).
        assert!(verify_key_against_sample(&good_key, &[]).is_ok());

        // Only tombstones → they still carry ciphertext; verification proceeds.
        let mut tombstone = row;
        tombstone.deleted = true;
        assert!(verify_key_against_sample(&good_key, &[tombstone]).is_ok());
    }

    #[test]
    fn stored_session_debug_never_leaks_tokens() {
        let stored = StoredSession {
            access_token: "SUPER-SECRET-ACCESS".into(),
            refresh_token: "super-secret-refresh".into(),
            expires_in: 3600,
            user_id: "u".into(),
            saved_at: 12345,
        };
        let text = format!("{stored:?}");
        assert!(!text.contains("SUPER-SECRET-ACCESS"));
        assert!(!text.contains("super-secret-refresh"));
        assert!(text.contains("StoredSession"));
    }
}
