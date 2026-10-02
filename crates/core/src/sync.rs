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

use crate::{App, CoreError, RemoteResetInfo};
use crypto::{decrypt, derive_master_key, encrypt, MasterKey};
use sync::{EnvironmentRow, ProjectRow, Session, SyncClient, VariableRow, VaultMetaPush, VaultRow};

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
    /// The remote vault was reset on another device: abort WITHOUT pushing
    /// or pulling, and the caller must ask the user rather than adopt,
    /// because adopting would push this device's pre-wipe rows back over
    /// the wipe.
    RemoteReset,
}

/// Decide how to reconcile local and remote vault salts.
///
/// The salt is not secret; it only identifies the key domain. Mixing rows
/// from two domains leaves ciphertexts nobody can decrypt, so any mismatch
/// without a matching local rekey marker must stop the sync.
/// Local and remote vault state, gathered by the caller so this stays pure.
struct SaltInputs<'a> {
    local_salt: &'a [u8],
    local_epoch: i64,
    remote_salt_b64: Option<&'a str>,
    remote_epoch: Option<i64>,
    remote_key_change: Option<&'a str>,
    pending_marker: Option<&'a str>,
}

fn salt_action(i: &SaltInputs) -> SaltAction {
    let Some(remote) = i.remote_salt_b64 else {
        return SaltAction::PushLocal;
    };
    if remote == b64_encode(i.local_salt) {
        return SaltAction::Proceed;
    }
    // Salt differs. A remote reset elsewhere wins over everything in this
    // branch — even a pending rekey marker from this device, which must be
    // stale if the remote was wiped after it: pushing our salt back would
    // resurrect pre-wipe rows over the reset.
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch)
        && i.remote_key_change == Some(models::constants::KEY_CHANGE_RESET)
    {
        return SaltAction::RemoteReset;
    }
    // Salt differs. A remote that has rotated past us wins even when this
    // device holds a pending rekey marker: our meta is stale and pushing it
    // would clobber a newer key domain.
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch) {
        return SaltAction::RemoteKeyChanged;
    }
    if i.pending_marker
        .is_some_and(|m| m == hex::encode(i.local_salt))
    {
        return SaltAction::PushRekey;
    }
    SaltAction::RemoteKeyChanged
}

/// True when the remote vault shares our key domain but predates the verifier
/// migration, so this sync should fill in the verifier. Deliberately only for
/// `Proceed`: a salt mismatch must abort before anything is written.
fn needs_verifier_backfill(action: SaltAction, remote: Option<&VaultRow>) -> bool {
    matches!(action, SaltAction::Proceed)
        && remote.is_some_and(|v| v.verifier_ct.is_none() && v.verifier_nonce.is_none())
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

/// Decide how to verify a derived key against the remote vault, given what
/// the `vaults` row carries. Pure; unit-testable without HTTP.
///
/// A complete verifier pair is the strongest signal: it is independent of the
/// vault's contents, so an empty vault still rejects a wrong password. A row
/// written before the verifier migration has neither field and falls back to
/// the sample. A verifier without a nonce is a half-written row and must not
/// be mistaken for "no verifier".
#[allow(clippy::type_complexity)]
fn verifier_parts(vault: &VaultRow) -> Result<Option<(Vec<u8>, Vec<u8>)>, CoreError> {
    match (&vault.verifier_ct, &vault.verifier_nonce) {
        (None, None) => Ok(None),
        (Some(ct), Some(nonce)) => Ok(Some((b64_decode(ct)?, b64_decode(nonce)?))),
        _ => Err(CoreError::RemoteVerifierIncomplete),
    }
}

/// Verify a master key against the remote verifier ciphertext.
fn verify_verifier(key: &MasterKey, ct: &[u8], nonce: &[u8]) -> Result<(), CoreError> {
    let plaintext = decrypt(key, ct, nonce).map_err(|_| CoreError::invalid_password())?;
    if plaintext.as_str() == models::constants::VAULT_VERIFIER_MESSAGE {
        Ok(())
    } else {
        Err(CoreError::invalid_password())
    }
}

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

/// Mark a remote project as deleted for a reset. Pure; unit-testable.
/// Only metadata changes: a reset has no master key, so the row's contents
/// are carried through untouched.
//
// Not yet wired: the reset orchestrator (follow-up task) is the caller.
#[allow(dead_code)]
fn tombstone_project(row: &ProjectRow, now: DateTime<Utc>) -> ProjectRow {
    ProjectRow {
        deleted: true,
        version: row.version + 1,
        updated_at: Some(now),
        ..row.clone()
    }
}

/// Mark a remote environment as deleted for a reset. Pure; unit-testable.
/// Only metadata changes (`EnvironmentRow` carries no `version` and none is
/// added here): a reset has no master key, so the row is carried through
/// untouched apart from the tombstone markers.
//
// Not yet wired: the reset orchestrator (follow-up task) is the caller.
#[allow(dead_code)]
fn tombstone_environment(row: &EnvironmentRow, now: DateTime<Utc>) -> EnvironmentRow {
    EnvironmentRow {
        deleted: true,
        updated_at: Some(now),
        ..row.clone()
    }
}

/// Mark a remote variable as deleted for a reset. The ciphertext and nonce
/// are carried through byte-identical: a reset has no master key, so
/// re-encrypting is impossible, and a row whose ciphertext changed would no
/// longer be readable by any device that still holds the old key.
//
// Not yet wired: the reset orchestrator (follow-up task) is the caller.
#[allow(dead_code)]
fn tombstone_variable(row: &VariableRow, now: DateTime<Utc>) -> VariableRow {
    VariableRow {
        deleted: true,
        version: row.version + 1,
        updated_at: Some(now),
        ..row.clone()
    }
}

/// Verify a derived key against the remote vault. Prefers the verifier
/// ciphertext, which works regardless of how many variables exist; falls back
/// to a sample of variable ciphertexts for vaults predating the verifier
/// migration. A wrong password yields `CoreError::InvalidPassword`.
async fn verify_key_against_remote(
    client: &SyncClient,
    session: &Session,
    key: &MasterKey,
    vault: &VaultRow,
) -> Result<(), CoreError> {
    if let Some((ct, nonce)) = verifier_parts(vault)? {
        return verify_verifier(key, &ct, &nonce);
    }
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
        let kdf_params: KdfParams = serde_json::from_value(vault.kdf_params.clone())
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;

        // No verifier travels over the wire; derive locally and verify
        // against a real remote ciphertext before touching the local vault.
        let key = derive_master_key(&password, &salt, &kdf_params)?;
        verify_key_against_remote(&client, &session, &key, &vault).await?;

        let (verifier_ct, verifier_nonce) =
            encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage
            .init_vault(&salt, &kdf_params, &verifier_ct, &verifier_nonce)?;
        self.storage.set_key_epoch(vault.key_epoch)?;
        self.master_key = Some(key);
        Ok(())
    }

    /// Adopt the remote vault's key after a `RemoteKeyChanged` abort.
    ///
    /// `password` must be the one currently protecting the REMOTE vault: its
    /// salt + kdf params derive the new key, verified against the remote
    /// verifier ciphertext (or a remote sample ciphertext in vaults predating
    /// the verifier migration) before anything local is touched. Every local variable is
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
        let kdf_params: KdfParams = serde_json::from_value(vault.kdf_params.clone())
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;

        let new_key = derive_master_key(&password, &remote_salt, &kdf_params)?;
        verify_key_against_remote(&client, &session, &new_key, &vault).await?;

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
            vault.key_epoch,
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
        let mut vault_push: Option<VaultMetaPush> = None;
        let mut clear_rekey_marker = false;
        let mut salt_action_taken = SaltAction::Proceed;
        if self.storage.is_initialized()? {
            let meta = self.storage.get_vault_meta()?;
            let pending = SyncState::get(self.storage.conn(), PENDING_REKEY_SALT_KEY)?;
            let inputs = SaltInputs {
                local_salt: &meta.salt,
                local_epoch: meta.key_epoch,
                remote_salt_b64: remote_vault.as_ref().map(|v| v.salt.as_str()),
                remote_epoch: remote_vault.as_ref().map(|v| v.key_epoch),
                remote_key_change: remote_vault.as_ref().and_then(|v| v.key_change.as_deref()),
                pending_marker: pending.as_deref(),
            };
            salt_action_taken = salt_action(&inputs);
            match salt_action_taken {
                SaltAction::Proceed => {}
                SaltAction::PushLocal | SaltAction::PushRekey => {
                    vault_push = Some(VaultMetaPush {
                        salt: b64_encode(&meta.salt),
                        kdf_params: serde_json::to_value(&meta.kdf_params)?,
                        verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                        verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                        key_epoch: meta.key_epoch,
                        key_change: if salt_action_taken == SaltAction::PushRekey {
                            models::constants::KEY_CHANGE_REKEY.into()
                        } else {
                            models::constants::KEY_CHANGE_INIT.into()
                        },
                        key_changed_at: if salt_action_taken == SaltAction::PushRekey {
                            Some(Utc::now().to_rfc3339())
                        } else {
                            None
                        },
                    });
                    clear_rekey_marker = salt_action_taken == SaltAction::PushRekey;
                }
                SaltAction::RemoteKeyChanged => return Err(CoreError::RemoteKeyChanged),
                SaltAction::RemoteReset => {
                    let v = remote_vault.as_ref().ok_or_else(|| {
                        CoreError::Other("remote reset detected without a remote row".into())
                    })?;
                    return Err(CoreError::RemoteReset(RemoteResetInfo {
                        remote_epoch: v.key_epoch,
                        key_change: v.key_change.clone(),
                        key_changed_at: v.key_changed_at,
                    }));
                }
            }
        }

        // Local-only delete chains (project deleted but children live) would
        // otherwise leave live children under dead parents on the server.
        self.storage.cascade_tombstones(Utc::now())?;

        // ---- Push: vault meta first (rows below are encrypted under the key
        // it describes), then dirty rows. ----
        if let Some(push) = &vault_push {
            client.push_vault(&session, push).await?;
            report.pushed += 1;
            if clear_rekey_marker {
                // Clear only after the push landed: on network failure the
                // marker must survive so the next sync can retry. A stale
                // marker (salts equal) is inert — the guard only reads it on
                // a mismatch, and the next rekey overwrites it.
                SyncState::remove(self.storage.conn(), PENDING_REKEY_SALT_KEY)?;
            }
        }

        // Backfill: this vault predates the verifier migration. Completing the
        // verifier makes the next device's password check real. `push_vault`
        // upserts a complete `VaultRow` body (`resolution=merge-duplicates`),
        // so this ALSO rewrites `key_epoch`, `key_change` and `key_changed_at`
        // — not just the additive verifier fields. That rewrite is safe only
        // because the guard compared salts first: every epoch bump today also
        // rotates the salt, so salt-equality currently implies epoch-equality
        // and the rewritten values equal the remote's. The verifier is
        // encrypted under the LOCAL key, so the LOCAL `kdf_params` it was
        // derived from travel with it — never echo the remote params here.
        if needs_verifier_backfill(salt_action_taken, remote_vault.as_ref()) {
            let meta = self.storage.get_vault_meta()?;
            let key = self.require_key()?;
            let (ct, nonce) = encrypt(key, models::constants::VAULT_VERIFIER_MESSAGE)?;
            let remote = remote_vault
                .as_ref()
                .expect("needs_verifier_backfill guarantees a remote vault is present");
            client
                .push_vault(
                    &session,
                    &VaultMetaPush {
                        salt: remote.salt.clone(),
                        kdf_params: serde_json::to_value(&meta.kdf_params)?,
                        verifier_ct: Some(b64_encode(&ct)),
                        verifier_nonce: Some(b64_encode(&nonce)),
                        key_epoch: meta.key_epoch,
                        key_change: models::constants::KEY_CHANGE_INIT.into(),
                        key_changed_at: None,
                    },
                )
                .await?;
            report.pushed += 1;
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
    fn tombstoning_preserves_ciphertext_byte_for_byte() {
        let now = ts(0);
        let row = VariableRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000001".into(),
            environment_id: "018f0000-0000-7000-8000-000000000002".into(),
            key: "SECRET".into(),
            value_encrypted: b64_encode(b"opaque-ciphertext"),
            nonce: b64_encode(b"opaque-nonce-24-bytes-xx"),
            notes: Some("keep me".into()),
            is_readonly: true,
            allow_export: false,
            deleted: false,
            version: 4,
            updated_at: None,
        };

        let dead = tombstone_variable(&row, now);
        assert!(dead.deleted);
        assert_eq!(dead.version, 5);
        assert_eq!(dead.updated_at, Some(now));
        assert_eq!(
            dead.value_encrypted, row.value_encrypted,
            "ciphertext must survive"
        );
        assert_eq!(dead.nonce, row.nonce, "nonce must survive");
        assert_eq!(dead.key, row.key);
        assert_eq!(dead.notes, row.notes);
        assert_eq!(dead.owner_id, row.owner_id);
        assert_eq!(dead.is_readonly, row.is_readonly);
        assert_eq!(dead.allow_export, row.allow_export);
    }

    #[test]
    fn tombstoning_project_and_environment_preserves_fields() {
        let now = ts(0);

        let project = ProjectRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000003".into(),
            name: "P".into(),
            description: Some("keep me".into()),
            color: Some("red".into()),
            icon: None,
            deleted: false,
            version: 2,
            updated_at: None,
        };
        let dead_project = tombstone_project(&project, now);
        assert!(dead_project.deleted);
        assert_eq!(dead_project.version, 3);
        assert_eq!(dead_project.updated_at, Some(now));
        assert_eq!(dead_project.name, project.name);
        assert_eq!(dead_project.description, project.description);
        assert_eq!(dead_project.color, project.color);
        assert_eq!(dead_project.icon, project.icon);
        assert_eq!(dead_project.owner_id, project.owner_id);

        // EnvironmentRow carries no `version`: only `deleted`/`updated_at`
        // may change, everything else survives.
        let env = EnvironmentRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000004".into(),
            project_id: project.id.clone(),
            name: "local".into(),
            is_default: true,
            sort_order: 7,
            deleted: false,
            updated_at: None,
        };
        let dead_env = tombstone_environment(&env, now);
        assert!(dead_env.deleted);
        assert_eq!(dead_env.updated_at, Some(now));
        assert_eq!(dead_env.project_id, env.project_id);
        assert_eq!(dead_env.name, env.name);
        assert_eq!(dead_env.is_default, env.is_default);
        assert_eq!(dead_env.sort_order, env.sort_order);
        assert_eq!(dead_env.owner_id, env.owner_id);
    }

    fn salt_inputs<'a>(
        local: &'a [u8],
        remote: Option<&'a str>,
        marker: Option<&'a str>,
    ) -> SaltInputs<'a> {
        SaltInputs {
            local_salt: local,
            local_epoch: 1,
            remote_salt_b64: remote,
            remote_epoch: None,
            remote_key_change: None,
            pending_marker: marker,
        }
    }

    #[test]
    fn salt_guard_covers_all_four_branches() {
        let local = [9u8; 16];
        let local_b64 = b64_encode(&local);
        let local_hex = hex::encode(local);
        let other_b64 = b64_encode(&[8u8; 16]);

        // Remote has no vault → push local meta (first sync).
        assert_eq!(
            salt_action(&salt_inputs(&local, None, None)),
            SaltAction::PushLocal
        );
        assert_eq!(
            salt_action(&salt_inputs(&local, None, Some(&local_hex))),
            SaltAction::PushLocal
        );

        // Salts equal → normal sync regardless of a (stale) marker.
        assert_eq!(
            salt_action(&salt_inputs(&local, Some(&local_b64), None)),
            SaltAction::Proceed
        );
        assert_eq!(
            salt_action(&salt_inputs(&local, Some(&local_b64), Some(&local_hex))),
            SaltAction::Proceed
        );

        // Salts differ + marker matches THIS device's salt → rekeyed here:
        // push the new meta before the rows.
        assert_eq!(
            salt_action(&salt_inputs(&local, Some(&other_b64), Some(&local_hex))),
            SaltAction::PushRekey
        );

        // Salts differ, no marker → abort, nothing pushed or pulled.
        assert_eq!(
            salt_action(&salt_inputs(&local, Some(&other_b64), None)),
            SaltAction::RemoteKeyChanged
        );
        // A marker for a different salt must not authorize the push.
        assert_eq!(
            salt_action(&salt_inputs(&local, Some(&other_b64), Some("deadbeef"))),
            SaltAction::RemoteKeyChanged
        );
    }

    #[test]
    fn remote_epoch_ahead_blocks_a_stale_local_rekey() {
        // This device rekeyed and has a pending marker, but the remote has
        // since rotated again. Pushing our stale meta would clobber it.
        let local = [1u8; 16];
        let local_hex = hex::encode(local);
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 2,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(3),
            remote_key_change: None,
            pending_marker: Some(&local_hex),
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn remote_epoch_ahead_with_matching_salt_still_proceeds() {
        // Salts match, so the key domains agree; a higher remote epoch is
        // bookkeeping, not a reason to abort.
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&local)),
            remote_epoch: Some(9),
            remote_key_change: None,
            pending_marker: None,
        };
        assert_eq!(salt_action(&i), SaltAction::Proceed);
    }

    #[test]
    fn remote_epoch_behind_does_not_block_our_newer_rekey() {
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 5,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(4),
            remote_key_change: None,
            pending_marker: Some(&hex::encode(local)),
        };
        assert_eq!(salt_action(&i), SaltAction::PushRekey);
    }

    #[test]
    fn remote_reset_is_distinguished_from_a_remote_rekey() {
        let local = [1u8; 16];
        let other = b64_encode(&[2u8; 16]);

        let mut i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&other),
            remote_epoch: Some(3),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: None,
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteReset);

        // Same shape, but the remote rotated the key rather than being reset.
        i.remote_key_change = Some(models::constants::KEY_CHANGE_REKEY);
        assert_eq!(
            salt_action(&i),
            SaltAction::RemoteKeyChanged,
            "a rekey elsewhere keeps the guided adoption flow"
        );

        // A pre-migration remote row has no key_change: stay conservative.
        i.remote_key_change = None;
        assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn remote_reset_never_triggers_on_matching_salt_or_lower_epoch() {
        let local = [1u8; 16];
        let matching = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&local)),
            remote_epoch: Some(99),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: None,
        };
        assert_eq!(salt_action(&matching), SaltAction::Proceed);

        let mut behind = matching;
        let diverged = b64_encode(&[2u8; 16]);
        behind.remote_salt_b64 = Some(&diverged);
        behind.local_epoch = 5;
        behind.remote_epoch = Some(4);
        assert_eq!(salt_action(&behind), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn a_pending_reset_marker_beats_the_rekey_marker_check() {
        // This device has a stale rekey marker and the remote was reset after
        // it. The reset must win, or we would push our stale salt over the wipe.
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(3),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: Some(&hex::encode(local)),
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteReset);
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

    fn vault_row_with_verifier(key: &MasterKey) -> VaultRow {
        let (ct, nonce) = encrypt(key, models::constants::VAULT_VERIFIER_MESSAGE).unwrap();
        VaultRow {
            owner_id: None,
            salt: "c2FsdA==".into(),
            kdf_params: serde_json::json!({"m_cost": 2048, "t_cost": 1, "p_cost": 1, "output_len": 32}),
            verifier_ct: Some(b64_encode(&ct)),
            verifier_nonce: Some(b64_encode(&nonce)),
            key_epoch: 1,
            key_change: Some("init".into()),
            key_changed_at: None,
        }
    }

    fn test_keys() -> (MasterKey, MasterKey, KdfParams, Vec<u8>) {
        let params = KdfParams {
            m_cost: 2048,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        let salt = vec![9u8; 16];
        let good =
            derive_master_key(&SecretString::new("correct-horse".into()), &salt, &params).unwrap();
        let bad = derive_master_key(&SecretString::new("wrong".into()), &salt, &params).unwrap();
        (good, bad, params, salt)
    }

    #[test]
    fn verifier_accepts_only_the_right_key() {
        let (good, bad, _, _) = test_keys();
        let row = vault_row_with_verifier(&good);
        let (ct, nonce) = (
            b64_decode(row.verifier_ct.as_ref().unwrap()).unwrap(),
            b64_decode(row.verifier_nonce.as_ref().unwrap()).unwrap(),
        );
        assert!(verify_verifier(&good, &ct, &nonce).is_ok());
        assert!(matches!(
            verify_verifier(&bad, &ct, &nonce),
            Err(CoreError::InvalidPassword(_))
        ));
    }

    #[test]
    fn verifier_rejects_ciphertext_of_the_wrong_constant() {
        // Right key, but the row was encrypted over some other plaintext: the
        // AEAD tag passes yet the message must not match.
        let (good, _, _, _) = test_keys();
        let (ct, nonce) = encrypt(&good, "some-other-value").unwrap();
        assert!(matches!(
            verify_verifier(&good, &ct, &nonce),
            Err(CoreError::InvalidPassword(_))
        ));
    }

    #[test]
    fn verifier_row_without_nonce_is_an_explicit_error() {
        let (good, _, _, _) = test_keys();
        let mut row = vault_row_with_verifier(&good);
        row.verifier_nonce = None;
        assert!(matches!(
            verifier_parts(&row),
            Err(CoreError::RemoteVerifierIncomplete)
        ));
    }

    #[test]
    fn backfill_only_on_matching_domain_without_verifier() {
        let key = test_keys().0;
        let mut old_row = vault_row_with_verifier(&key);
        old_row.verifier_ct = None;
        old_row.verifier_nonce = None;

        assert!(needs_verifier_backfill(SaltAction::Proceed, Some(&old_row)));
        assert!(
            !needs_verifier_backfill(SaltAction::Proceed, None),
            "no remote vault: the first push already carries the verifier"
        );
        assert!(
            !needs_verifier_backfill(SaltAction::RemoteKeyChanged, Some(&old_row)),
            "a salt mismatch must abort, never write"
        );
        assert!(
            !needs_verifier_backfill(SaltAction::PushRekey, Some(&old_row)),
            "a rekey push already carries a verifier"
        );
        assert!(
            !needs_verifier_backfill(SaltAction::Proceed, Some(&vault_row_with_verifier(&key))),
            "already has a verifier"
        );
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
