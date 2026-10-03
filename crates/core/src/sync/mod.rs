//! Sync orchestration: push dirty rows, pull since cursor, LWW merge,
//! tombstone cascade and bootstrap for new devices.
//!
//! Zero-knowledge: this module moves ciphertexts only — nothing here decrypts
//! or sends plaintext values.

mod account;
mod guard;
mod merge;
mod rows;
mod verify;

pub use guard::init_remote_guard_needed;

use chrono::{DateTime, Utc};
use models::KdfParams;
use secrecy::SecretString;
use std::fmt;
use storage::{SyncState, SyncTable};

use crate::{App, CoreError, RemoteResetInfo};
use crypto::{decrypt, derive_master_key, encrypt};
use sync::{EnvironmentRow, ProjectRow, Session, SyncClient, VariableRow, VaultMetaPush, VaultRow};

use account::{
    clear_supabase_session, fresh_session, load_stored_session, read_sync_config,
    save_supabase_session, sync_client,
};
use guard::{
    key_change_for, needs_verifier_backfill, plan_pending_reset, reset_epoch_for, salt_action,
    PendingResetPlan, SaltAction, SaltInputs,
};
use merge::{merge_environment, merge_project, merge_variable, next_cursor, MergeOutcome};
use rows::{
    b64_decode, b64_encode, environment_to_dto, project_to_dto, reset_tombstone_sets,
    variable_to_dto,
};
use verify::verify_key_against_remote;

pub const SUPABASE_URL_ENV: &str = "VAULTR_SUPABASE_URL";
pub const SUPABASE_KEY_ENV: &str = "VAULTR_SUPABASE_KEY";
/// Keyring account holding the Supabase JWT session (service =
/// KEYRING_SERVICE).
///
/// **Deliberately global, unlike the master-key session: this is an ACCOUNT
/// credential, not a vault credential.** One person has one Supabase account
/// and one login, so every vault shares it — it is the same account talking to
/// the same server. `vltr logout` logging the account out entirely is the
/// correct semantic; there is no such thing as logging out of one vault.
///
/// Do NOT scope it per database (the master key IS scoped per database, see
/// `core::session::session_account`). A database being created has no
/// session of its own, so [`init_remote_guard_needed`] would be false on every
/// `vltr init`: the guard would never ask the server whether this account
/// already has a vault, silently creating a divergent local key domain.
const KEYRING_ACCOUNT_SUPABASE: &str = "supabase-session";
/// `sync_state` cursor key for incremental pull.
const CURSOR_KEY: &str = "last_pull";
/// `sync_state` marker set by `rekey`: hex of the local salt THIS device
/// rotated. A salt mismatch with this marker present authorizes pushing the
/// new local vault meta; without it the mismatch aborts the sync.
pub const PENDING_REKEY_SALT_KEY: &str = "pending_rekey_salt";
/// `sync_state` marker set by `reset_local`: this device has abandoned its key
/// and installed a new domain locally, but the matching remote wipe may not
/// have landed. A sync with this marker set finishes the wipe before running
/// the salt guard.
pub const PENDING_LOCAL_RESET_KEY: &str = "pending_local_reset";
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
// ---------- App methods ----------

impl App {
    /// True when the Supabase env vars are present (sync is configurable).
    pub fn sync_available_config() -> bool {
        read_sync_config().is_some()
    }

    /// True when a vault exists on the server (requires the account's stored
    /// session — account-global, see [`KEYRING_ACCOUNT_SUPABASE`]).
    pub async fn remote_has_vault() -> Result<bool, CoreError> {
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        Ok(client.get_vault(&session).await?.is_some())
    }

    /// Log in to Supabase and persist the JWT session in the OS keyring. One
    /// login per account, shared by every vault.
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

    /// Log the account out of sync. Not per-vault on purpose
    /// ([`KEYRING_ACCOUNT_SUPABASE`]).
    pub fn sync_logout(&self) -> Result<(), CoreError> {
        clear_supabase_session()
    }

    /// True when sync env vars are set and the account has a Supabase session.
    pub fn sync_enabled() -> bool {
        std::env::var(SUPABASE_URL_ENV).is_ok_and(|v| !v.is_empty())
            && std::env::var(SUPABASE_KEY_ENV).is_ok_and(|v| !v.is_empty())
            && matches!(load_stored_session(), Ok(Some(_)))
    }

    /// True when the account has a Supabase session stored (keyring or fallback
    /// file), regardless of how sync is configured. Unlike
    /// [`App::sync_enabled`], this checks the session alone — env vars /
    /// sync.json are irrelevant.
    ///
    /// Takes no database on purpose: `vltr init` consults this before the vault
    /// exists. See [`init_remote_guard_needed`].
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
    ///
    /// Also serves the divergence prompt's "keep local" choice, which is the
    /// `RemoteReset` case of the same divergence — and that is why the rotation
    /// here re-dirties projects and environments while `App::rekey` does not:
    /// adoption is what follows a remote reset, and a reset tombstoned every
    /// server row with a newer `updated_at`. Only the variables were being
    /// re-queued, so the retry's push left the parents' tombstones standing and
    /// the pull that followed deleted the project the user had asked to keep.
    /// See [`Storage::apply_key_rotation_dirtying_parents`], which also
    /// explains why a rekey must keep paying for variables only.
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
        // Live rows only, deliberately. A tombstone's ciphertext is dead weight:
        // nothing ever decrypts it, and a reset keeps those bytes as they were,
        // so a tombstone this device pulled can carry a key domain nobody holds
        // any more — the key of a vault that has since been reset. Decrypting
        // those made adoption abort with `decryption failed` on the first of
        // them, which is every vault that has ever synced a remote carrying
        // them: the "keep local" choice, the one that exists to prevent data
        // loss, could not be taken at all. What adoption propagates about a
        // tombstone is `deleted`, `version` and `updated_at`, so skipping them
        // loses nothing and leaves their bytes exactly as a reset left them.
        //
        // A LIVE row that fails to decrypt is still a hard error, below: it
        // would mean the local vault's contents disagree with the key this
        // device is holding, and swallowing that leaves a verifier claiming one
        // key over ciphertext from another.
        let variables = self.storage.live_variables()?;
        let mut reencrypted = Vec::with_capacity(variables.len());
        for var in &variables {
            let plaintext = decrypt(old_key, &var.value_encrypted, &var.nonce)?;
            let (ciphertext, nonce) = encrypt(&new_key, plaintext.as_str())?;
            reencrypted.push((var.id, ciphertext, nonce));
        }

        let (verifier_ct, verifier_nonce) =
            encrypt(&new_key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        // Not `apply_key_rotation`: adoption must also re-queue the parents,
        // or a post-reset retry pushes no project/environment rows and the
        // reset's tombstones win the following pull. See this method's doc.
        self.storage.apply_key_rotation_dirtying_parents(
            &reencrypted,
            &remote_salt,
            &kdf_params,
            &verifier_ct,
            &verifier_nonce,
            vault.key_epoch,
        )?;

        self.last_session_error = crate::session::save_master_key(self.storage.db_path(), &new_key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(new_key);
        Ok(())
    }

    /// Discard this device's vault and join the remote's key domain after a
    /// `RemoteReset` abort — the divergence prompt's "discard local" choice.
    ///
    /// The counterpart of [`App::adopt_remote_key`], and deliberately its
    /// opposite: a reset wiped the remote's live secrets, so re-encrypting this
    /// device's pre-wipe rows and pushing them back would resurrect exactly what
    /// the wipe destroyed. Here the local rows are *deleted* instead, and what is
    /// adopted is the remote's domain, so both devices end up aligned and empty.
    ///
    /// `password` must be the one protecting the REMOTE vault: its salt and kdf
    /// params derive the key, verified against the remote verifier (or a remote
    /// sample ciphertext in vaults predating the verifier migration) before
    /// anything local is touched — a wrong password must not be what destroys a
    /// local vault. The remote's salt, kdf params, verifier and epoch are
    /// installed as-is: this is not an epoch bump, it is a move to the remote's
    /// domain, and re-generating either would only re-create the mismatch the
    /// guard just found.
    ///
    /// `pending_local_reset` is cleared: the remote wipe it stands for has
    /// already landed by the time a device sees this prompt, and a surviving
    /// marker would have the next sync wipe the remote a second time. (The
    /// explicit removal is belt-and-braces — `reset_vault` empties `sync_state`
    /// wholesale — but it keeps the invariant stated where it is relied on.)
    ///
    /// Unlike `adopt_remote_key` this never reads `require_key()`: the local
    /// rows are destroyed, not re-encrypted, so the old in-memory key is
    /// irrelevant. The new key replaces it and is saved to the session, or the
    /// stored session would no longer open the vault it now describes.
    pub async fn discard_local_and_adopt(
        &mut self,
        password: SecretString,
    ) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let remote = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;

        let salt = b64_decode(&remote.salt)?;
        let kdf_params: KdfParams = serde_json::from_value(remote.kdf_params.clone())
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;

        // Verify BEFORE the wipe: this is the last moment at which a wrong
        // password can be caught without having destroyed anything.
        let key = derive_master_key(&password, &salt, &kdf_params)?;
        verify_key_against_remote(&client, &session, &key, &remote).await?;

        let (verifier_ct, verifier_nonce) =
            encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.reset_vault(
            &salt,
            &kdf_params,
            &verifier_ct,
            &verifier_nonce,
            remote.key_epoch,
        )?;
        SyncState::remove(self.storage.conn(), PENDING_LOCAL_RESET_KEY)?;

        self.last_session_error = crate::session::save_master_key(self.storage.db_path(), &key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(key);
        Ok(())
    }

    /// Push the remote half of a reset: new vault metadata first, then a
    /// tombstone for every row. Needs no master key — a tombstone is a
    /// metadata write and the ciphertext travels through untouched.
    ///
    /// Two sources feed the row this pushes, and the split between them is the
    /// whole point:
    ///
    /// * `salt`, `kdf_params`, `verifier_ct` and `verifier_nonce` are the LOCAL
    ///   ones, read from storage. The row being replaced describes the domain
    ///   being wiped, so publishing ITS salt, kdf params or verifier would
    ///   leave the server advertising a key domain nobody holds while its rows
    ///   sit tombstoned underneath it. The local verifier was encrypted under
    ///   the local key, so it must travel with the params it was derived from.
    /// * `key_epoch` is the single exception, and it comes from the remote row:
    ///   `remote.key_epoch + 1`. The local epoch is only a placeholder from
    ///   `reset_local`, which cannot know the server's counter, so writing it
    ///   back could lower it. Adding to the remote's value is monotonic, so
    ///   neither a reset nor a retry of an interrupted one can move the server
    ///   backwards — and that is what keeps the next device's salt guard able to
    ///   tell a reset from a password change.
    ///
    /// Idempotent: re-running re-tombstones already-dead rows, bumping their
    /// version and `updated_at`, which the LWW merge resolves the same way.
    /// Returns the number of rows tombstoned.
    async fn push_reset(
        &self,
        client: &SyncClient,
        session: &Session,
        remote: &VaultRow,
    ) -> Result<usize, CoreError> {
        let meta = self.storage.get_vault_meta()?;
        // The one field not taken from local meta; see the doc comment. This is
        // the opposite of the verifier backfill in `sync()`, which pushes the
        // LOCAL epoch because a backfill must not write a stale value over a
        // newer remote one — here the intent is to advance past the remote.
        let target_epoch = reset_epoch_for(remote.key_epoch);
        client
            .push_vault(
                session,
                &VaultMetaPush {
                    salt: b64_encode(&meta.salt),
                    kdf_params: serde_json::to_value(&meta.kdf_params)?,
                    verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                    verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                    key_epoch: target_epoch,
                    key_change: models::constants::KEY_CHANGE_RESET.into(),
                    key_changed_at: Some(Utc::now().to_rfc3339()),
                },
            )
            .await?;
        // The push landed, so the placeholder is now stale: converge the local
        // counter on the published one. Without it, the next rekey on THIS
        // device starts from the placeholder and lands behind the remote — and
        // because the remote row still carries `key_change = "reset"`, the salt
        // guard then answers `RemoteReset` ("the remote vault was reset on
        // another device") on the very device that performed the reset, which
        // is a dead end for a user whose previous password is the one that was
        // lost.
        //
        // `Storage::set_key_epoch` requires an audit before any flow bumps the
        // epoch without rotating the salt. This is that audit: the verifier
        // backfill cannot fire in a post-reset state, because it needs
        // `Proceed` AND a remote row carrying no verifier, and every reset
        // path writes one — so it can never republish a stale epoch over this
        // one. The salt guard reads the epoch only inside the branch where the
        // salts already differ, so this write is inert there.
        self.storage.set_key_epoch(target_epoch)?;

        let projects = client
            .pull_rows::<ProjectRow>(session, "projects", None)
            .await?;
        let environments = client
            .pull_rows::<EnvironmentRow>(session, "environments", None)
            .await?;
        let variables = client
            .pull_rows::<VariableRow>(session, "variables", None)
            .await?;
        let (projects, environments, variables) =
            reset_tombstone_sets(&projects, &environments, &variables, Utc::now());
        let count = projects.len() + environments.len() + variables.len();

        // Parents before children: the server enforces the same FKs.
        if !projects.is_empty() {
            client.push_rows(session, "projects", &projects).await?;
        }
        if !environments.is_empty() {
            client
                .push_rows(session, "environments", &environments)
                .await?;
        }
        if !variables.is_empty() {
            client.push_rows(session, "variables", &variables).await?;
        }
        Ok(count)
    }

    /// Wipe the remote of live secrets and align it with the local vault that
    /// [`App::reset_local`] just installed. Requires a sync session; does not
    /// require the master key.
    pub async fn reset_remote(&mut self) -> Result<usize, CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let remote = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;
        let count = self.push_reset(&client, &session, &remote).await?;
        SyncState::remove(self.storage.conn(), PENDING_LOCAL_RESET_KEY)?;
        Ok(count)
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
        let mut remote_vault = client.get_vault(&session).await?;
        // A reset that was interrupted before its remote wipe landed must be
        // finished first. Left to the salt guard it would abort with
        // RemoteKeyChanged forever, since the local salt has already moved.
        // `finished_reset` outlives the branch: when the account had no
        // `vaults` row there is nothing to wipe, and the row this sync goes on
        // to create is the reset's own domain, not a fresh `init`.
        let finished_reset = self.pending_reset()?;
        if finished_reset {
            match plan_pending_reset(remote_vault.as_ref()) {
                PendingResetPlan::Wipe => {
                    let remote = remote_vault.as_ref().ok_or_else(|| {
                        CoreError::Other("pending reset planned a wipe with no remote row".into())
                    })?;
                    let count = self.push_reset(&client, &session, remote).await?;
                    report.pushed += count + 1;
                    // Re-read the vault meta: the snapshot above predates the
                    // wipe, so the salt guard would compare the NEW local salt
                    // against the OLD remote salt and abort this very sync.
                    // For a user who just reset because they lost the password
                    // that abort is a dead end — `vltr sync` would prompt for
                    // the remote master password and fail to adopt it. After
                    // the refetch the guard sees post-wipe data, resolves to
                    // `Proceed`, and the sync that landed the wipe also
                    // completes and reports success.
                    remote_vault = client.get_vault(&session).await?;
                }
                PendingResetPlan::AlreadyWiped => {}
            }
            // Cleared exactly once, after either branch. Every failure above
            // (`push_reset`, the refetch) short-circuits first, so an
            // interruption always leaves the marker set for the next sync to
            // retry. With no remote row there was nothing to wipe — the local
            // vault already is the new domain — so skipping silently here would
            // strand the marker and re-enter this branch on every future sync.
            SyncState::remove(self.storage.conn(), PENDING_LOCAL_RESET_KEY)?;
        }
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
                    let is_rekey = salt_action_taken == SaltAction::PushRekey;
                    vault_push = Some(VaultMetaPush {
                        salt: b64_encode(&meta.salt),
                        kdf_params: serde_json::to_value(&meta.kdf_params)?,
                        verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                        verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                        key_epoch: meta.key_epoch,
                        key_change: key_change_for(salt_action_taken, finished_reset).into(),
                        key_changed_at: if is_rekey || finished_reset {
                            Some(Utc::now().to_rfc3339())
                        } else {
                            None
                        },
                    });
                    clear_rekey_marker = is_rekey;
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
                        // Hardcoded `init` / no timestamp, unlike the push above
                        // which routes through `key_change_for`. Unreachable
                        // today: this branch needs `Proceed` plus a remote row
                        // with no verifier, and every reset path writes a
                        // verifier, so a post-reset vault can never reach it.
                        // It would become reachable only if a flow could leave a
                        // verifier-less remote row behind, or if the backfill
                        // stopped requiring `Proceed` — and because
                        // `push_vault` upserts a whole row, this would then
                        // silently rewrite a remote reset signal back to `init`
                        // and hand the next device the adoption dead end
                        // instead of an explanation. Route it through
                        // `key_change_for` if that ever happens.
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
mod tests;
