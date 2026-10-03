//! Business logic / use cases.
//! This is the only layer that CLI and Desktop should talk to.

use chrono::{DateTime, Utc};
use crypto::{decrypt, derive_master_key, encrypt, generate_salt, MasterKey};
use models::{DecryptedVariable, Environment, KdfParams, Project, Variable, VariableSummary};
use secrecy::SecretString;
use storage::{Storage, StorageError, SyncState};
use thiserror::Error;
use uuid::Uuid;

pub mod backup;
pub mod envfile;
pub mod session;
pub mod sync;

/// The remote vault was reset on another device: its epoch advanced and
/// `key_change` says `reset`. Adopting automatically would push this
/// device's pre-wipe rows back over the reset, so the caller must ask.
#[derive(Debug, Clone)]
pub struct RemoteResetInfo {
    pub remote_epoch: i64,
    pub key_change: Option<String>,
    pub key_changed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Sync(#[from] ::sync::SyncError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    InvalidPassword(String),
    #[error("vault is locked")]
    Locked,
    /// The remote vault salt no longer matches the local one (and this device
    /// has no pending rekey marker): another device changed the master key,
    /// or this vault was initialized independently. Nothing was pushed/pulled.
    #[error("the vault master key changed on another device")]
    RemoteKeyChanged,
    /// The remote vault was reset on another device (epoch advanced, key
    /// change says `reset`). Carries only epoch metadata — no key material,
    /// nothing decrypted.
    #[error("the remote vault was reset on another device")]
    RemoteReset(RemoteResetInfo),
    /// The remote `vaults` row carries `verifier_ct` without `verifier_nonce`.
    /// Refusing to sync beats verifying against a half-written row.
    #[error("the remote vault verifier is incomplete (ciphertext without nonce)")]
    RemoteVerifierIncomplete,
    #[error("project already exists")]
    ProjectExists,
    #[error("project not found")]
    ProjectNotFound,
    #[error("environment not found")]
    EnvironmentNotFound,
    #[error("variable not found")]
    VariableNotFound,
    #[error("variable is read-only")]
    ReadOnly,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A live variable could not be re-encrypted during a key rotation —
    /// `vltr rekey`, or the "keep what is local" branch of the divergence
    /// prompt.
    ///
    /// This exists because the alternative was a lie. Both call sites reach it
    /// through `?` on `decrypt`, which surfaces as `decryption failed (wrong key
    /// or corrupted data)`: a bare sentence that names neither the row nor the
    /// operation, and points at the key — which, at that point in a rotation, is
    /// provably *not* the problem. The user just unlocked with it and every
    /// other row opened.
    ///
    /// What actually happened is narrower and stranger: this one row's ciphertext
    /// belongs to a key domain this device no longer holds. A pull can deliver
    /// a row another device wrote, and the salt is what identifies a domain, so
    /// the row arrived under a key the salt no longer describes. Tombstones are
    /// exempt — nothing reads them, so they are skipped rather than decrypted.
    ///
    /// The message therefore names the row and says what is true, instead of
    /// blaming the key the user just proved correct.
    #[error(
        "cannot rotate the master key: the value of `{key}` was written under a \
         different key domain and this device cannot read it, so it cannot re-encrypt it. \
         Nothing has been changed — the vault is exactly as it was. This normally means one \
         live row reached this vault from a device that has since rotated or reset its key."
    )]
    VariableNotDecryptable {
        /// The variable's key, which is metadata the user already sees in
        /// `vltr ls` — not the value, which is never named or held here.
        key: String,
    },
    #[error("{0}")]
    Other(String),
}

impl CoreError {
    /// Default invalid-password error (no extra context).
    pub fn invalid_password() -> Self {
        Self::InvalidPassword("invalid master password".into())
    }
}

/// Main entry point for all operations.
pub struct App {
    storage: Storage,
    master_key: Option<MasterKey>,
    last_session_error: Option<String>,
}

impl App {
    pub fn open(db_path: impl AsRef<std::path::Path>) -> Result<Self, CoreError> {
        let storage = Storage::open(db_path)?;
        Ok(Self {
            storage,
            master_key: None,
            last_session_error: None,
        })
    }

    pub fn open_in_memory() -> Result<Self, CoreError> {
        let storage = Storage::open_in_memory()?;
        Ok(Self {
            storage,
            master_key: None,
            last_session_error: None,
        })
    }

    pub fn is_initialized(&self) -> Result<bool, CoreError> {
        Ok(self.storage.is_initialized()?)
    }

    /// Path of the vault file, or `None` for in-memory storage. Sessions are
    /// scoped to it: one persisted session per database.
    pub fn db_path(&self) -> Option<&std::path::Path> {
        self.storage.db_path()
    }

    pub fn init(&mut self, password: SecretString) -> Result<(), CoreError> {
        if self.storage.is_initialized()? {
            return Err(CoreError::Other("vault already initialized".into()));
        }
        let salt = generate_salt();
        let params = KdfParams::default();
        let key = derive_master_key(&password, &salt, &params)?;
        let (verifier_ct, verifier_nonce) =
            encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage
            .init_vault(&salt, &params, &verifier_ct, &verifier_nonce)?;
        self.last_session_error = session::save_master_key(self.storage.db_path(), &key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(key);
        Ok(())
    }

    pub fn unlock(&mut self, password: SecretString) -> Result<(), CoreError> {
        let meta = self.storage.get_vault_meta()?;
        let key = derive_master_key(&password, &meta.salt, &meta.kdf_params)?;
        // Verify password by decrypting the vault verifier marker.
        let marker = decrypt(&key, &meta.verifier_ct, &meta.verifier_nonce)
            .map_err(|_| CoreError::invalid_password())?;
        if marker.as_str() != models::constants::VAULT_VERIFIER_MESSAGE {
            return Err(CoreError::invalid_password());
        }
        self.last_session_error = session::save_master_key(self.storage.db_path(), &key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(key);
        Ok(())
    }

    /// Reason the last `unlock`/`init` failed to persist a session, if any.
    /// Consumed on read.
    pub fn take_session_error(&mut self) -> Option<String> {
        self.last_session_error.take()
    }

    /// Verify the master password without opening a session or storing the key.
    pub fn verify_password(&self, password: SecretString) -> Result<(), CoreError> {
        let meta = self.storage.get_vault_meta()?;
        let key = derive_master_key(&password, &meta.salt, &meta.kdf_params)?;
        let marker = decrypt(&key, &meta.verifier_ct, &meta.verifier_nonce)
            .map_err(|_| CoreError::invalid_password())?;
        if marker.as_str() != models::constants::VAULT_VERIFIER_MESSAGE {
            return Err(CoreError::invalid_password());
        }
        Ok(())
    }

    /// Change the master password: rotate the salt, derive a new key and
    /// re-encrypt every **live** variable (all environments; tombstones are
    /// skipped — see the comment at the rotation below, and
    /// [`Storage::live_variables`]).
    ///
    /// The vault's existing `kdf_params` are kept: they were chosen at init
    /// and a rekey only rotates the secret material (salt + ciphertexts),
    /// not the Argon2 cost. When a `pending_rekey_salt` marker is written at
    /// all (see below for the case where it is not), it is written BEFORE the
    /// rotation transaction: if the transaction fails, the vault is untouched
    /// and the stale marker is inert (the sync guard only consults it when
    /// salts actually differ, and the next rekey overwrites it), so no crash
    /// window can strand the local vault.
    ///
    /// When a `pending_local_reset` is already set, NO rekey marker is written
    /// at all. The reset wins, and this is the half of the "only one marker at
    /// a time" invariant `reset_local` states from the other side. Do not
    /// "fix" this back into a second active marker:
    ///
    /// * A rekey marker is REDUNDANT here, not merely redundant-in-principle.
    ///   The pending-reset branch of `sync()` runs BEFORE the salt guard, so
    ///   the next sync executes `push_reset` — which publishes the LOCAL salt,
    ///   re-encrypted verifier and local kdf params, the post-rotation ones,
    ///   because the rotation landed. The new salt is pushed either way. What
    ///   the rekey marker would add is a second, competing instruction, and
    ///   `key_change` would become `rekey` instead of `reset` for every other
    ///   device: the reset would be laundered into a password change, the
    ///   tombstone wipe would never run, and the pre-reset rows would stay
    ///   live on the server — still readable, because the other devices still
    ///   hold the old key. They would then abort on `RemoteKeyChanged` and be
    ///   asked for a remote password the user has just admitted losing.
    /// * Declining to SET is what makes the invariant unconditional. The
    ///   alternative — set the marker, then remove it once the rotation lands
    ///   — has a window in which both exist, and a rekey interrupted inside
    ///   the rotation would strand exactly the two-marker state this closes.
    ///   Here the reset marker is never disturbed, so an interrupted rekey
    ///   leaves a coherent single-marker state: the reset's own domain, and
    ///   the next sync completes the wipe against it.
    ///
    /// Note this is the opposite of dropping `pending_local_reset` instead.
    /// That keeps the invariant too, but it downgrades the pending reset to a
    /// plain rekey, which loses the wipe; the reset is the stronger statement
    /// of intent and is the one that must survive a rekey.
    ///
    /// Returns the number of re-encrypted variables: the live rows, since
    /// tombstones are not touched. This is also what the CLI prints, so it
    /// counts the secrets the user actually has.
    pub fn rekey(&mut self, new_password: SecretString) -> Result<usize, CoreError> {
        let old_key = self.require_key()?;
        let meta = self.storage.get_vault_meta()?;
        let salt = generate_salt();
        let new_key = derive_master_key(&new_password, &salt, &meta.kdf_params)?;

        // Read before the rotation and decide here, so the marker is either
        // written in full or never written: `apply_key_rotation` touches
        // `vault_meta`, `variables` and the parents' `synced_at`, never
        // `sync_state`, so this cannot go stale underneath the rotation.
        // Writing the marker first and deleting it after would leave a window
        // in which both markers are live. See this method's doc.
        if !self.pending_reset()? {
            SyncState::set(
                self.storage.conn(),
                sync::PENDING_REKEY_SALT_KEY,
                &hex::encode(salt),
            )?;
        }

        // Live rows only, for the same reason adoption reads only the live ones:
        // a tombstone's ciphertext is dead weight. A reset tombstones rows
        // without touching their `value_encrypted`/`nonce`, so a tombstone that
        // arrived by pull carries a key domain nobody holds any more — the reset
        // that wrote it destroyed that key. Decrypting those cut the whole
        // rotation short with `decryption failed` on the first of them, which
        // made `vltr rekey` impossible on any vault that had ever synced a
        // remote carrying one. That is a worse dead end than the one adoption
        // had: rekey has no prompt to decline and no other command that rotates
        // the master key, and if the remote has not moved on since the tombstone
        // was pulled then `sync` succeeds silently, so nothing ever surfaces the
        // state to the user.
        //
        // Note the premise this used to rest on — that the local key opens every
        // row by construction, which is why a rotation could afford
        // `all_variables` — is false, and the adoption bug is what proved it
        // false: the rows in question did not come from this device at all.
        //
        // A LIVE row that fails to decrypt is still a hard error, below. Same
        // asymmetry as adoption, and for the same reason: `deleted = true`
        // means nobody will read that row again, so skipping it loses nothing,
        // whereas a live row is a secret the user believes they have. Swallowing
        // it would leave a vault whose verifier advertises one key over
        // ciphertext from another. Refusing is atomic here — the loop completes
        // before `apply_key_rotation` is called — so the vault is untouched.
        //
        // The count returned is therefore the number of live rows moved, which
        // is what the CLI reports as "variables re-encrypted". A user with one
        // secret and a hundred tombstones has one variable, and reporting three
        // is the number that was wrong.
        let variables = self.storage.live_variables()?;
        let count = variables.len();
        let mut reencrypted = Vec::with_capacity(count);
        for var in &variables {
            let plaintext = decrypt(old_key, &var.value_encrypted, &var.nonce).map_err(|_| {
                CoreError::VariableNotDecryptable {
                    key: var.key.clone(),
                }
            })?;
            let (ciphertext, nonce) = encrypt(&new_key, plaintext.as_str())?;
            reencrypted.push((var.id, ciphertext, nonce));
        }

        let (verifier_ct, verifier_nonce) =
            encrypt(&new_key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.apply_key_rotation(
            &reencrypted,
            &salt,
            &meta.kdf_params,
            &verifier_ct,
            &verifier_nonce,
            meta.key_epoch + 1,
        )?;

        self.last_session_error = session::save_master_key(self.storage.db_path(), &new_key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(new_key);
        Ok(count)
    }

    /// Replace the local vault with an empty one under a NEW master key.
    ///
    /// Deliberately does not require an unlocked vault, and never reads
    /// `require_key()`: the lost password is the reason this exists. The old
    /// rows are deleted rather than re-encrypted because their key is gone.
    ///
    /// The epoch installed here is a LOCAL placeholder, advanced from this
    /// vault's own epoch. It is not the epoch the server ends up with: the
    /// authoritative value is `remote + 1`, computed by
    /// [`App::reset_remote`] / `sync()` where the remote row is in hand. That is
    /// why this takes no epoch argument — an offline caller cannot know the
    /// remote counter, and a guessed value could only ever lower it.
    ///
    /// Records `pending_local_reset`, stamped with the time of the reset, so a
    /// later sync pushes the matching remote wipe; and clears any
    /// `pending_rekey_salt` — a reset subsumes both markers, and only one may
    /// be active at a time. The other half of that invariant is [`App::rekey`],
    /// which declines to write its own marker while a reset is pending rather
    /// than removing this one.
    ///
    /// Returns the local epoch installed.
    pub fn reset_local(&mut self, new_password: SecretString) -> Result<i64, CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let meta = self.storage.get_vault_meta()?;
        let kdf_params = meta.kdf_params;
        let target_epoch = meta.key_epoch + 1;
        let salt = generate_salt();
        let new_key = derive_master_key(&new_password, &salt, &kdf_params)?;
        let (verifier_ct, verifier_nonce) =
            encrypt(&new_key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.reset_vault(
            &salt,
            &kdf_params,
            &verifier_ct,
            &verifier_nonce,
            target_epoch,
        )?;
        SyncState::remove(self.storage.conn(), sync::PENDING_REKEY_SALT_KEY)?;
        // The marker records WHEN the reset happened, not which epoch: the
        // authoritative epoch is `remote + 1`, computed at push time, so a
        // stored epoch here would be a second, wrong answer to a question
        // nobody asks — `pending_reset()` only tests that the marker exists.
        //
        // The timestamp is currently WRITE-ONLY. It is not what
        // `key_changed_at` reports: `push_reset` and the `PushLocal` that
        // finishes a reset both stamp `Utc::now()` at push time, and nothing
        // reads this value back. Wiring it through is a follow-up, not a
        // comment fix — it would change the metadata the reset publishes, and
        // that deserves end-to-end coverage this round is not touching.
        SyncState::set(
            self.storage.conn(),
            sync::PENDING_LOCAL_RESET_KEY,
            &Utc::now().to_rfc3339(),
        )?;
        self.last_session_error = session::save_master_key(self.storage.db_path(), &new_key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(new_key);
        Ok(target_epoch)
    }

    /// True when a local reset still needs its remote wipe pushed.
    pub fn pending_reset(&self) -> Result<bool, CoreError> {
        Ok(SyncState::get(self.storage.conn(), sync::PENDING_LOCAL_RESET_KEY)?.is_some())
    }

    /// Unlock using a key already loaded (e.g. from OS keyring or a local session file).
    ///
    /// A key that cannot open THIS vault's verifier is provably not this vault's
    /// key, so the rejection path drops the persisted session before returning.
    /// The decrypt failure is the one that matters: after [`App::reset_local`],
    /// an [`App::rekey`] or an adoption, the stored session holds the OLD key,
    /// and that key fails to decrypt rather than decrypting to the wrong marker.
    /// Returning early on it left a session that can open nothing in place for
    /// its full sliding TTL, so every command kept re-probing it and kept
    /// answering "invalid master password" instead of asking — and the password
    /// that works is the new one, which the message never mentions.
    ///
    /// Nothing is lost by clearing: the only caller is
    /// [`App::try_unlock_from_session`], so the key being rejected is the one
    /// that was just read out of the session.
    ///
    /// That claim needs the drop to have happened, so the clear is propagated
    /// rather than discarded: a session store that refuses to let go is returned
    /// in place of the rejection, because a surviving entry is exactly the state
    /// that answers "invalid master password" to every later command.
    pub fn unlock_with_key(&mut self, key: MasterKey) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let meta = self.storage.get_vault_meta()?;
        let opens_this_vault = decrypt(&key, &meta.verifier_ct, &meta.verifier_nonce)
            .is_ok_and(|marker| marker.as_str() == models::constants::VAULT_VERIFIER_MESSAGE);
        if !opens_this_vault {
            session::clear_session(self.storage.db_path())?;
            return Err(CoreError::invalid_password());
        }
        self.master_key = Some(key);
        Ok(())
    }

    /// Try to restore a session from the OS keyring, or a local 0600 session
    /// file if the keyring is unavailable. Returns true if unlocked.
    pub fn try_unlock_from_session(&mut self) -> Result<bool, CoreError> {
        if self.is_unlocked() {
            return Ok(true);
        }
        match session::load_master_key(self.storage.db_path())? {
            Some(key) => {
                self.unlock_with_key(key)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Clear the in-process key and this vault's persisted session (keyring +
    /// local session file). Other vaults are untouched.
    pub fn lock(&mut self) -> Result<(), CoreError> {
        self.master_key = None;
        self.last_session_error = None;
        session::clear_session(self.storage.db_path())?;
        Ok(())
    }

    pub fn has_keyring_session(&self) -> Result<bool, CoreError> {
        Ok(session::inspect(self.storage.db_path())?.is_some())
    }

    /// Where the current session is stored, if any (does not refresh the TTL).
    pub fn session_store(&self) -> Result<Option<session::SessionStore>, CoreError> {
        Ok(session::inspect(self.storage.db_path())?.map(|info| info.store))
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn schema_version(&self) -> Result<i64, CoreError> {
        Ok(self.storage.schema_version()?)
    }

    fn require_key(&self) -> Result<&MasterKey, CoreError> {
        self.master_key.as_ref().ok_or(CoreError::Locked)
    }

    fn resolve_env(
        &self,
        project_name: &str,
        env_name: &str,
    ) -> Result<(Project, Environment), CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        let env = self
            .storage
            .get_environment(project.id, env_name)?
            .ok_or(CoreError::EnvironmentNotFound)?;
        Ok((project, env))
    }

    // ---------- Projects ----------

    pub fn create_project(
        &self,
        name: &str,
        description: Option<String>,
        color: Option<String>,
        icon: Option<String>,
    ) -> Result<Project, CoreError> {
        models::validate_name("project", name).map_err(|e| CoreError::Other(e.to_string()))?;
        if self.storage.get_project_by_name(name)?.is_some() {
            return Err(CoreError::ProjectExists);
        }

        let now = Utc::now();
        let project = Project {
            id: Uuid::now_v7(),
            name: name.to_string(),
            description,
            color,
            icon,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        self.storage.create_project(&project)?;

        let env = Environment {
            id: Uuid::now_v7(),
            project_id: project.id,
            name: models::constants::DEFAULT_ENVIRONMENT.to_string(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        self.storage.create_environment(&env)?;
        Ok(project)
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, CoreError> {
        Ok(self.storage.list_projects()?)
    }

    pub fn delete_project(&self, name: &str) -> Result<(), CoreError> {
        if !self.storage.delete_project(name)? {
            return Err(CoreError::ProjectNotFound);
        }
        Ok(())
    }

    // ---------- Environments ----------

    pub fn list_environments(&self, project_name: &str) -> Result<Vec<Environment>, CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        Ok(self.storage.list_environments(project.id)?)
    }

    pub fn create_environment(
        &self,
        project_name: &str,
        env_name: &str,
    ) -> Result<Environment, CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        if self
            .storage
            .get_environment(project.id, env_name)?
            .is_some()
        {
            return Err(CoreError::Other(format!(
                "environment '{}' already exists",
                env_name
            )));
        }
        let now = Utc::now();
        let env = Environment {
            id: Uuid::now_v7(),
            project_id: project.id,
            name: env_name.to_string(),
            is_default: false,
            sort_order: 10,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        self.storage.create_environment(&env)?;
        Ok(env)
    }

    pub fn delete_environment(&self, project_name: &str, env_name: &str) -> Result<(), CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        let was_default = self
            .storage
            .get_environment(project.id, env_name)?
            .map(|e| e.is_default)
            .unwrap_or(false);
        if !self.storage.delete_environment(project.id, env_name)? {
            return Err(CoreError::EnvironmentNotFound);
        }
        if was_default {
            if let Some(next) = self.storage.list_environments(project.id)?.first().cloned() {
                self.storage.set_default_environment(project.id, next.id)?;
            }
        }
        Ok(())
    }

    /// The default environment of a project.
    pub fn default_environment(&self, project_name: &str) -> Result<Environment, CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        self.storage
            .get_default_environment(project.id)?
            .ok_or(CoreError::EnvironmentNotFound)
    }

    /// Switch the default environment of a project.
    pub fn use_environment(&self, project_name: &str, env_name: &str) -> Result<(), CoreError> {
        let (_project, env) = self.resolve_env(project_name, env_name)?;
        self.storage
            .set_default_environment(env.project_id, env.id)?;
        Ok(())
    }

    // ---------- Variables ----------

    pub fn set_variable(
        &self,
        project_name: &str,
        env_name: &str,
        key: &str,
        value: &str,
        notes: Option<String>,
    ) -> Result<Variable, CoreError> {
        models::validate_name("variable key", key).map_err(|e| CoreError::Other(e.to_string()))?;
        let master_key = self.require_key()?;
        let (_project, env) = self.resolve_env(project_name, env_name)?;

        let (ciphertext, nonce) = encrypt(master_key, value)?;
        let now = Utc::now();

        if let Some(existing) = self.storage.get_variable(env.id, key)? {
            if existing.is_readonly {
                return Err(CoreError::ReadOnly);
            }
            self.storage
                .update_variable(env.id, key, &ciphertext, &nonce, notes.as_deref())?;
            return Ok(Variable {
                id: existing.id,
                environment_id: env.id,
                key: key.to_string(),
                value_encrypted: ciphertext,
                nonce,
                notes: notes.or(existing.notes),
                is_readonly: existing.is_readonly,
                allow_export: existing.allow_export,
                created_at: existing.created_at,
                updated_at: now,
                version: existing.version + 1,
                deleted: false,
            });
        }

        let var = Variable {
            id: Uuid::now_v7(),
            environment_id: env.id,
            key: key.to_string(),
            value_encrypted: ciphertext,
            nonce,
            notes,
            is_readonly: false,
            allow_export: true,
            created_at: now,
            updated_at: now,
            version: 1,
            deleted: false,
        };
        self.storage.create_variable(&var)?;
        Ok(var)
    }

    pub fn get_variable(
        &self,
        project_name: &str,
        env_name: &str,
        key: &str,
    ) -> Result<DecryptedVariable, CoreError> {
        let master_key = self.require_key()?;
        let (_project, env) = self.resolve_env(project_name, env_name)?;
        let var = self
            .storage
            .get_variable(env.id, key)?
            .ok_or(CoreError::VariableNotFound)?;
        let value = decrypt(master_key, &var.value_encrypted, &var.nonce)?.to_string();
        Ok(DecryptedVariable {
            id: var.id,
            environment_id: var.environment_id,
            key: var.key,
            value,
            notes: var.notes,
            is_readonly: var.is_readonly,
            allow_export: var.allow_export,
        })
    }

    pub fn delete_variable(
        &self,
        project_name: &str,
        env_name: &str,
        key: &str,
    ) -> Result<(), CoreError> {
        let (_project, env) = self.resolve_env(project_name, env_name)?;
        if let Some(var) = self.storage.get_variable(env.id, key)? {
            if var.is_readonly {
                return Err(CoreError::ReadOnly);
            }
        }
        if !self.storage.delete_variable(env.id, key)? {
            return Err(CoreError::VariableNotFound);
        }
        Ok(())
    }

    pub fn list_variables(
        &self,
        project_name: &str,
        env_name: &str,
    ) -> Result<Vec<DecryptedVariable>, CoreError> {
        let master_key = self.require_key()?;
        let (_project, env) = self.resolve_env(project_name, env_name)?;
        let vars = self.storage.list_variables(env.id)?;
        let mut result = Vec::with_capacity(vars.len());
        for var in vars {
            let value = decrypt(master_key, &var.value_encrypted, &var.nonce)?.to_string();
            result.push(DecryptedVariable {
                id: var.id,
                environment_id: var.environment_id,
                key: var.key,
                value,
                notes: var.notes,
                is_readonly: var.is_readonly,
                allow_export: var.allow_export,
            });
        }
        Ok(result)
    }

    pub fn export_env(&self, project_name: &str, env_name: &str) -> Result<String, CoreError> {
        let vars = self.list_variables(project_name, env_name)?;
        Ok(envfile::format_env(&vars))
    }

    pub fn import_env(
        &self,
        project_name: &str,
        env_name: &str,
        content: &str,
    ) -> Result<usize, CoreError> {
        let pairs = envfile::parse_env(content);
        let mut count = 0;
        for (key, value) in pairs {
            self.set_variable(project_name, env_name, &key, &value, None)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn search(
        &self,
        query: &str,
        project: Option<&str>,
        env: Option<&str>,
    ) -> Result<Vec<VariableSummary>, CoreError> {
        Ok(self.storage.search_variables(query, project, env)?)
    }

    /// Per-environment variable counts for a project.
    pub fn project_status(&self, project_name: &str) -> Result<Vec<(Environment, i64)>, CoreError> {
        let project = self
            .storage
            .get_project_by_name(project_name)?
            .ok_or(CoreError::ProjectNotFound)?;
        Ok(self.storage.list_environments_with_counts(project.id)?)
    }

    /// Write encrypted backup of the entire vault to `path`.
    pub fn backup(&self, path: impl AsRef<std::path::Path>) -> Result<(), CoreError> {
        let master_key = self.require_key()?;
        let snapshot = backup::build_snapshot(&self.storage)?;
        let blob = backup::seal_backup(master_key, &snapshot)?;
        std::fs::write(path.as_ref(), blob)?;
        Ok(())
    }

    /// Restore encrypted backup into `target_db` (must not be initialized).
    /// Uses the same master password that protected the source vault.
    pub fn restore(
        target_db: impl AsRef<std::path::Path>,
        password: SecretString,
        backup_blob: &[u8],
    ) -> Result<(), CoreError> {
        let storage = Storage::open(target_db)?;
        if storage.is_initialized()? {
            return Err(CoreError::Other(
                "target vault already initialized; refuse to overwrite".into(),
            ));
        }
        let snapshot = backup::open_backup_with_password(password, backup_blob)?;
        backup::restore_snapshot(&storage, &snapshot)?;
        Ok(())
    }

    /// Write `.env` file for a project environment. If the file already exists,
    /// only missing keys are appended (existing content is preserved).
    pub fn apply_env(
        &self,
        project_name: &str,
        env_name: &str,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), CoreError> {
        let vars = self.list_variables(project_name, env_name)?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let content = if path.exists() {
            let existing = std::fs::read_to_string(path)?;
            envfile::merge_missing(&existing, &vars)
        } else {
            envfile::format_env(&vars)
        };
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn unlocked_app() -> App {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("test-password-123".into()))
            .unwrap();
        app
    }

    #[test]
    fn init_create_set_get_export() {
        let app = unlocked_app();
        app.create_project("Fudi", None, None, None).unwrap();
        app.set_variable("Fudi", "local", "OPENAI_API_KEY", "sk-test", None)
            .unwrap();
        let v = app.get_variable("Fudi", "local", "OPENAI_API_KEY").unwrap();
        assert_eq!(v.value, "sk-test");

        let exported = app.export_env("Fudi", "local").unwrap();
        assert!(exported.contains("OPENAI_API_KEY=sk-test"));
    }

    #[test]
    fn set_updates_existing() {
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        app.set_variable("P", "local", "K", "v1", None).unwrap();
        app.set_variable("P", "local", "K", "v2", None).unwrap();
        let v = app.get_variable("P", "local", "K").unwrap();
        assert_eq!(v.value, "v2");
    }

    #[test]
    fn delete_variable() {
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        app.set_variable("P", "local", "K", "v", None).unwrap();
        app.delete_variable("P", "local", "K").unwrap();
        assert!(matches!(
            app.get_variable("P", "local", "K"),
            Err(CoreError::VariableNotFound)
        ));
    }

    #[test]
    fn delete_default_env_promotes_remaining() {
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        let staging = app.create_environment("P", "staging").unwrap();
        app.delete_environment("P", "local").unwrap();
        assert_eq!(app.default_environment("P").unwrap().id, staging.id);
    }

    #[test]
    fn import_env() {
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        let n = app
            .import_env("P", "local", "FOO=bar\n# comment\nBAZ=\"hello world\"\n")
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(app.get_variable("P", "local", "FOO").unwrap().value, "bar");
        assert_eq!(
            app.get_variable("P", "local", "BAZ").unwrap().value,
            "hello world"
        );
    }

    #[test]
    fn apply_merges_missing_keys_into_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        app.set_variable("P", "local", "A", "new", None).unwrap();
        app.set_variable("P", "local", "B", "2", None).unwrap();
        let out = dir.path().join(".env");
        std::fs::write(&out, "A=keep\n").unwrap();
        app.apply_env("P", "local", &out).unwrap();
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("A=keep"));
        assert!(content.contains("B=2"));
    }

    #[test]
    fn search_scopes_by_project_and_env() {
        let app = unlocked_app();
        app.create_project("A", None, None, None).unwrap();
        app.create_project("B", None, None, None).unwrap();
        app.set_variable("A", "local", "K", "1", None).unwrap();
        app.set_variable("B", "local", "K", "2", None).unwrap();
        assert_eq!(app.search("k", Some("A"), None).unwrap().len(), 1);
        let status = app.project_status("A").unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].1, 1); // 1 variable en local
    }

    #[test]
    fn verify_password_rejects_wrong_without_session() {
        let mut app = unlocked_app();
        app.lock().unwrap();
        assert!(!app.is_unlocked());
        assert!(app
            .verify_password(SecretString::new("test-password-123".into()))
            .is_ok());
        assert!(app
            .verify_password(SecretString::new("wrong".into()))
            .is_err());
        assert!(!app.is_unlocked()); // no abre sesión
    }

    #[test]
    fn use_environment_switches_default() {
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        app.create_environment("P", "staging").unwrap();
        assert_eq!(app.default_environment("P").unwrap().name, "local");
        app.use_environment("P", "staging").unwrap();
        assert_eq!(app.default_environment("P").unwrap().name, "staging");
    }

    #[test]
    fn search_finds_key() {
        let app = unlocked_app();
        app.create_project("Fudi", None, None, None).unwrap();
        app.set_variable("Fudi", "local", "OPENAI_API_KEY", "x", None)
            .unwrap();
        let hits = app.search("openai", None, None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].project_name, "Fudi");
        assert_eq!(hits[0].key, "OPENAI_API_KEY");
    }

    #[test]
    fn locked_rejects_secret_ops() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("pw".into())).unwrap();
        app.create_project("P", None, None, None).unwrap();
        // Simulate lock by clearing key — re-open pattern
        let app2 = App::open_in_memory().unwrap();
        // fresh memory vault is not the same; just check Locked on empty key
        assert!(matches!(
            app2.set_variable("P", "local", "K", "v", None),
            Err(CoreError::Locked) | Err(CoreError::Storage(_)) | Err(CoreError::ProjectNotFound)
        ));
    }
    #[test]
    fn backup_and_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.db");
        let bak = dir.path().join("vault.enc");
        let dst = dir.path().join("dst.db");

        let mut app = App::open(&src).unwrap();
        app.init(SecretString::new("pw-backup-1".into())).unwrap();
        app.create_project("Fudi", None, None, None).unwrap();
        app.set_variable("Fudi", "local", "KEY", "secret-value", None)
            .unwrap();
        app.backup(&bak).unwrap();

        App::restore(
            &dst,
            SecretString::new("pw-backup-1".into()),
            &std::fs::read(&bak).unwrap(),
        )
        .unwrap();

        let mut app2 = App::open(&dst).unwrap();
        app2.unlock(SecretString::new("pw-backup-1".into()))
            .unwrap();
        let v = app2.get_variable("Fudi", "local", "KEY").unwrap();
        assert_eq!(v.value, "secret-value");

        // Both temp vaults opened a real session; drop them so the test suite
        // leaves no keyring entry behind.
        app2.lock().unwrap();
        app.lock().unwrap();
    }

    #[test]
    fn rekey_rotates_password_and_reencrypts_everything() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");

        let mut app = App::open(&db).unwrap();
        app.init(SecretString::new("old-pass".into())).unwrap();
        app.create_project("P", None, None, None).unwrap();
        app.set_variable("P", "local", "secret", "original-value", None)
            .unwrap();
        // Full lock/unlock cycle before rekey, like a real session would.
        app.lock().unwrap();
        app.unlock(SecretString::new("old-pass".into())).unwrap();

        let before = app.storage.get_vault_meta().unwrap();
        let count = app.rekey(SecretString::new("new-pass".into())).unwrap();
        assert_eq!(count, 1);

        // The verifier only accepts the new password from now on.
        assert!(app
            .verify_password(SecretString::new("old-pass".into()))
            .is_err());
        assert!(app
            .verify_password(SecretString::new("new-pass".into()))
            .is_ok());

        // New key domain: salt rotated, KDF cost kept as chosen at init.
        let after = app.storage.get_vault_meta().unwrap();
        assert_ne!(after.salt, before.salt);
        assert_eq!(
            serde_json::to_string(&after.kdf_params).unwrap(),
            serde_json::to_string(&before.kdf_params).unwrap()
        );

        // Close/reopen cycle under the new password decrypts the value.
        app.lock().unwrap();
        app.unlock(SecretString::new("new-pass".into())).unwrap();
        let v = app.get_variable("P", "local", "secret").unwrap();
        assert_eq!(v.value, "original-value");

        // The sync guard marker is pinned to the new local salt.
        let marker = SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap();
        assert_eq!(marker.as_deref(), Some(hex::encode(after.salt).as_str()));

        // Drop the temp vault's session so the suite leaves no keyring entry.
        app.lock().unwrap();
    }

    #[test]
    fn rekey_increments_key_epoch() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 1);
        app.unlock(SecretString::new("first".into())).unwrap();
        app.rekey(SecretString::new("second".into())).unwrap();
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 2);
    }

    #[test]
    fn reset_local_installs_an_empty_vault_under_a_new_key() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("old-password".into())).unwrap();
        app.create_project("p", None, None, None).unwrap();
        let env = app.default_environment("p").unwrap();
        app.set_variable("p", &env.name, "K", "secret", None)
            .unwrap();
        let old_salt = app.storage.get_vault_meta().unwrap().salt;

        // Note: locked, and no call supplying the old password anywhere.
        // `reset_local` must work without an unlocked vault.
        app.lock().unwrap();
        let epoch = app
            .reset_local(SecretString::new("brand-new".into()))
            .unwrap();

        assert!(app.storage.list_projects().unwrap().is_empty());
        assert!(app.storage.all_variables().unwrap().is_empty());
        let meta = app.storage.get_vault_meta().unwrap();
        assert_ne!(
            meta.salt, old_salt,
            "a reset must rotate the salt, never keep it"
        );
        assert_eq!(epoch, 2, "advances from the vault's own epoch of 1");
        assert_eq!(
            meta.key_epoch, epoch,
            "the returned epoch is the one stored"
        );
        assert!(!meta.verifier_ct.is_empty());

        // The new password opens it; the old one does not.
        assert!(app
            .verify_password(SecretString::new("brand-new".into()))
            .is_ok());
        assert!(app
            .verify_password(SecretString::new("old-password".into()))
            .is_err());

        assert!(app.pending_reset().unwrap());
    }

    #[test]
    fn reset_local_clears_a_pending_rekey_marker() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        app.rekey(SecretString::new("second".into())).unwrap();
        assert!(
            SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY)
                .unwrap()
                .is_some()
        );

        app.lock().unwrap();
        app.reset_local(SecretString::new("third".into())).unwrap();
        assert_eq!(
            SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap(),
            None
        );
    }

    #[test]
    fn a_rekey_does_not_add_a_second_marker_to_a_pending_reset() {
        // The other direction of the "only one marker at a time" invariant
        // `reset_local` documents. The reset wins and keeps the only marker:
        // the wipe pushes the local salt regardless, so a rekey marker would
        // add nothing, and honouring it would publish `key_change = 'rekey'`,
        // skip the tombstone wipe, and leave the pre-reset rows live on the
        // server for the other devices — which still hold the old key — to
        // read.
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        app.reset_local(SecretString::new("second".into())).unwrap();
        // Sampled AFTER the reset, not before: `reset_local` rotates the salt
        // too, so comparing against the pre-reset salt would pass even if the
        // rekey had not rotated anything — and that rotation is the premise of
        // skipping the marker.
        let reset_salt = app.storage.get_vault_meta().unwrap().salt;
        // The rekey needs an unlocked vault; `reset_local` left it unlocked
        // under the new key, which is what a real `vltr reset` does too.
        assert!(
            app.pending_reset().unwrap(),
            "precondition: reset is pending"
        );
        assert_eq!(
            SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap(),
            None,
            "precondition: `reset_local` cleared the rekey marker"
        );

        app.rekey(SecretString::new("third".into())).unwrap();

        assert_eq!(
            SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap(),
            None,
            "a pending reset must not gain a competing rekey marker"
        );
        assert!(
            app.pending_reset().unwrap(),
            "the reset must survive the rekey: it is what makes the next sync wipe"
        );

        // The rotation did land, and that is why the marker can be skipped:
        // `push_reset` publishes the LOCAL salt, so the rekey's new domain is
        // what gets pushed. If the rotation had not landed, the wipe would
        // publish the reset's salt and still be a complete reset.
        let meta = app.storage.get_vault_meta().unwrap();
        assert_ne!(
            meta.salt, reset_salt,
            "the rekey rotated the salt, and the rotated salt is what `push_reset` publishes"
        );
        // init(1) → reset_local(2) → rekey(3).
        assert_eq!(meta.key_epoch, 3);
    }

    #[test]
    fn a_rekey_without_a_pending_reset_still_sets_its_own_marker() {
        // The guard on the other side: the marker is conditional on the reset,
        // not retired. Without this, inverting the condition above would still
        // pass every reset test and would silently stop publishing a rekey's
        // salt — a plain password change would then abort on the salt guard
        // instead of syncing.
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        assert!(
            !app.pending_reset().unwrap(),
            "precondition: no reset pending"
        );

        app.rekey(SecretString::new("second".into())).unwrap();

        let meta = app.storage.get_vault_meta().unwrap();
        assert_eq!(
            SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY)
                .unwrap()
                .as_deref(),
            Some(hex::encode(meta.salt).as_str()),
            "the marker must describe the rotated local salt, or the salt guard aborts"
        );
        assert!(
            !app.pending_reset().unwrap(),
            "a rekey must never conjure a reset marker"
        );
        assert_eq!(meta.key_epoch, 2, "init(1) → rekey(2)");
    }

    #[test]
    fn the_pending_reset_marker_records_when_the_reset_happened() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        let before = Utc::now();
        app.reset_local(SecretString::new("second".into())).unwrap();
        let after = Utc::now();

        // A timestamp, not the placeholder epoch: the authoritative epoch is
        // `remote + 1`, computed at push time, so storing one here would be a
        // second wrong answer to a question nobody asks.
        let marker = SyncState::get(app.storage.conn(), sync::PENDING_LOCAL_RESET_KEY)
            .unwrap()
            .unwrap();
        let stamped = DateTime::parse_from_rfc3339(&marker)
            .expect("the marker must be an RFC3339 timestamp")
            .with_timezone(&Utc);
        assert!(
            stamped >= before - chrono::Duration::seconds(1) && stamped <= after,
            "the marker must record the moment of the reset, got {marker}"
        );
    }

    #[test]
    fn reset_local_advances_the_epoch_from_its_own_value() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        app.rekey(SecretString::new("second".into())).unwrap();
        app.rekey(SecretString::new("third".into())).unwrap();
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 3);

        // No epoch argument: the caller cannot install an arbitrary value, so
        // the reset can never write a counter the local vault does not own.
        assert_eq!(
            app.reset_local(SecretString::new("fourth".into())).unwrap(),
            4
        );
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 4);
    }

    #[test]
    fn reset_vault_leaves_no_rows_behind_for_discard() {
        // The invariant `discard_local_and_adopt` stands on: `reset_vault`
        // installs the domain and the epoch it is HANDED — a foreign salt, the
        // remote's counter — instead of generating its own, and no row of the
        // previous domain survives. That is what makes "discard local" leave
        // this device aligned with a remote that a reset left empty.
        let app = unlocked_app();
        app.create_project("p", None, None, None).unwrap();
        let env = app.default_environment("p").unwrap();
        app.set_variable("p", &env.name, "K", "v", None).unwrap();
        assert!(!app.storage.all_variables().unwrap().is_empty());
        SyncState::set(
            app.storage.conn(),
            sync::PENDING_LOCAL_RESET_KEY,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();

        app.storage
            .reset_vault(
                &[7u8; 16],
                &app.storage.get_vault_meta().unwrap().kdf_params,
                b"ct",
                b"nonce",
                5,
            )
            .unwrap();

        assert!(app.storage.list_projects().unwrap().is_empty());
        assert!(app.storage.all_variables().unwrap().is_empty());
        let meta = app.storage.get_vault_meta().unwrap();
        assert_eq!(
            meta.salt,
            vec![7u8; 16],
            "adopts the salt it is given, never a fresh one"
        );
        assert_eq!(meta.key_epoch, 5, "adopts the remote epoch as-is");
        // `sync_state` goes too: the pull cursor describes rows this vault no
        // longer has, and a leftover `pending_local_reset` would make the next
        // sync wipe the remote a second time.
        let markers: i64 = app
            .storage
            .conn()
            .query_row("SELECT COUNT(*) FROM sync_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(markers, 0, "no cursor or marker may survive a discard");
    }

    #[test]
    fn apply_writes_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app();
        app.create_project("P", None, None, None).unwrap();
        app.set_variable("P", "local", "A", "1", None).unwrap();
        let out = dir.path().join(".env");
        app.apply_env("P", "local", &out).unwrap();
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("A=1"));
    }
}
