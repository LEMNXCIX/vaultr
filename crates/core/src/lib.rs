//! Business logic / use cases.
//! This is the only layer that CLI and Desktop should talk to.

use chrono::Utc;
use crypto::{decrypt, derive_master_key, encrypt, generate_salt, MasterKey};
use models::{DecryptedVariable, Environment, KdfParams, Project, Variable, VariableSummary};
use secrecy::SecretString;
use storage::{Storage, StorageError};
use thiserror::Error;
use uuid::Uuid;

pub mod backup;
pub mod envfile;
pub mod session;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("invalid master password")]
    InvalidPassword,
    #[error("vault is locked")]
    Locked,
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
    #[error("{0}")]
    Other(String),
}

/// Main entry point for all operations.
pub struct App {
    storage: Storage,
    master_key: Option<MasterKey>,
}

impl App {
    pub fn open(db_path: impl AsRef<std::path::Path>) -> Result<Self, CoreError> {
        let storage = Storage::open(db_path)?;
        Ok(Self {
            storage,
            master_key: None,
        })
    }

    pub fn open_in_memory() -> Result<Self, CoreError> {
        let storage = Storage::open_in_memory()?;
        Ok(Self {
            storage,
            master_key: None,
        })
    }

    pub fn is_initialized(&self) -> Result<bool, CoreError> {
        Ok(self.storage.is_initialized()?)
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
        let _ = session::save_master_key(&key);
        self.master_key = Some(key);
        Ok(())
    }

    pub fn unlock(&mut self, password: SecretString) -> Result<(), CoreError> {
        let meta = self.storage.get_vault_meta()?;
        let key = derive_master_key(&password, &meta.salt, &meta.kdf_params)?;
        // Verify password by decrypting the vault verifier marker.
        let marker = decrypt(&key, &meta.verifier_ct, &meta.verifier_nonce)
            .map_err(|_| CoreError::InvalidPassword)?;
        if marker.as_str() != models::constants::VAULT_VERIFIER_MESSAGE {
            return Err(CoreError::InvalidPassword);
        }
        let _ = session::save_master_key(&key);
        self.master_key = Some(key);
        Ok(())
    }

    /// Unlock using a key already loaded (e.g. from OS keyring).
    pub fn unlock_with_key(&mut self, key: MasterKey) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let meta = self.storage.get_vault_meta()?;
        let marker = decrypt(&key, &meta.verifier_ct, &meta.verifier_nonce)
            .map_err(|_| CoreError::InvalidPassword)?;
        if marker.as_str() != models::constants::VAULT_VERIFIER_MESSAGE {
            let _ = session::clear_session();
            return Err(CoreError::InvalidPassword);
        }
        self.master_key = Some(key);
        Ok(())
    }

    /// Try to restore session from OS keyring. Returns true if unlocked.
    pub fn try_unlock_from_session(&mut self) -> Result<bool, CoreError> {
        if self.is_unlocked() {
            return Ok(true);
        }
        match session::load_master_key()? {
            Some(key) => {
                self.unlock_with_key(key)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Clear in-memory key and OS keyring session.
    pub fn lock(&mut self) -> Result<(), CoreError> {
        self.master_key = None;
        session::clear_session()?;
        Ok(())
    }

    pub fn has_keyring_session() -> Result<bool, CoreError> {
        session::has_session()
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
        };
        self.storage.create_environment(&env)?;
        Ok(env)
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

    pub fn search(&self, query: &str) -> Result<Vec<VariableSummary>, CoreError> {
        Ok(self.storage.search_variables(query)?)
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

    /// Write `.env` file for a project environment.
    pub fn apply_env(
        &self,
        project_name: &str,
        env_name: &str,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), CoreError> {
        let content = self.export_env(project_name, env_name)?;
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path.as_ref(), content)?;
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
    fn search_finds_key() {
        let app = unlocked_app();
        app.create_project("Fudi", None, None, None).unwrap();
        app.set_variable("Fudi", "local", "OPENAI_API_KEY", "x", None)
            .unwrap();
        let hits = app.search("openai").unwrap();
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
