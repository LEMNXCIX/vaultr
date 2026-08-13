//! Local SQLite storage layer.
//! The only place that knows about the database schema.

use chrono::{DateTime, Utc};
use models::{Environment, Id, KdfParams, Project, Variable, VariableSummary, VaultMeta};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

pub mod migrations;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("vault not initialized")]
    NotInitialized,
    #[error("vault already initialized")]
    AlreadyInitialized,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        let storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> Result<(), StorageError> {
        migrations::run(&self.conn)
    }

    /// Current schema migration version (0 if empty).
    pub fn schema_version(&self) -> Result<i64, StorageError> {
        migrations::current_version(&self.conn)
    }

    // ---------- Vault meta ----------

    pub fn is_initialized(&self) -> Result<bool, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM vault_meta", [], |r| r.get(0))?;
        Ok(count > 0)
    }

    pub fn init_vault(
        &self,
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
    ) -> Result<(), StorageError> {
        if self.is_initialized()? {
            return Err(StorageError::AlreadyInitialized);
        }
        let now = Utc::now().to_rfc3339();
        let params_json = serde_json::to_string(kdf_params)?;
        self.conn.execute(
            "INSERT INTO vault_meta (id, salt, kdf_params, verifier_ct, verifier_nonce, created_at, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?5)",
            params![salt, params_json, verifier_ct, verifier_nonce, now],
        )?;
        Ok(())
    }

    pub fn get_vault_meta(&self) -> Result<VaultMeta, StorageError> {
        self.conn
            .query_row(
                "SELECT salt, kdf_params, verifier_ct, verifier_nonce, created_at, updated_at
                 FROM vault_meta WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(salt, params_json, verifier_ct, verifier_nonce, created, updated)| -> Result<VaultMeta, StorageError> {
                    let kdf_params: KdfParams = serde_json::from_str(&params_json)?;
                    Ok(VaultMeta {
                        salt,
                        kdf_params,
                        verifier_ct,
                        verifier_nonce,
                        created_at: parse_dt(&created),
                        updated_at: parse_dt(&updated),
                    })
                },
            )
            .transpose()?
            .ok_or(StorageError::NotInitialized)
    }

    // ---------- Projects ----------

    pub fn create_project(&self, project: &Project) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO projects (id, name, description, color, icon, created_at, updated_at, owner_id, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                project.id.to_string(),
                project.name,
                project.description,
                project.color,
                project.icon,
                project.created_at.to_rfc3339(),
                project.updated_at.to_rfc3339(),
                project.owner_id,
                project.version,
            ],
        )?;
        Ok(())
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version
             FROM projects ORDER BY name",
        )?;
        let rows = stmt.query_map([], map_project)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_project_by_name(&self, name: &str) -> Result<Option<Project>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version
                 FROM projects WHERE name = ?1",
                params![name],
                map_project,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn delete_project(&self, name: &str) -> Result<bool, StorageError> {
        let n = self
            .conn
            .execute("DELETE FROM projects WHERE name = ?1", params![name])?;
        Ok(n > 0)
    }

    // ---------- Environments ----------

    pub fn create_environment(&self, env: &Environment) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO environments (id, project_id, name, is_default, sort_order, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                env.id.to_string(),
                env.project_id.to_string(),
                env.name,
                env.is_default as i32,
                env.sort_order,
                env.created_at.to_rfc3339(),
                env.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_environments(&self, project_id: Id) -> Result<Vec<Environment>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at
             FROM environments WHERE project_id = ?1 ORDER BY sort_order, name",
        )?;
        let rows = stmt.query_map(params![project_id.to_string()], map_environment)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_environment(
        &self,
        project_id: Id,
        env_name: &str,
    ) -> Result<Option<Environment>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at
                 FROM environments WHERE project_id = ?1 AND name = ?2",
                params![project_id.to_string(), env_name],
                map_environment,
            )
            .optional()
            .map_err(Into::into)
    }

    // ---------- Variables ----------

    pub fn create_variable(&self, var: &Variable) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO variables
             (id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                var.id.to_string(),
                var.environment_id.to_string(),
                var.key,
                var.value_encrypted,
                var.nonce,
                var.notes,
                var.is_readonly as i32,
                var.allow_export as i32,
                var.created_at.to_rfc3339(),
                var.updated_at.to_rfc3339(),
                var.version,
            ],
        )?;
        Ok(())
    }

    pub fn update_variable(
        &self,
        environment_id: Id,
        key: &str,
        value_encrypted: &[u8],
        nonce: &[u8],
        notes: Option<&str>,
    ) -> Result<bool, StorageError> {
        let now = Utc::now().to_rfc3339();
        let n = self.conn.execute(
            "UPDATE variables SET value_encrypted = ?1, nonce = ?2, notes = COALESCE(?3, notes),
             updated_at = ?4, version = version + 1
             WHERE environment_id = ?5 AND key = ?6",
            params![
                value_encrypted,
                nonce,
                notes,
                now,
                environment_id.to_string(),
                key
            ],
        )?;
        Ok(n > 0)
    }

    pub fn delete_variable(&self, environment_id: Id, key: &str) -> Result<bool, StorageError> {
        let n = self.conn.execute(
            "DELETE FROM variables WHERE environment_id = ?1 AND key = ?2",
            params![environment_id.to_string(), key],
        )?;
        Ok(n > 0)
    }

    pub fn get_variable(
        &self,
        environment_id: Id,
        key: &str,
    ) -> Result<Option<Variable>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version
                 FROM variables WHERE environment_id = ?1 AND key = ?2",
                params![environment_id.to_string(), key],
                map_variable,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_variables(&self, environment_id: Id) -> Result<Vec<Variable>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version
             FROM variables WHERE environment_id = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![environment_id.to_string()], map_variable)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Search variable keys (and optional notes) across all projects.
    pub fn search_variables(&self, query: &str) -> Result<Vec<VariableSummary>, StorageError> {
        let pattern = format!("%{}%", query.to_lowercase());
        let mut stmt = self.conn.prepare(
            "SELECT v.id, p.id, p.name, e.id, e.name, v.key, v.notes, v.is_readonly, v.allow_export, v.updated_at
             FROM variables v
             JOIN environments e ON e.id = v.environment_id
             JOIN projects p ON p.id = e.project_id
             WHERE lower(v.key) LIKE ?1 OR lower(COALESCE(v.notes, '')) LIKE ?1
             ORDER BY p.name, e.name, v.key",
        )?;
        let rows = stmt.query_map(params![pattern], |row| {
            Ok(VariableSummary {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                project_id: Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                project_name: row.get(2)?,
                environment_id: Uuid::parse_str(&row.get::<_, String>(3)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                environment_name: row.get(4)?,
                key: row.get(5)?,
                notes: row.get(6)?,
                is_readonly: row.get::<_, i32>(7)? != 0,
                allow_export: row.get::<_, i32>(8)? != 0,
                updated_at: parse_dt(&row.get::<_, String>(9)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn map_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: parse_uuid(&row.get::<_, String>(0)?)?,
        name: row.get(1)?,
        description: row.get(2)?,
        color: row.get(3)?,
        icon: row.get(4)?,
        created_at: parse_dt(&row.get::<_, String>(5)?),
        updated_at: parse_dt(&row.get::<_, String>(6)?),
        owner_id: row.get(7)?,
        version: row.get(8)?,
    })
}

fn map_environment(row: &rusqlite::Row<'_>) -> rusqlite::Result<Environment> {
    Ok(Environment {
        id: parse_uuid(&row.get::<_, String>(0)?)?,
        project_id: parse_uuid(&row.get::<_, String>(1)?)?,
        name: row.get(2)?,
        is_default: row.get::<_, i32>(3)? != 0,
        sort_order: row.get(4)?,
        created_at: parse_dt(&row.get::<_, String>(5)?),
        updated_at: parse_dt(&row.get::<_, String>(6)?),
    })
}

fn map_variable(row: &rusqlite::Row<'_>) -> rusqlite::Result<Variable> {
    Ok(Variable {
        id: parse_uuid(&row.get::<_, String>(0)?)?,
        environment_id: parse_uuid(&row.get::<_, String>(1)?)?,
        key: row.get(2)?,
        value_encrypted: row.get(3)?,
        nonce: row.get(4)?,
        notes: row.get(5)?,
        is_readonly: row.get::<_, i32>(6)? != 0,
        allow_export: row.get::<_, i32>(7)? != 0,
        created_at: parse_dt(&row.get::<_, String>(8)?),
        updated_at: parse_dt(&row.get::<_, String>(9)?),
        version: row.get(10)?,
    })
}

fn parse_uuid(s: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

pub fn default_db_path() -> PathBuf {
    use models::constants::{APP_NAME, APP_ORGANIZATION, APP_QUALIFIER};
    let base = directories::ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME)
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("vault.db")
}

/// Move a vault created before the application was renamed to Vaultr.
///
/// The migration is deliberately conservative: it never replaces a vault that
/// already exists at the new location.
pub fn migrate_legacy_db(target: &Path) -> Result<bool, StorageError> {
    use models::constants::{APP_QUALIFIER, LEGACY_APP_NAME, LEGACY_APP_ORGANIZATION};

    let Some(legacy_dirs) =
        directories::ProjectDirs::from(APP_QUALIFIER, LEGACY_APP_ORGANIZATION, LEGACY_APP_NAME)
    else {
        return Ok(false);
    };
    let legacy = legacy_dirs.data_dir().join("vault.db");
    migrate_vault_path(&legacy, target)
}

fn migrate_vault_path(legacy: &Path, target: &Path) -> Result<bool, StorageError> {
    if target.exists() || !legacy.exists() {
        return Ok(false);
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(legacy, target)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::KdfParams;

    #[test]
    fn init_and_project_roundtrip() {
        let s = Storage::open_in_memory().unwrap();
        assert!(!s.is_initialized().unwrap());
        s.init_vault(&[1u8; 16], &KdfParams::default(), b"ct", b"nonce")
            .unwrap();
        assert!(s.is_initialized().unwrap());

        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "Fudi".into(),
            description: Some("demo".into()),
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
        };
        s.create_project(&p).unwrap();
        let found = s.get_project_by_name("Fudi").unwrap().unwrap();
        assert_eq!(found.name, "Fudi");
    }

    #[test]
    fn legacy_vault_migrates_without_overwriting_target() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("secrets-manager/vault.db");
        let target = dir.path().join("vaultr/vault.db");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, b"vault").unwrap();

        assert!(migrate_vault_path(&legacy, &target).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"vault");

        std::fs::write(&legacy, b"legacy").unwrap();
        assert!(!migrate_vault_path(&legacy, &target).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"vault");
    }
}
