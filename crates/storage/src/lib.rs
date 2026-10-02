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

/// Tables that participate in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTable {
    Projects,
    Environments,
    Variables,
}

impl SyncTable {
    fn table_name(self) -> &'static str {
        match self {
            SyncTable::Projects => "projects",
            SyncTable::Environments => "environments",
            SyncTable::Variables => "variables",
        }
    }
}

/// Key/value store for sync cursors (e.g. `last_pull`), backed by `sync_state`.
pub struct SyncState;

impl SyncState {
    pub fn get(conn: &Connection, key: &str) -> Result<Option<String>, StorageError> {
        Ok(conn
            .query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set(conn: &Connection, key: &str, value: &str) -> Result<(), StorageError> {
        conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Remove a key (no-op when absent); e.g. clearing the rekey marker.
    pub fn remove(conn: &Connection, key: &str) -> Result<(), StorageError> {
        conn.execute("DELETE FROM sync_state WHERE key = ?1", params![key])?;
        Ok(())
    }
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
                "SELECT salt, kdf_params, verifier_ct, verifier_nonce, key_epoch, created_at, updated_at
                 FROM vault_meta WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(salt, params_json, verifier_ct, verifier_nonce, key_epoch, created, updated)| -> Result<VaultMeta, StorageError> {
                    let kdf_params: KdfParams = serde_json::from_str(&params_json)?;
                    Ok(VaultMeta {
                        salt,
                        kdf_params,
                        verifier_ct,
                        verifier_nonce,
                        key_epoch,
                        created_at: parse_dt(&created),
                        updated_at: parse_dt(&updated),
                    })
                },
            )
            .transpose()?
            .ok_or(StorageError::NotInitialized)
    }

    /// Atomically rotate the vault's key material (used by `rekey` and by
    /// adoption of a remote key): swap the ciphertext of every listed
    /// variable AND update `vault_meta` (salt, kdf params, verifier) in ONE
    /// transaction — all of it applies or none of it does.
    ///
    /// `updated_at` and `version` are deliberately untouched: a mere key
    /// rotation must never win (or lose) an LWW comparison against genuinely
    /// newer edits from other devices. `synced_at` is cleared so each row
    /// re-enters the dirty set (`synced_at IS NULL OR updated_at > synced_at`)
    /// and the new ciphertext propagates on the next push.
    ///
    /// Load-bearing for sync: every key-epoch bump today also rotates the
    /// salt (`rekey` generates a fresh salt; remote-key adoption copies the
    /// remote one), so salt-equality currently implies epoch-equality. The
    /// sync verifier-backfill relies on that. A future reset flow that bumps
    /// the epoch WITHOUT rotating the salt must audit the backfill and the
    /// salt guard first.
    pub fn apply_key_rotation(
        &self,
        reencrypted: &[(Id, Vec<u8>, Vec<u8>)],
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
        key_epoch: i64,
    ) -> Result<(), StorageError> {
        self.apply_key_rotation_within(
            reencrypted,
            salt,
            kdf_params,
            verifier_ct,
            verifier_nonce,
            key_epoch,
            false,
        )
    }

    /// [`Self::apply_key_rotation`] PLUS re-queuing every project and
    /// environment for push, inside the SAME transaction.
    ///
    /// Why the adoption path needs this and a plain rekey does not. Adoption is
    /// what follows a remote **reset**, and the reset left a tombstone for
    /// every row on the server, each with a NEWER `updated_at` than anything
    /// this device holds. `apply_key_rotation` re-encrypts and re-dirties
    /// variables only, so on a device that had already synced the parents were
    /// not in the dirty set at all: the retry's push left their tombstones in
    /// place, the pull that followed won LWW against them, and
    /// `cascade_tombstones` took the children with them. The user had chosen to
    /// keep the vault and got it back flagged deleted.
    ///
    /// Re-queuing rather than editing is the point: `updated_at` and `version`
    /// stay exactly as they are, so the push replaces each tombstone by primary
    /// key (`resolution=merge-duplicates`) and the pull after it has no newer
    /// row to bring the deletion back with. A plain rekey changes neither the
    /// parents' names nor their contents, so re-pushing them would be pure
    /// waste — which is why this is a separate method rather than a flag every
    /// rotation sets. Do not fold it into `apply_key_rotation`.
    ///
    /// Same transaction as the rotation, deliberately: a rotation that landed
    /// while the parents stayed clean is the silent data loss above, and a
    /// parents-only write that landed while the rotation failed would leave
    /// rows re-encrypted under a key `vault_meta` does not describe.
    pub fn apply_key_rotation_dirtying_parents(
        &self,
        reencrypted: &[(Id, Vec<u8>, Vec<u8>)],
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
        key_epoch: i64,
    ) -> Result<(), StorageError> {
        self.apply_key_rotation_within(
            reencrypted,
            salt,
            kdf_params,
            verifier_ct,
            verifier_nonce,
            key_epoch,
            true,
        )
    }

    fn apply_key_rotation_within(
        &self,
        reencrypted: &[(Id, Vec<u8>, Vec<u8>)],
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
        key_epoch: i64,
        dirty_parents: bool,
    ) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        for (id, ciphertext, nonce) in reencrypted {
            let n = tx.execute(
                "UPDATE variables SET value_encrypted = ?1, nonce = ?2, synced_at = NULL
                 WHERE id = ?3",
                params![ciphertext, nonce, id.to_string()],
            )?;
            if n == 0 {
                // Returning drops the transaction → automatic rollback.
                return Err(StorageError::Other(format!(
                    "variable {id} disappeared during key rotation"
                )));
            }
        }
        if dirty_parents {
            // Every row, tombstoned or not: a local tombstone must overwrite
            // the remote one too, and a live one must un-tombstone it.
            tx.execute("UPDATE projects SET synced_at = NULL", [])?;
            tx.execute("UPDATE environments SET synced_at = NULL", [])?;
        }
        let params_json = serde_json::to_string(kdf_params)?;
        let updated = tx.execute(
            "UPDATE vault_meta
             SET salt = ?1, kdf_params = ?2, verifier_ct = ?3, verifier_nonce = ?4, key_epoch = ?5, updated_at = ?6
             WHERE id = 1",
            params![
                salt,
                params_json,
                verifier_ct,
                verifier_nonce,
                key_epoch,
                Utc::now().to_rfc3339()
            ],
        )?;
        if updated == 0 {
            return Err(StorageError::NotInitialized);
        }
        tx.commit()?;
        Ok(())
    }

    /// Overwrite the local key epoch. Used by the reset flow, to converge the
    /// local counter on the epoch that flow just published; the key rotation
    /// itself is `reset_vault`'s job, not this method's.
    ///
    /// See `apply_key_rotation`: salt-equality implying epoch-equality is
    /// load-bearing for the sync verifier-backfill. A caller that moves the
    /// epoch WITHOUT rotating the salt therefore breaks that lock. That audit
    /// is done, and it is written down at the `set_key_epoch` call inside
    /// `core`'s `push_reset` (crates/core/src/sync.rs): the verifier backfill
    /// needs `Proceed` AND a remote row carrying no verifier, and every reset
    /// path writes one, so it can never republish a stale epoch over this one;
    /// and the salt guard reads the epoch only inside the branch where the
    /// salts already differ, so the write is inert there. Read that comment
    /// before adding a second such caller — a reset is not a licence to skip
    /// the question, only the first case that answered it.
    pub fn set_key_epoch(&self, epoch: i64) -> Result<(), StorageError> {
        let n = self.conn.execute(
            "UPDATE vault_meta SET key_epoch = ?1, updated_at = ?2 WHERE id = 1",
            params![epoch, Utc::now().to_rfc3339()],
        )?;
        if n == 0 {
            return Err(StorageError::NotInitialized);
        }
        Ok(())
    }

    /// Destroy every row and re-install a new key domain on the single
    /// `vault_meta` row. Used by the reset flow, where the previous key is
    /// unrecoverable and its rows cannot be re-encrypted — only deleted.
    ///
    /// `sync_state` is emptied too: the cursor describes rows this vault no
    /// longer has, so carrying it over would silently skip a pull.
    pub fn reset_vault(
        &self,
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
        key_epoch: i64,
    ) -> Result<(), StorageError> {
        if !self.is_initialized()? {
            return Err(StorageError::NotInitialized);
        }
        let params_json = serde_json::to_string(kdf_params)?;
        let tx = self.conn.unchecked_transaction()?;
        // Children first: variables → environments → projects hold FKs.
        tx.execute("DELETE FROM variables", [])?;
        tx.execute("DELETE FROM environments", [])?;
        tx.execute("DELETE FROM projects", [])?;
        tx.execute("DELETE FROM sync_state", [])?;
        let n = tx.execute(
            "UPDATE vault_meta
             SET salt = ?1, kdf_params = ?2, verifier_ct = ?3, verifier_nonce = ?4,
                 key_epoch = ?5, updated_at = ?6
             WHERE id = 1",
            params![
                salt,
                params_json,
                verifier_ct,
                verifier_nonce,
                key_epoch,
                Utc::now().to_rfc3339()
            ],
        )?;
        if n == 0 {
            return Err(StorageError::NotInitialized);
        }
        tx.commit()?;
        Ok(())
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
            "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version, deleted
             FROM projects WHERE deleted = 0 ORDER BY name",
        )?;
        let rows = stmt.query_map([], map_project)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_project_by_name(&self, name: &str) -> Result<Option<Project>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version, deleted
                 FROM projects WHERE name = ?1 AND deleted = 0",
                params![name],
                map_project,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Soft delete: tombstone the row so sync can propagate it.
    pub fn delete_project(&self, name: &str) -> Result<bool, StorageError> {
        let n = self.conn.execute(
            "UPDATE projects
             SET deleted = 1, updated_at = ?2, version = version + 1
             WHERE name = ?1 AND deleted = 0",
            params![name, Utc::now().to_rfc3339()],
        )?;
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
            "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at, deleted
             FROM environments WHERE project_id = ?1 AND deleted = 0 ORDER BY sort_order, name",
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
                "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at, deleted
                 FROM environments WHERE project_id = ?1 AND name = ?2 AND deleted = 0",
                params![project_id.to_string(), env_name],
                map_environment,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_default_environment(
        &self,
        project_id: Id,
    ) -> Result<Option<Environment>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at, deleted
                 FROM environments WHERE project_id = ?1 AND is_default = 1 AND deleted = 0 LIMIT 1",
                params![project_id.to_string()],
                map_environment,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_default_environment(&self, project_id: Id, env_id: Id) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE environments SET is_default = 0 WHERE project_id = ?1",
            params![project_id.to_string()],
        )?;
        tx.execute(
            "UPDATE environments SET is_default = 1 WHERE id = ?2 AND project_id = ?1",
            params![project_id.to_string(), env_id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Environments of a project with their variable counts.
    pub fn list_environments_with_counts(
        &self,
        project_id: Id,
    ) -> Result<Vec<(Environment, i64)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT e.id, e.project_id, e.name, e.is_default, e.sort_order, e.created_at, e.updated_at, e.deleted,
                    COUNT(v.id) AS var_count
             FROM environments e LEFT JOIN variables v ON v.environment_id = e.id AND v.deleted = 0
             WHERE e.project_id = ?1 AND e.deleted = 0
             GROUP BY e.id ORDER BY e.sort_order, e.name",
        )?;
        let rows = stmt.query_map(params![project_id.to_string()], |row| {
            Ok((map_environment(row)?, row.get::<_, i64>(8)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Soft delete: tombstone the row so sync can propagate it.
    pub fn delete_environment(&self, project_id: Id, env_name: &str) -> Result<bool, StorageError> {
        let n = self.conn.execute(
            "UPDATE environments
             SET deleted = 1, updated_at = ?3
             WHERE project_id = ?1 AND name = ?2 AND deleted = 0",
            params![project_id.to_string(), env_name, Utc::now().to_rfc3339()],
        )?;
        Ok(n > 0)
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
              WHERE environment_id = ?5 AND key = ?6 AND deleted = 0",
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

    /// Soft delete: tombstone the row so sync can propagate it.
    pub fn delete_variable(&self, environment_id: Id, key: &str) -> Result<bool, StorageError> {
        let n = self.conn.execute(
            "UPDATE variables
             SET deleted = 1, updated_at = ?3, version = version + 1
             WHERE environment_id = ?1 AND key = ?2 AND deleted = 0",
            params![environment_id.to_string(), key, Utc::now().to_rfc3339()],
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
                "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted
                 FROM variables WHERE environment_id = ?1 AND key = ?2 AND deleted = 0",
                params![environment_id.to_string(), key],
                map_variable,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_variables(&self, environment_id: Id) -> Result<Vec<Variable>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted
             FROM variables WHERE environment_id = ?1 AND deleted = 0 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![environment_id.to_string()], map_variable)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Every variable row, tombstones included — the full ciphertext set a
    /// key rotation must cover (`list_variables` hides deleted rows).
    pub fn all_variables(&self) -> Result<Vec<Variable>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted
             FROM variables",
        )?;
        let rows = stmt.query_map([], map_variable)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Search variable keys (and optional notes) across all projects,
    /// optionally scoped to one project and/or environment by name.
    pub fn search_variables(
        &self,
        query: &str,
        project: Option<&str>,
        env: Option<&str>,
    ) -> Result<Vec<VariableSummary>, StorageError> {
        let pattern = format!("%{}%", query.to_lowercase());
        let mut sql = String::from(
            "SELECT v.id, p.id, p.name, e.id, e.name, v.key, v.notes, v.is_readonly, v.allow_export, v.updated_at
             FROM variables v
              JOIN environments e ON e.id = v.environment_id AND e.deleted = 0
              JOIN projects p ON p.id = e.project_id AND p.deleted = 0
              WHERE v.deleted = 0
                AND (lower(v.key) LIKE ?1 OR lower(COALESCE(v.notes, '')) LIKE ?1)",
        );
        let project = project.map(str::to_string);
        let env = env.map(str::to_string);
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&pattern];
        if let Some(p) = &project {
            sql.push_str(" AND p.name = ?");
            params.push(p);
        }
        if let Some(e) = &env {
            sql.push_str(" AND e.name = ?");
            params.push(e);
        }
        sql.push_str(" ORDER BY p.name, e.name, v.key");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(VariableSummary {
                id: parse_uuid(&row.get::<_, String>(0)?)?,
                project_id: parse_uuid(&row.get::<_, String>(1)?)?,
                project_name: row.get(2)?,
                environment_id: parse_uuid(&row.get::<_, String>(3)?)?,
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

    // ---------- Sync helpers ----------

    /// Raw connection access for cursor management via [`SyncState`].
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Stamp `synced_at` on the given rows so they leave the dirty set.
    pub fn mark_synced(
        &self,
        table: SyncTable,
        ids: &[Id],
        ts: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if ids.is_empty() {
            return Ok(());
        }
        let ts = ts.to_rfc3339();
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!(
            "UPDATE {} SET synced_at = ?1 WHERE id IN ({})",
            table.table_name(),
            placeholders
        );
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&ts];
        let id_strs: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        for id in &id_strs {
            params.push(id);
        }
        self.conn.execute(&sql, params.as_slice())?;
        Ok(())
    }

    /// Rows pending push (`synced_at IS NULL OR updated_at > synced_at`).
    /// Includes tombstoned rows — that is how deletes propagate.
    pub fn dirty_projects(&self) -> Result<Vec<Project>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version, deleted
             FROM projects WHERE synced_at IS NULL OR updated_at > synced_at",
        )?;
        let rows = stmt.query_map([], map_project)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn dirty_environments(&self) -> Result<Vec<Environment>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at, deleted
             FROM environments WHERE synced_at IS NULL OR updated_at > synced_at",
        )?;
        let rows = stmt.query_map([], map_environment)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn dirty_variables(&self) -> Result<Vec<Variable>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted
             FROM variables WHERE synced_at IS NULL OR updated_at > synced_at",
        )?;
        let rows = stmt.query_map([], map_variable)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ---------- Sync merge helpers ----------

    /// Row by id including tombstones (needed to LWW-compare pulled rows).
    pub fn find_project_by_id(&self, id: Id) -> Result<Option<Project>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, name, description, color, icon, created_at, updated_at, owner_id, version, deleted
                 FROM projects WHERE id = ?1",
                params![id.to_string()],
                map_project,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Row by id including tombstones.
    pub fn find_environment_by_id(&self, id: Id) -> Result<Option<Environment>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, project_id, name, is_default, sort_order, created_at, updated_at, deleted
                 FROM environments WHERE id = ?1",
                params![id.to_string()],
                map_environment,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Row by id including tombstones.
    pub fn find_variable_by_id(&self, id: Id) -> Result<Option<Variable>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted
                 FROM variables WHERE id = ?1",
                params![id.to_string()],
                map_variable,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Insert-or-full-overwrite from a pulled row (LWW winner), tombstones included.
    pub fn upsert_pulled_project(&self, p: &Project) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO projects (id, name, description, color, icon, created_at, updated_at, owner_id, version, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, description = excluded.description,
               color = excluded.color, icon = excluded.icon,
               updated_at = excluded.updated_at, version = excluded.version,
               deleted = excluded.deleted",
            params![
                p.id.to_string(),
                p.name,
                p.description,
                p.color,
                p.icon,
                p.created_at.to_rfc3339(),
                p.updated_at.to_rfc3339(),
                p.owner_id,
                p.version,
                p.deleted as i32,
            ],
        )?;
        Ok(())
    }

    /// Insert-or-full-overwrite from a pulled row (LWW winner), tombstones included.
    pub fn upsert_pulled_environment(&self, e: &Environment) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO environments (id, project_id, name, is_default, sort_order, created_at, updated_at, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               project_id = excluded.project_id, name = excluded.name,
               is_default = excluded.is_default, sort_order = excluded.sort_order,
               updated_at = excluded.updated_at, deleted = excluded.deleted",
            params![
                e.id.to_string(),
                e.project_id.to_string(),
                e.name,
                e.is_default as i32,
                e.sort_order,
                e.created_at.to_rfc3339(),
                e.updated_at.to_rfc3339(),
                e.deleted as i32,
            ],
        )?;
        Ok(())
    }

    /// Insert-or-full-overwrite from a pulled row (LWW winner), tombstones included.
    pub fn upsert_pulled_variable(&self, v: &Variable) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO variables
             (id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET
               environment_id = excluded.environment_id, key = excluded.key,
               value_encrypted = excluded.value_encrypted, nonce = excluded.nonce,
               notes = excluded.notes, is_readonly = excluded.is_readonly,
               allow_export = excluded.allow_export, updated_at = excluded.updated_at,
               version = excluded.version, deleted = excluded.deleted",
            params![
                v.id.to_string(),
                v.environment_id.to_string(),
                v.key,
                v.value_encrypted,
                v.nonce,
                v.notes,
                v.is_readonly as i32,
                v.allow_export as i32,
                v.created_at.to_rfc3339(),
                v.updated_at.to_rfc3339(),
                v.version,
                v.deleted as i32,
            ],
        )?;
        Ok(())
    }

    /// Soft-delete live children of tombstoned parents (projects → environments
    /// → variables). A tombstoned parent must never leave live children behind,
    /// locally or on the server. Returns the number of newly tombstoned rows;
    /// they become dirty and propagate on the next push.
    pub fn cascade_tombstones(&self, ts: DateTime<Utc>) -> Result<usize, StorageError> {
        let ts = ts.to_rfc3339();
        let n_envs = self.conn.execute(
            "UPDATE environments
             SET deleted = 1, updated_at = ?1
             WHERE deleted = 0 AND project_id IN (SELECT id FROM projects WHERE deleted = 1)",
            params![ts],
        )?;
        let n_vars = self.conn.execute(
            "UPDATE variables
             SET deleted = 1, version = version + 1, updated_at = ?1
             WHERE deleted = 0 AND environment_id IN (SELECT id FROM environments WHERE deleted = 1)",
            params![ts],
        )?;
        Ok(n_envs + n_vars)
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
        deleted: row.get::<_, i32>(9)? != 0,
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
        deleted: row.get::<_, i32>(7)? != 0,
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
        deleted: row.get::<_, i32>(11)? != 0,
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
    if let Ok(path) = std::env::var("SECRETS_DB") {
        return PathBuf::from(path);
    }
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
            deleted: false,
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

    fn sample_var(env_id: Id, key: &str) -> Variable {
        let now = Utc::now();
        Variable {
            id: Uuid::now_v7(),
            environment_id: env_id,
            key: key.into(),
            value_encrypted: vec![1, 2, 3],
            nonce: vec![0; 24],
            notes: None,
            is_readonly: false,
            allow_export: true,
            created_at: now,
            updated_at: now,
            version: 1,
            deleted: false,
        }
    }

    #[test]
    fn soft_delete_hides_row_but_keeps_tombstone_dirty() {
        let s = Storage::open_in_memory().unwrap();
        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        s.create_project(&p).unwrap();
        let e = Environment {
            id: Uuid::now_v7(),
            project_id: p.id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        s.create_environment(&e).unwrap();
        let v = sample_var(e.id, "K");
        s.create_variable(&v).unwrap();

        // Everything visible before delete.
        assert_eq!(s.list_variables(e.id).unwrap().len(), 1);
        assert_eq!(s.search_variables("k", None, None).unwrap().len(), 1);

        assert!(s.delete_variable(e.id, "K").unwrap());

        // Hidden from list/get/search after soft delete.
        assert!(s.list_variables(e.id).unwrap().is_empty());
        assert!(s.get_variable(e.id, "K").unwrap().is_none());
        assert!(s.search_variables("k", None, None).unwrap().is_empty());

        // ...but present as a dirty tombstone for sync push.
        let dirty = s.dirty_variables().unwrap();
        assert_eq!(dirty.len(), 1);
        assert!(dirty[0].deleted);
        assert_eq!(dirty[0].id, v.id);
        assert_eq!(dirty[0].version, 2);

        // The partial unique index allows recreating the same key.
        let v2 = sample_var(e.id, "K");
        s.create_variable(&v2).unwrap();
        assert_eq!(s.list_variables(e.id).unwrap().len(), 1);

        // mark_synced clears the dirty set.
        s.mark_synced(SyncTable::Variables, &[v.id, v2.id], Utc::now())
            .unwrap();
        assert!(s.dirty_variables().unwrap().is_empty());
    }

    #[test]
    fn project_and_environment_soft_deletes() {
        let s = Storage::open_in_memory().unwrap();
        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        s.create_project(&p).unwrap();
        let e = Environment {
            id: Uuid::now_v7(),
            project_id: p.id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        s.create_environment(&e).unwrap();

        assert!(s.delete_environment(p.id, "local").unwrap());
        assert!(s.list_environments(p.id).unwrap().is_empty());
        assert!(s
            .dirty_environments()
            .unwrap()
            .iter()
            .all(|env| env.deleted));

        assert!(s.delete_project("P").unwrap());
        assert!(s.list_projects().unwrap().is_empty());
        assert!(s.get_project_by_name("P").unwrap().is_none());
        assert_eq!(s.dirty_projects().unwrap().len(), 1);
    }

    #[test]
    fn sync_state_roundtrip() {
        let s = Storage::open_in_memory().unwrap();
        assert!(SyncState::get(s.conn(), "last_pull").unwrap().is_none());
        SyncState::set(s.conn(), "last_pull", "2026-01-01T00:00:00Z").unwrap();
        SyncState::set(s.conn(), "last_pull", "2026-02-01T00:00:00Z").unwrap();
        assert_eq!(
            SyncState::get(s.conn(), "last_pull").unwrap().as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
        SyncState::remove(s.conn(), "last_pull").unwrap();
        assert!(SyncState::get(s.conn(), "last_pull").unwrap().is_none());
        // Removing an absent key is a no-op.
        SyncState::remove(s.conn(), "last_pull").unwrap();
    }

    #[test]
    fn key_rotation_keeps_lww_timestamps_and_redirties_rows() {
        let s = Storage::open_in_memory().unwrap();
        s.init_vault(&[1u8; 16], &KdfParams::default(), b"ct", b"nonce")
            .unwrap();
        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        s.create_project(&p).unwrap();
        let e = Environment {
            id: Uuid::now_v7(),
            project_id: p.id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        s.create_environment(&e).unwrap();
        let v = sample_var(e.id, "K");
        s.create_variable(&v).unwrap();
        // Row fully synced: rotation must still redirty it.
        s.mark_synced(
            SyncTable::Variables,
            &[v.id],
            now + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert!(s.dirty_variables().unwrap().is_empty());

        let before = s.get_variable(e.id, "K").unwrap().unwrap();
        s.apply_key_rotation(
            &[(v.id, vec![9, 9, 9], vec![1; 24])],
            &[2u8; 16],
            &KdfParams::default(),
            b"ct2",
            b"nonce2",
            2,
        )
        .unwrap();

        let after = s.get_variable(e.id, "K").unwrap().unwrap();
        assert_eq!(after.value_encrypted, vec![9, 9, 9]);
        assert_eq!(
            after.updated_at, before.updated_at,
            "LWW timestamp must not move"
        );
        assert_eq!(after.version, before.version, "rotation is not an edit");

        // New ciphertext is dirty → propagates on the next push.
        let dirty = s.dirty_variables().unwrap();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].id, v.id);

        // vault_meta rotated in the same transaction.
        let meta = s.get_vault_meta().unwrap();
        assert_eq!(meta.salt, vec![2u8; 16]);

        // Tombstones are part of the rotation set too.
        assert_eq!(s.all_variables().unwrap().len(), 1);
        assert!(s.delete_variable(e.id, "K").unwrap());
        assert_eq!(s.all_variables().unwrap().len(), 1, "tombstones included");
    }

    #[test]
    fn adoption_rotation_requeues_parents_and_leaves_their_timestamps_alone() {
        // A device that had already synced before a remote reset: nothing is
        // dirty, which is exactly the state that made the "keep local"
        // adoption push no parents.
        let s = synced_vault_with_one_variable();
        let project_id = s.get_project_by_name("P").unwrap().unwrap().id;
        let env_id = s.list_environments(project_id).unwrap()[0].id;
        let var = s.all_variables().unwrap().pop().unwrap();
        assert!(
            s.dirty_projects().unwrap().is_empty()
                && s.dirty_environments().unwrap().is_empty()
                && s.dirty_variables().unwrap().is_empty(),
            "precondition: this device had fully synced"
        );
        let project_before = s.find_project_by_id(project_id).unwrap().unwrap();
        let env_before = s.find_environment_by_id(env_id).unwrap().unwrap();
        let reencrypted = vec![(var.id, vec![9, 9, 9], vec![1; 24])];

        // The adoption path: parents must go back to the dirty set so their
        // live rows overwrite the reset's tombstones before the pull runs.
        s.apply_key_rotation_dirtying_parents(
            &reencrypted,
            &[3u8; 16],
            &KdfParams::default(),
            b"ct3",
            b"nonce3",
            9,
        )
        .unwrap();

        let dirty_projects = s.dirty_projects().unwrap();
        assert_eq!(dirty_projects.len(), 1, "the project must be re-pushed");
        assert_eq!(dirty_projects[0].id, project_id);
        assert!(!dirty_projects[0].deleted, "re-queuing must not tombstone");
        let dirty_envs = s.dirty_environments().unwrap();
        assert_eq!(dirty_envs.len(), 1, "the environment must be re-pushed");
        assert_eq!(dirty_envs[0].id, env_id);
        assert!(!dirty_envs[0].deleted, "re-queuing must not tombstone");
        assert_eq!(s.dirty_variables().unwrap().len(), 1, "variables too");

        // Same LWW contract as a plain rotation: the push overwrites the
        // tombstone server-side by primary key, so no timestamp may move —
        // a bumped `updated_at` would also be what makes the following pull
        // unable to resurrect the deletion.
        let project_after = s.find_project_by_id(project_id).unwrap().unwrap();
        assert_eq!(project_after.updated_at, project_before.updated_at);
        assert_eq!(project_after.version, project_before.version);
        let env_after = s.find_environment_by_id(env_id).unwrap().unwrap();
        assert_eq!(env_after.updated_at, env_before.updated_at);
        assert_eq!(s.get_vault_meta().unwrap().key_epoch, 9);
    }

    #[test]
    fn a_plain_key_rotation_leaves_parents_clean() {
        // The other half of the contract, and the reason the adoption path has
        // its own method instead of a global rule: on a rekey the parents'
        // names and contents are unchanged, so re-pushing them would be pure
        // waste. If this test ever fails, a global "always redirty parents"
        // has crept in.
        let s = synced_vault_with_one_variable();
        let project_id = s.get_project_by_name("P").unwrap().unwrap().id;
        let var = s.all_variables().unwrap().pop().unwrap();
        s.apply_key_rotation(
            &[(var.id, vec![9, 9, 9], vec![1; 24])],
            &[4u8; 16],
            &KdfParams::default(),
            b"ct4",
            b"nonce4",
            2,
        )
        .unwrap();

        assert!(
            s.dirty_projects().unwrap().is_empty(),
            "rekey must not push parents"
        );
        assert!(
            s.dirty_environments().unwrap().is_empty(),
            "rekey must not push parents"
        );
        assert_eq!(s.dirty_variables().unwrap().len(), 1, "variables only");
        assert!(
            !s.find_project_by_id(project_id).unwrap().unwrap().deleted,
            "a rotation never deletes anything locally either"
        );
    }

    /// An initialized vault holding one project, one environment and one
    /// variable, all three already marked synced.
    fn synced_vault_with_one_variable() -> Storage {
        let s = Storage::open_in_memory().unwrap();
        s.init_vault(&[1u8; 16], &KdfParams::default(), b"ct", b"nonce")
            .unwrap();
        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "P".into(),
            description: None,
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        s.create_project(&p).unwrap();
        let e = Environment {
            id: Uuid::now_v7(),
            project_id: p.id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        s.create_environment(&e).unwrap();
        let v = sample_var(e.id, "K");
        s.create_variable(&v).unwrap();
        // As a completed sync would leave them: stamped, so not dirty.
        let stamped = now + chrono::Duration::seconds(1);
        s.mark_synced(SyncTable::Projects, &[p.id], stamped)
            .unwrap();
        s.mark_synced(SyncTable::Environments, &[e.id], stamped)
            .unwrap();
        s.mark_synced(SyncTable::Variables, &[v.id], stamped)
            .unwrap();
        s
    }

    #[test]
    fn set_key_epoch_on_uninitialized_vault_errors() {
        let s = Storage::open_in_memory().unwrap();
        assert!(matches!(
            s.set_key_epoch(2),
            Err(StorageError::NotInitialized)
        ));
    }

    #[test]
    fn reset_vault_empties_everything_and_installs_the_new_domain() {
        let s = Storage::open_in_memory().unwrap();
        s.init_vault(&[1u8; 16], &KdfParams::default(), b"ct", b"nonce")
            .unwrap();
        let now = Utc::now();
        let p = Project {
            id: Uuid::now_v7(),
            name: "p".into(),
            description: None,
            color: None,
            icon: None,
            created_at: now,
            updated_at: now,
            owner_id: None,
            version: 1,
            deleted: false,
        };
        s.create_project(&p).unwrap();
        let e = Environment {
            id: Uuid::now_v7(),
            project_id: p.id,
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        s.create_environment(&e).unwrap();
        s.create_variable(&sample_var(e.id, "K")).unwrap();
        SyncState::set(s.conn(), "last_pull", "2026-01-01T00:00:00Z").unwrap();
        assert!(!s.all_variables().unwrap().is_empty());

        let params = KdfParams {
            m_cost: 2048,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        s.reset_vault(&[9u8; 16], &params, b"new-ct", b"new-nonce", 4)
            .unwrap();

        assert!(
            s.is_initialized().unwrap(),
            "the vault still exists after a reset"
        );
        assert!(s.list_projects().unwrap().is_empty());
        assert!(s.all_variables().unwrap().is_empty());
        assert_eq!(
            SyncState::get(s.conn(), "last_pull").unwrap(),
            None,
            "the pull cursor is dropped"
        );
        let meta = s.get_vault_meta().unwrap();
        assert_eq!(meta.salt, vec![9u8; 16]);
        assert_eq!(meta.kdf_params.m_cost, 2048);
        assert_eq!(meta.verifier_ct, b"new-ct".to_vec());
        assert_eq!(meta.verifier_nonce, b"new-nonce".to_vec());
        assert_eq!(meta.key_epoch, 4);
    }

    #[test]
    fn reset_vault_on_uninitialized_vault_errors() {
        let s = Storage::open_in_memory().unwrap();
        assert!(matches!(
            s.reset_vault(&[9u8; 16], &KdfParams::default(), b"c", b"n", 1),
            Err(StorageError::NotInitialized)
        ));
    }

    #[test]
    fn migration_v1_to_v2_preserves_rows() {
        use crate::migrations::MIGRATIONS;
        use rusqlite::Connection;
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO projects (id, name, description, color, icon, created_at, updated_at, owner_id, version)
             VALUES ('p1', 'Old', NULL, NULL, NULL, ?1, ?1, NULL, 3)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO environments (id, project_id, name, is_default, sort_order, created_at, updated_at)
             VALUES ('e1', 'p1', 'local', 1, 0, ?1, ?1)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO variables (id, environment_id, key, value_encrypted, nonce, notes, is_readonly, allow_export, created_at, updated_at, version)
             VALUES ('v1', 'e1', 'KEY', x'0102', x'000000000000000000000000000000000000000000000000', NULL, 0, 1, ?1, ?1, 5)",
            params![now],
        )
        .unwrap();

        migrations::run(&conn).unwrap();
        assert_eq!(migrations::current_version(&conn).unwrap(), 3);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM variables", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let version: i64 = conn
            .query_row("SELECT version FROM projects WHERE id = 'p1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 3);
    }
}
