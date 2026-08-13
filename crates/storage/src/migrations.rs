//! Versioned SQL migrations embedded at compile time.
//!
//! Add new files under `migrations/` as `NNN_name.sql` and register them in
//! [`MIGRATIONS`] in ascending version order.

use crate::StorageError;
use chrono::Utc;
use rusqlite::{params, Connection};

/// A single schema migration.
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

/// Ordered list of all migrations. Append only — never reorder or edit applied SQL.
pub static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "001_initial",
    sql: include_str!("../migrations/001_initial.sql"),
}];

const BOOTSTRAP: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL
);
"#;

/// Apply all pending migrations. Safe to call on every open.
pub fn run(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(BOOTSTRAP)?;

    // Legacy vaults created with the old inline SCHEMA (no tracking table rows).
    if table_exists(conn, "projects")? && !is_applied(conn, 1)? {
        record(conn, 1, "001_initial")?;
        // Continue so any future migrations (2+) still run.
    }

    for m in MIGRATIONS {
        if is_applied(conn, m.version)? {
            continue;
        }
        let tx = conn.unchecked_transaction().map_err(StorageError::from)?;
        tx.execute_batch(m.sql)
            .map_err(|e| StorageError::Other(format!("migration {} failed: {e}", m.name)))?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
            params![m.version, m.name, Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
        tracing::info!(version = m.version, name = m.name, "applied migration");
    }
    Ok(())
}

fn is_applied(conn: &Connection, version: i64) -> Result<bool, StorageError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        params![version],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn record(conn: &Connection, version: i64, name: &str) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
        params![version, name, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, StorageError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Highest applied migration version (0 if none).
pub fn current_version(conn: &Connection) -> Result<i64, StorageError> {
    let v: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn runs_initial_migration() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run(&conn).unwrap();
        assert!(table_exists(&conn, "projects").unwrap());
        assert!(table_exists(&conn, "variables").unwrap());
        assert!(is_applied(&conn, 1).unwrap());
        // Idempotent
        run(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 1);
    }
}
