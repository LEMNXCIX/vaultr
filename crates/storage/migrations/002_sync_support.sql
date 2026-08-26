-- Sync support (v2): tombstones + dirty tracking.
--
-- Adds `deleted` (soft-delete tombstone) and `synced_at` (dirty tracking) to
-- projects/environments/variables, plus a `sync_state` key/value table for the
-- sync cursor (e.g. last_pull).
--
-- SQLite cannot drop a UNIQUE constraint in place, so the three tables are
-- rebuilt with the standard create-new/copy/drop/rename pattern and the old
-- table-level UNIQUEs are replaced by partial unique indexes on
-- `deleted = 0`. This lets a deleted row coexist with a new live row that
-- reuses its name/key while keeping live names unique. Existing rows are
-- preserved verbatim.
--
-- Rebuild runs with foreign_keys OFF (see migrations.rs): with FKs enabled,
-- DROP TABLE performs an implicit DELETE whose ON DELETE CASCADE would wipe
-- rows already copied into the new tables. Atomicity is preserved by the
-- explicit BEGIN/COMMIT below; the runner verifies foreign_key_check after.

BEGIN IMMEDIATE;

CREATE TABLE variables_new (
    id              TEXT PRIMARY KEY,
    environment_id  TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    value_encrypted BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    notes           TEXT,
    is_readonly     INTEGER NOT NULL DEFAULT 0,
    allow_export    INTEGER NOT NULL DEFAULT 1,
    deleted         INTEGER NOT NULL DEFAULT 0,
    synced_at       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE environments_new (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    is_default      INTEGER NOT NULL DEFAULT 0,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    deleted         INTEGER NOT NULL DEFAULT 0,
    synced_at       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE projects_new (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    color           TEXT,
    icon            TEXT,
    deleted         INTEGER NOT NULL DEFAULT 0,
    synced_at       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    owner_id        TEXT,
    version         INTEGER NOT NULL DEFAULT 1
);

INSERT INTO variables_new
SELECT id, environment_id, key, value_encrypted, nonce, notes,
       is_readonly, allow_export, 0, NULL, created_at, updated_at, version
FROM variables;

INSERT INTO environments_new
SELECT id, project_id, name, is_default, sort_order, 0, NULL, created_at, updated_at
FROM environments;

INSERT INTO projects_new
SELECT id, name, description, color, icon, 0, NULL, created_at, updated_at, owner_id, version
FROM projects;

DROP TABLE variables;
DROP TABLE environments;
DROP TABLE projects;

ALTER TABLE variables_new RENAME TO variables;
ALTER TABLE environments_new RENAME TO environments;
ALTER TABLE projects_new RENAME TO projects;

-- Live rows keep unique names/keys; tombstoned rows do not block reuse.
CREATE UNIQUE INDEX idx_projects_name_live ON projects(name) WHERE deleted = 0;
CREATE UNIQUE INDEX idx_environments_project_name_live ON environments(project_id, name) WHERE deleted = 0;
CREATE UNIQUE INDEX idx_variables_env_key_live ON variables(environment_id, key) WHERE deleted = 0;

-- Recreate plain indexes lost with the dropped tables.
CREATE INDEX idx_variables_key ON variables(key);
CREATE INDEX idx_environments_project ON environments(project_id);

CREATE TABLE sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

COMMIT;
