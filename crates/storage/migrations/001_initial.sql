-- Initial vault schema (v1)
-- Applied once via schema_migrations; do not use IF NOT EXISTS for tables
-- (the runner guarantees single execution).

CREATE TABLE vault_meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    salt            BLOB NOT NULL,
    kdf_params      TEXT NOT NULL,
    verifier_ct     BLOB NOT NULL,
    verifier_nonce  BLOB NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE projects (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    color           TEXT,
    icon            TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    owner_id        TEXT,
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE environments (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    is_default      INTEGER NOT NULL DEFAULT 0,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(project_id, name)
);

CREATE TABLE variables (
    id              TEXT PRIMARY KEY,
    environment_id  TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    value_encrypted BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    notes           TEXT,
    is_readonly     INTEGER NOT NULL DEFAULT 0,
    allow_export    INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    UNIQUE(environment_id, key)
);

CREATE INDEX idx_variables_key ON variables(key);
CREATE INDEX idx_environments_project ON environments(project_id);
