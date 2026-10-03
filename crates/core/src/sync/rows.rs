use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use models::{Environment, Id, Project, Variable};

use crate::CoreError;
use sync::{EnvironmentRow, ProjectRow, VariableRow};

// ---------- base64 + mapping ----------

pub(super) fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub(super) fn b64_decode(s: &str) -> Result<Vec<u8>, CoreError> {
    B64.decode(s)
        .map_err(|e| CoreError::Other(format!("invalid base64 from server: {e}")))
}

pub(super) fn parse_id(s: &str) -> Result<Id, CoreError> {
    s.parse::<Id>()
        .map_err(|e| CoreError::Other(format!("invalid id '{s}' from server: {e}")))
}

pub(super) fn project_to_dto(p: &Project) -> ProjectRow {
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

pub(super) fn environment_to_dto(e: &Environment) -> EnvironmentRow {
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

pub(super) fn variable_to_dto(v: &Variable) -> VariableRow {
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

pub(super) fn project_from_dto(r: &ProjectRow) -> Result<Project, CoreError> {
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

pub(super) fn environment_from_dto(r: &EnvironmentRow) -> Result<Environment, CoreError> {
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

pub(super) fn variable_from_dto(r: &VariableRow) -> Result<Variable, CoreError> {
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

/// Mark a remote project as deleted for a reset. Pure; unit-testable.
/// Only metadata changes: a reset has no master key, so the row's contents
/// are carried through untouched.
pub(super) fn tombstone_project(row: &ProjectRow, now: DateTime<Utc>) -> ProjectRow {
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
pub(super) fn tombstone_environment(row: &EnvironmentRow, now: DateTime<Utc>) -> EnvironmentRow {
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
pub(super) fn tombstone_variable(row: &VariableRow, now: DateTime<Utc>) -> VariableRow {
    VariableRow {
        deleted: true,
        version: row.version + 1,
        updated_at: Some(now),
        ..row.clone()
    }
}

/// Tombstone every pulled row, grouped so the caller can push parents before
/// children. Pure and order-preserving; the caller does the network.
pub(super) fn reset_tombstone_sets(
    projects: &[ProjectRow],
    environments: &[EnvironmentRow],
    variables: &[VariableRow],
    now: DateTime<Utc>,
) -> (Vec<ProjectRow>, Vec<EnvironmentRow>, Vec<VariableRow>) {
    (
        projects.iter().map(|r| tombstone_project(r, now)).collect(),
        environments
            .iter()
            .map(|r| tombstone_environment(r, now))
            .collect(),
        variables
            .iter()
            .map(|r| tombstone_variable(r, now))
            .collect(),
    )
}
