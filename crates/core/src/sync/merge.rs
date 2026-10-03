use chrono::{DateTime, Utc};
use storage::Storage;

use super::rows::{environment_from_dto, parse_id, project_from_dto, variable_from_dto};
use crate::CoreError;
use sync::{EnvironmentRow, ProjectRow, VariableRow};

/// LWW decision: apply the remote row iff strictly newer than local.
/// Missing local row → apply. Missing timestamps → keep local (conservative).
pub(super) fn remote_wins(
    remote_ts: Option<DateTime<Utc>>,
    local_ts: Option<DateTime<Utc>>,
) -> bool {
    match (remote_ts, local_ts) {
        (Some(remote), Some(local)) => remote > local,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// New pull cursor: max of previous cursor and every timestamp seen this run.
pub(super) fn next_cursor(
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

// ---------- Merge (pure-ish: Storage in, rows applied) ----------

/// Result of merging one pulled row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MergeOutcome {
    /// Remote lost LWW (or had no timestamp); local row untouched.
    LocalKept,
    /// Remote applied; `true` when it was a tombstone.
    Applied(bool),
    /// Parent row unknown locally; skipped to avoid an FK violation.
    SkippedOrphan,
}

impl MergeOutcome {
    pub(super) fn pulled_and_deleted(self) -> Option<bool> {
        match self {
            MergeOutcome::Applied(deleted) => Some(deleted),
            _ => None,
        }
    }
}

pub(super) fn merge_project(
    storage: &Storage,
    row: &ProjectRow,
) -> Result<MergeOutcome, CoreError> {
    let id = parse_id(&row.id)?;
    let local_ts = storage.find_project_by_id(id)?.map(|p| p.updated_at);
    if !remote_wins(row.updated_at, local_ts) {
        return Ok(MergeOutcome::LocalKept);
    }
    storage.upsert_pulled_project(&project_from_dto(row)?)?;
    Ok(MergeOutcome::Applied(row.deleted))
}

pub(super) fn merge_environment(
    storage: &Storage,
    row: &EnvironmentRow,
) -> Result<MergeOutcome, CoreError> {
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

pub(super) fn merge_variable(
    storage: &Storage,
    row: &VariableRow,
) -> Result<MergeOutcome, CoreError> {
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
