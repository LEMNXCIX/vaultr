//! Optional synchronization layer (Supabase).
//! Intentionally empty in the MVP – only the local SQLite is the source of truth.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("sync not implemented yet")]
    NotImplemented,
}

pub struct SyncService;

impl Default for SyncService {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncService {
    pub fn new() -> Self {
        Self
    }

    pub fn push(&self) -> Result<(), SyncError> {
        Err(SyncError::NotImplemented)
    }

    pub fn pull(&self) -> Result<(), SyncError> {
        Err(SyncError::NotImplemented)
    }
}
