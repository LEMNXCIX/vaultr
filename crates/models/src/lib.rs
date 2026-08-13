//! Domain models for the secrets manager.
//! Pure data structures with no I/O or crypto dependencies.

pub mod constants;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier used across the system (UUID v7).
pub type Id = Uuid;

/// Metadata of the local vault (single row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub salt: Vec<u8>,
    pub kdf_params: KdfParams,
    /// AEAD ciphertext used to verify the master password on unlock.
    pub verifier_ct: Vec<u8>,
    pub verifier_nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Argon2id parameters stored as JSON in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes (e.g. 65536 = 64 MiB)
    pub m_cost: u32,
    /// Number of iterations
    pub t_cost: u32,
    /// Degree of parallelism
    pub p_cost: u32,
    /// Output length in bytes (normally 32)
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: constants::ARGON2_M_COST_KIB,
            t_cost: constants::ARGON2_T_COST,
            p_cost: constants::ARGON2_P_COST,
            output_len: constants::ARGON2_OUTPUT_LEN,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Reserved for future multi-user support
    pub owner_id: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: Id,
    pub project_id: Id,
    pub name: String,
    pub is_default: bool,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub id: Id,
    pub environment_id: Id,
    pub key: String,
    /// Always stored encrypted. Never keep plaintext here long-term.
    pub value_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub notes: Option<String>,
    /// Future sharing: cannot be modified by non-owners
    pub is_readonly: bool,
    /// Future sharing: whether the value may be exported
    pub allow_export: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
}

/// A decrypted view of a variable (used only in memory, never persisted).
#[derive(Clone)]
pub struct DecryptedVariable {
    pub id: Id,
    pub environment_id: Id,
    pub key: String,
    pub value: String,
    pub notes: Option<String>,
    pub is_readonly: bool,
    pub allow_export: bool,
}

impl std::fmt::Debug for DecryptedVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedVariable")
            .field("id", &self.id)
            .field("environment_id", &self.environment_id)
            .field("key", &self.key)
            .field("value", &"[redacted]")
            .field("notes", &self.notes)
            .field("is_readonly", &self.is_readonly)
            .field("allow_export", &self.allow_export)
            .finish()
    }
}

/// Summary used for listings and search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableSummary {
    pub id: Id,
    pub project_id: Id,
    pub project_name: String,
    pub environment_id: Id,
    pub environment_name: String,
    pub key: String,
    pub notes: Option<String>,
    pub is_readonly: bool,
    pub allow_export: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("project not found")]
    ProjectNotFound,
    #[error("environment not found")]
    EnvironmentNotFound,
    #[error("variable not found")]
    VariableNotFound,
    #[error("variable key already exists in this environment")]
    DuplicateKey,
    #[error("invalid name: {0}")]
    InvalidName(String),
}

/// Validate project / environment / variable key names.
pub fn validate_name(kind: &str, name: &str) -> Result<(), DomainError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(DomainError::InvalidName(format!(
            "{kind} must not be empty"
        )));
    }
    if name.len() > constants::MAX_NAME_LEN {
        return Err(DomainError::InvalidName(format!("{kind} too long")));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(DomainError::InvalidName(format!(
            "{kind} contains control characters"
        )));
    }
    Ok(())
}
