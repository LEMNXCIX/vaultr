//! Application-wide constants. Prefer these over magic strings/numbers in call sites.

/// Default environment created with every new project.
pub const DEFAULT_ENVIRONMENT: &str = "local";

/// AEAD plaintext used as vault password verifier.
pub const VAULT_VERIFIER_MESSAGE: &str = "vault-ok";

/// Max length for project / environment / variable names.
pub const MAX_NAME_LEN: usize = 256;

/// Qualifier for `directories` / OS paths (reversed domain style).
pub const APP_QUALIFIER: &str = "dev";
pub const APP_ORGANIZATION: &str = "Vaultr";
pub const APP_NAME: &str = "vaultr";

/// Previous application identifiers, used only to locate and migrate a local vault.
pub const LEGACY_APP_ORGANIZATION: &str = "SecretsManager";
pub const LEGACY_APP_NAME: &str = "secrets-manager";

/// OS keyring service / account identifiers.
pub const KEYRING_SERVICE: &str = "dev.secrets-manager.vault";
pub const KEYRING_ACCOUNT: &str = "master-key-session";

/// Sliding session TTL (seconds).
pub const SESSION_TTL_SECS: u64 = 30 * 60;

/// HKDF info/context for project keys (future sharing).
pub const PROJECT_KEY_HKDF_INFO: &[u8] = b"secrets-manager-project-key-v1";

/// Backup file format identifiers.
pub const BACKUP_FILE_MAGIC: &[u8; 16] = b"SECRETSBAK01\0\0\0\0";
pub const BACKUP_SNAPSHOT_MAGIC: &str = "SECRETS-BACKUP-v1";

/// Argon2id defaults (OWASP-oriented baseline).
pub const ARGON2_M_COST_KIB: u32 = 65_536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
pub const ARGON2_OUTPUT_LEN: usize = 32;
