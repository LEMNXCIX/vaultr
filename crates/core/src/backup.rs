//! Encrypted full-vault backup and restore.
//!
//! File format (v1):
//!   magic[16] = b"SECRETSBAK01\0\0\0\0"
//!   salt_len u16 LE + salt
//!   kdf_json_len u32 LE + kdf_json UTF-8
//!   nonce[24] + ciphertext  (XChaCha20-Poly1305 over snapshot JSON)

use crate::CoreError;
use chrono::Utc;
use crypto::{decrypt, derive_master_key, encrypt, MasterKey};
use models::{Environment, KdfParams, Project, Variable, VaultMeta};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use storage::Storage;

use models::constants::{BACKUP_FILE_MAGIC as MAGIC, BACKUP_SNAPSHOT_MAGIC as SNAPSHOT_MAGIC};

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub magic: String,
    pub created_at: String,
    pub vault_meta: VaultMetaDto,
    pub projects: Vec<Project>,
    pub environments: Vec<Environment>,
    pub variables: Vec<Variable>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetaDto {
    pub salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub verifier_ct: Vec<u8>,
    pub verifier_nonce: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&VaultMeta> for VaultMetaDto {
    fn from(m: &VaultMeta) -> Self {
        Self {
            salt: m.salt.clone(),
            kdf_params: m.kdf_params.clone(),
            verifier_ct: m.verifier_ct.clone(),
            verifier_nonce: m.verifier_nonce.clone(),
            created_at: m.created_at.to_rfc3339(),
            updated_at: m.updated_at.to_rfc3339(),
        }
    }
}

pub fn build_snapshot(storage: &Storage) -> Result<VaultSnapshot, CoreError> {
    let meta = storage.get_vault_meta()?;
    let projects = storage.list_projects()?;
    let mut environments = Vec::new();
    let mut variables = Vec::new();
    for p in &projects {
        let envs = storage.list_environments(p.id)?;
        for e in &envs {
            variables.extend(storage.list_variables(e.id)?);
        }
        environments.extend(envs);
    }
    Ok(VaultSnapshot {
        magic: SNAPSHOT_MAGIC.into(),
        created_at: Utc::now().to_rfc3339(),
        vault_meta: VaultMetaDto::from(&meta),
        projects,
        environments,
        variables,
    })
}

/// Seal snapshot: clear KDF material + encrypted body.
pub fn seal_backup(master_key: &MasterKey, snapshot: &VaultSnapshot) -> Result<Vec<u8>, CoreError> {
    let json = serde_json::to_string(snapshot)
        .map_err(|e| CoreError::Other(format!("serialize backup: {e}")))?;
    let (ct, nonce) = encrypt(master_key, &json)?;

    let salt = &snapshot.vault_meta.salt;
    let kdf_json = serde_json::to_vec(&snapshot.vault_meta.kdf_params)
        .map_err(|e| CoreError::Other(format!("serialize kdf: {e}")))?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(salt.len() as u16).to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&(kdf_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&kdf_json);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

struct Header {
    salt: Vec<u8>,
    kdf_params: KdfParams,
    body: Vec<u8>, // nonce || ciphertext
}

fn parse_header(blob: &[u8]) -> Result<Header, CoreError> {
    if blob.len() < 16 + 2 + 4 + 24 {
        return Err(CoreError::Other("backup file too small".into()));
    }
    if &blob[..16] != MAGIC {
        return Err(CoreError::Other("not a secrets backup file".into()));
    }
    let mut o = 16usize;
    let salt_len = u16::from_le_bytes([blob[o], blob[o + 1]]) as usize;
    o += 2;
    if o + salt_len + 4 > blob.len() {
        return Err(CoreError::Other("corrupt backup header".into()));
    }
    let salt = blob[o..o + salt_len].to_vec();
    o += salt_len;
    let kdf_len = u32::from_le_bytes(blob[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + kdf_len + 24 > blob.len() {
        return Err(CoreError::Other("corrupt backup header".into()));
    }
    let kdf_params: KdfParams = serde_json::from_slice(&blob[o..o + kdf_len])
        .map_err(|e| CoreError::Other(format!("invalid kdf in backup: {e}")))?;
    o += kdf_len;
    let body = blob[o..].to_vec();
    Ok(Header {
        salt,
        kdf_params,
        body,
    })
}

pub fn open_backup(master_key: &MasterKey, blob: &[u8]) -> Result<VaultSnapshot, CoreError> {
    let header = parse_header(blob)?;
    if header.body.len() < 25 {
        return Err(CoreError::Other("backup body too small".into()));
    }
    let (nonce, ct) = header.body.split_at(24);
    let json = decrypt(master_key, ct, nonce)?;
    let snapshot: VaultSnapshot = serde_json::from_str(json.as_str())
        .map_err(|e| CoreError::Other(format!("invalid backup payload: {e}")))?;
    if snapshot.magic != SNAPSHOT_MAGIC {
        return Err(CoreError::Other("unsupported backup payload".into()));
    }
    Ok(snapshot)
}

pub fn open_backup_with_password(
    password: SecretString,
    blob: &[u8],
) -> Result<VaultSnapshot, CoreError> {
    let header = parse_header(blob)?;
    let key = derive_master_key(&password, &header.salt, &header.kdf_params)?;
    open_backup(&key, blob)
}

pub fn restore_snapshot(storage: &Storage, snapshot: &VaultSnapshot) -> Result<(), CoreError> {
    if storage.is_initialized()? {
        return Err(CoreError::Other(
            "target vault already initialized; refuse to overwrite".into(),
        ));
    }
    storage.init_vault(
        &snapshot.vault_meta.salt,
        &snapshot.vault_meta.kdf_params,
        &snapshot.vault_meta.verifier_ct,
        &snapshot.vault_meta.verifier_nonce,
    )?;
    for p in &snapshot.projects {
        storage.create_project(p)?;
    }
    for e in &snapshot.environments {
        storage.create_environment(e)?;
    }
    for v in &snapshot.variables {
        storage.create_variable(v)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::generate_salt;
    use secrecy::SecretString;

    #[test]
    fn seal_open_roundtrip() {
        let salt = generate_salt();
        let params = KdfParams::default();
        let password = SecretString::new("backup-pass".into());
        let key = derive_master_key(&password, &salt, &params).unwrap();

        let snapshot = VaultSnapshot {
            magic: SNAPSHOT_MAGIC.into(),
            created_at: Utc::now().to_rfc3339(),
            vault_meta: VaultMetaDto {
                salt: salt.to_vec(),
                kdf_params: params.clone(),
                verifier_ct: vec![],
                verifier_nonce: vec![],
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            projects: vec![],
            environments: vec![],
            variables: vec![],
        };
        let blob = seal_backup(&key, &snapshot).unwrap();
        let opened = open_backup_with_password(password, &blob).unwrap();
        assert_eq!(opened.magic, SNAPSHOT_MAGIC);
        assert_eq!(opened.vault_meta.salt, salt.to_vec());
    }
}
