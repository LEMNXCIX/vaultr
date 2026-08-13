//! Cryptographic primitives: Argon2id key derivation + XChaCha20-Poly1305 AEAD.

use aead::{Aead, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use models::KdfParams;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// 32-byte master key, zeroized on drop.
pub type MasterKey = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("argon2 error: {0}")]
    Argon2(String),
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed (wrong key or corrupted data)")]
    Decryption,
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("invalid key length")]
    InvalidKey,
}

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Cryptographically secure random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte master key with Argon2id (raw KDF, not PHC string hashing).
pub fn derive_master_key(
    password: &SecretString,
    salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::Argon2("salt too short".into()));
    }
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(Zeroizing::new(key))
}

/// Encrypt plaintext. Returns `(ciphertext, nonce)`.
pub fn encrypt(master_key: &MasterKey, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(master_key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::Encryption)?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt ciphertext with the given nonce.
pub fn decrypt(
    master_key: &MasterKey,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<String>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(master_key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)?;
    let s = String::from_utf8(plaintext).map_err(|_| CryptoError::Decryption)?;
    Ok(Zeroizing::new(s))
}

/// HKDF project key (prepared for future sharing).
pub fn derive_project_key(
    master_key: &MasterKey,
    project_id: &[u8],
) -> Result<MasterKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(
        Some(models::constants::PROJECT_KEY_HKDF_INFO),
        master_key.as_ref(),
    );
    let mut okm = [0u8; KEY_LEN];
    hk.expand(project_id, &mut okm)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(Zeroizing::new(okm))
}

pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Constant-time-ish password confirmation helper for CLI (not crypto-auth).
pub fn passwords_match(a: &SecretString, b: &SecretString) -> bool {
    use subtle::ConstantTimeEq;
    let a = a.expose_secret().as_bytes();
    let b = b.expose_secret().as_bytes();
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let password = SecretString::new("correct horse battery staple".into());
        let salt = generate_salt();
        let params = KdfParams::default();
        let key = derive_master_key(&password, &salt, &params).unwrap();
        let plaintext = "sk-proj-very-secret-api-key-12345";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(recovered.as_str(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let salt = generate_salt();
        let params = KdfParams::default();
        let key1 =
            derive_master_key(&SecretString::new("password1".into()), &salt, &params).unwrap();
        let key2 =
            derive_master_key(&SecretString::new("password2".into()), &salt, &params).unwrap();
        let (ct, nonce) = encrypt(&key1, "secret").unwrap();
        assert!(decrypt(&key2, &ct, &nonce).is_err());
    }

    #[test]
    fn deterministic_derive() {
        let password = SecretString::new("same".into());
        let salt = [7u8; 16];
        let params = KdfParams::default();
        let a = derive_master_key(&password, &salt, &params).unwrap();
        let b = derive_master_key(&password, &salt, &params).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
