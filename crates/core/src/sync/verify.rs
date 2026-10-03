use crypto::{decrypt, MasterKey};

use super::rows::b64_decode;
use crate::CoreError;
use sync::{Session, SyncClient, VariableRow, VaultRow};

/// Decide how to verify a derived key against the remote vault, given what
/// the `vaults` row carries. Pure; unit-testable without HTTP.
///
/// A complete verifier pair is the strongest signal: it is independent of the
/// vault's contents, so an empty vault still rejects a wrong password. A row
/// written before the verifier migration has neither field and falls back to
/// the sample. A verifier without a nonce is a half-written row and must not
/// be mistaken for "no verifier".
#[allow(clippy::type_complexity)]
pub(super) fn verifier_parts(vault: &VaultRow) -> Result<Option<(Vec<u8>, Vec<u8>)>, CoreError> {
    match (&vault.verifier_ct, &vault.verifier_nonce) {
        (None, None) => Ok(None),
        (Some(ct), Some(nonce)) => Ok(Some((b64_decode(ct)?, b64_decode(nonce)?))),
        _ => Err(CoreError::RemoteVerifierIncomplete),
    }
}

/// Verify a master key against the remote verifier ciphertext.
pub(super) fn verify_verifier(key: &MasterKey, ct: &[u8], nonce: &[u8]) -> Result<(), CoreError> {
    let plaintext = decrypt(key, ct, nonce).map_err(|_| CoreError::invalid_password())?;
    if plaintext.as_str() == models::constants::VAULT_VERIFIER_MESSAGE {
        Ok(())
    } else {
        Err(CoreError::invalid_password())
    }
}

/// Verify a derived key against a sample of remote variable ciphertexts.
/// Prefers a live row, falling back to any row (tombstones still carry a
/// ciphertext). An empty sample — remote exists but has no variables yet —
/// is accepted: there is nothing to check against. Pure; unit-testable.
pub(super) fn verify_key_against_sample(
    key: &MasterKey,
    sample: &[VariableRow],
) -> Result<(), CoreError> {
    let Some(first) = sample
        .iter()
        .find(|r| !r.deleted)
        .or_else(|| sample.first())
    else {
        return Ok(());
    };
    let ct = b64_decode(&first.value_encrypted)?;
    let nonce = b64_decode(&first.nonce)?;
    if decrypt(key, &ct, &nonce).is_err() {
        return Err(CoreError::InvalidPassword(
            "la contraseña no descifra el vault remoto; revísala e inténtalo de nuevo".into(),
        ));
    }
    Ok(())
}

/// Verify a derived key against the remote vault. Prefers the verifier
/// ciphertext, which works regardless of how many variables exist; falls back
/// to a sample of variable ciphertexts for vaults predating the verifier
/// migration. A wrong password yields `CoreError::InvalidPassword`.
pub(super) async fn verify_key_against_remote(
    client: &SyncClient,
    session: &Session,
    key: &MasterKey,
    vault: &VaultRow,
) -> Result<(), CoreError> {
    if let Some((ct, nonce)) = verifier_parts(vault)? {
        return verify_verifier(key, &ct, &nonce);
    }
    let sample = client
        .pull_page::<VariableRow>(session, "variables")
        .await?;
    verify_key_against_sample(key, &sample)
}
