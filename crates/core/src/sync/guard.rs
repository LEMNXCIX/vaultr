use super::rows::b64_encode;
use sync::VaultRow;

/// Whether `vltr init` must ask the server whether this account already has a
/// vault before creating a local one — otherwise init creates a second key
/// domain the account can never merge back.
///
/// Both inputs are ACCOUNT-level (sync configured, account session) and must
/// never become per-database: the database being initialized has no session of
/// its own, so a per-database probe would make this `false` on every `init`
/// and silently drop the guard.
pub fn init_remote_guard_needed(sync_configured: bool, account_session: bool) -> bool {
    sync_configured && account_session
}

// ---------- Salt guard (pure) ----------

/// What `sync` must do with the remote vault meta before touching any row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SaltAction {
    /// Server has no vault: push the local meta (first sync from this device).
    PushLocal,
    /// Local and remote salts match: proceed with the normal sync.
    Proceed,
    /// This device rekeyed (marker matches the local salt): push the new
    /// local meta first — rows pushed afterwards are encrypted under it.
    PushRekey,
    /// Remote key changed elsewhere: abort WITHOUT pushing or pulling.
    RemoteKeyChanged,
    /// The remote vault was reset on another device: abort WITHOUT pushing
    /// or pulling, and the caller must ask the user rather than adopt,
    /// because adopting would push this device's pre-wipe rows back over
    /// the wipe.
    RemoteReset,
}

/// Decide how to reconcile local and remote vault salts.
///
/// The salt is not secret; it only identifies the key domain. Mixing rows
/// from two domains leaves ciphertexts nobody can decrypt, so any mismatch
/// without a matching local rekey marker must stop the sync.
/// Local and remote vault state, gathered by the caller so this stays pure.
pub(super) struct SaltInputs<'a> {
    pub(super) local_salt: &'a [u8],
    pub(super) local_epoch: i64,
    pub(super) remote_salt_b64: Option<&'a str>,
    pub(super) remote_epoch: Option<i64>,
    pub(super) remote_key_change: Option<&'a str>,
    pub(super) pending_marker: Option<&'a str>,
}

pub(super) fn salt_action(i: &SaltInputs) -> SaltAction {
    let Some(remote) = i.remote_salt_b64 else {
        return SaltAction::PushLocal;
    };
    if remote == b64_encode(i.local_salt) {
        return SaltAction::Proceed;
    }
    // Salt differs. A remote reset elsewhere wins over everything in this
    // branch — even a pending rekey marker from this device, which must be
    // stale if the remote was wiped after it: pushing our salt back would
    // resurrect pre-wipe rows over the reset.
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch)
        && i.remote_key_change == Some(models::constants::KEY_CHANGE_RESET)
    {
        return SaltAction::RemoteReset;
    }
    // Salt differs. A remote that has rotated past us wins even when this
    // device holds a pending rekey marker: our meta is stale and pushing it
    // would clobber a newer key domain.
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch) {
        return SaltAction::RemoteKeyChanged;
    }
    if i.pending_marker
        .is_some_and(|m| m == hex::encode(i.local_salt))
    {
        return SaltAction::PushRekey;
    }
    SaltAction::RemoteKeyChanged
}

/// True when the remote vault shares our key domain but predates the verifier
/// migration, so this sync should fill in the verifier. Deliberately only for
/// `Proceed`: a salt mismatch must abort before anything is written.
pub(super) fn needs_verifier_backfill(action: SaltAction, remote: Option<&VaultRow>) -> bool {
    matches!(action, SaltAction::Proceed)
        && remote.is_some_and(|v| v.verifier_ct.is_none() && v.verifier_nonce.is_none())
}

// ---------- Pending reset (pure) ----------

/// What a pending local reset must do before the salt guard runs, given the
/// remote state the caller already fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingResetPlan {
    /// A `vaults` row exists: run the wipe, then re-read the remote meta.
    Wipe,
    /// No `vaults` row: there is nothing to wipe, so the marker is already
    /// satisfied. The local vault holds the new domain and the salt guard
    /// takes `PushLocal` to create the row.
    AlreadyWiped,
}

/// Pure decision for [`App::sync`]'s pending-reset branch; the network work it
/// guards needs HTTP, the choice does not.
pub(super) fn plan_pending_reset(remote_vault: Option<&VaultRow>) -> PendingResetPlan {
    if remote_vault.is_some() {
        PendingResetPlan::Wipe
    } else {
        PendingResetPlan::AlreadyWiped
    }
}

/// The epoch a reset publishes: the remote's, plus one.
///
/// Computed at push time, where the remote row is in hand, so it can only ever
/// advance the server's counter — a retry of an interrupted wipe cannot lower
/// it, and the result is what [`salt_action`] needs to see on the next device
/// (`remote_epoch > local_epoch`) to report a reset instead of a password
/// change. Saturating rather than `+ 1`: an overflow panic inside a sync is
/// worse than a counter that stops moving.
pub(super) fn reset_epoch_for(remote_epoch: i64) -> i64 {
    remote_epoch.saturating_add(1)
}

/// Which `key_change` a vault-meta push publishes.
///
/// A `PushLocal` that finishes a pending reset creates the `vaults` row out of
/// the post-reset domain, so it must publish the reset: `init` would tell
/// another device that merely the master password changed, and the adoption
/// it triggers re-pushes that device's pre-wipe rows over the reset. A rekey is
/// its own signal and keeps its own label.
pub(super) fn key_change_for(action: SaltAction, finishing_reset: bool) -> &'static str {
    match action {
        SaltAction::PushRekey => models::constants::KEY_CHANGE_REKEY,
        _ if finishing_reset => models::constants::KEY_CHANGE_RESET,
        _ => models::constants::KEY_CHANGE_INIT,
    }
}
