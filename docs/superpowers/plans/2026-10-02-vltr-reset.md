# `vltr reset` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `vltr reset` command that lets someone who has lost their master password start over — wiping the local vault and the remote's live secrets — without ever needing the lost key, plus a divergence prompt so no other device silently resurrects the wiped data.

**Architecture:** A reset rotates to a NEW salt and a new key, bumps `key_epoch`, and records `key_change = 'reset'` on the server. Wiping the remote needs no key at all: a tombstone is a metadata write, so every remote row is re-pushed with `deleted = true` and its ciphertext byte-identical. Another device that finds the epoch advanced and `key_change = 'reset'` stops and asks, instead of adopting automatically and pushing its old rows back over the wipe.

**Tech Stack:** Rust 2021, `rusqlite`, `serde`, `chacha20poly1305` + `argon2` via the `crypto` crate, Supabase/PostgREST, clap.

**Spec:** `docs/superpowers/specs/2026-10-02-vault-reset-recovery-design.md` — sections 4 and 5. Section 6 (`vltr recover`, the Supabase account-password reset) is a **separate plan**, not this one: it touches only the sync client's auth surface and shares nothing with the reset path.

**Branch:** this plan builds on `verifier-key-epoch`. Branch from it, never from `main`: it uses `Storage::set_key_epoch`, `apply_key_rotation`'s `key_epoch` parameter, `VaultRow.key_epoch`/`key_change`, and `verify_key_against_remote` taking `&VaultRow`.

## Load-bearing invariant

**Every epoch bump must rotate the salt.** `salt_action` only consults the epoch when the salts already differ, so salt-equality and epoch-equality are currently locked together: if the salt matches, the epoch is never read. A flow that bumps the epoch while keeping the salt would create state no guard can reason about, and `needs_verifier_backfill` would silently regress the remote epoch.

The reset therefore generates a fresh 16-byte salt (`crypto::generate_salt`) rather than reusing the old one. `crates/storage/src/lib.rs` carries a comment recording this invariant; read it before changing anything about epochs.

## Global Constraints

- Reset **must not require the vault to be unlocked.** The lost password is the entire reason the command exists, so no code path in it may call `require_key()`. Verify this holds.
- Zero-knowledge: nothing decrypted leaves the device; nothing decrypted is logged or placed in an error message. The reset's remote wipe needs no decryption at all.
- A tombstone's `value_encrypted` and `nonce` must come through **byte-identical**. A reset has no key, so re-encrypting is impossible; if a row's ciphertext changes during a reset, that is a bug, not a style issue.
- The confirmation phrase is `RESET IT`, matched exactly — case, single space, nothing trimmed. `RESET`, `reset it`, `RESET  IT` (two spaces) and the empty string must all abort.
- The server's `vaults.key_change` vocabulary is exactly `init`, `rekey`, `reset`. Nothing else.
- Push `vaults` metadata **before** rows. The salt guard is what stops another device mixing domains during that window.
- `pending_local_reset` is written **before** the push and removed **after** it lands, so a network failure retries rather than leaving the remote half-wiped. A reset also clears any prior `pending_rekey_salt`: both markers describe the vault's key state and a reset subsumes both, so never more than one is active.
- The core package is named `vltr-core`, not `core`. Focused test runs use `cargo test -p vltr-core <name>`.
- No new dependency. `rand`/`OsRng` is already used by `crypto::generate_salt`.

## Review Focus

The failure modes most likely to bite a real person, most dangerous first. Each has a test in the task named.

1. **The confirmation accepts something it shouldn't.** Typing `reset it` or `RESET  IT` and proceeding destroys an unrecoverable vault. → Task 6.
2. **A row's ciphertext changes during the wipe.** Then a device that had the old key can no longer read rows it previously owned, and the tombstone claims a deletion the data can't back up. → Task 3.
3. **Another device resurrects the wiped secrets** by adopting the new key automatically and pushing its old rows back. This is the whole reason the divergence prompt exists. → Task 2 and Task 7.
4. **A device restored from a backup cannot sync after the reset.** It has the old salt and the old epoch; the guard must report the reset rather than an opaque wrong-password error, and choosing "keep local" must work. → Task 2.
5. **A network failure mid-wipe leaves the remote with live secrets and a new salt** — the worst possible state, because the salt moved but the rows did not. The marker must make the next sync finish the job. → Task 5.

---

### Task 1: `Storage::reset_vault`

**Files:**
- Modify: `crates/storage/src/lib.rs`
- Test: `crates/storage/src/lib.rs` (module `tests`)

**Interfaces:**
- Consumes: nothing new. `KdfParams`, `Id`, `Utc` already imported there.
- Produces: `pub fn reset_vault(&self, salt: &[u8], kdf_params: &KdfParams, verifier_ct: &[u8], verifier_nonce: &[u8], key_epoch: i64) -> Result<(), StorageError>`
  - Errors `StorageError::NotInitialized` when the vault is not initialized.
  - Deletes every row from `variables`, `environments`, `projects` and `sync_state`, then overwrites the `vault_meta` row's salt, kdf_params, verifier and epoch.
  - No new schema, no migration.

- [ ] **Step 1: Write the failing test**

In `crates/storage/src/lib.rs`'s `tests` module:

```rust
    #[test]
    fn reset_vault_empties_everything_and_installs_the_new_domain() {
        let s = Storage::open_in_memory().unwrap();
        s.init_vault(&[1u8; 16], &KdfParams::default(), b"ct", b"nonce").unwrap();
        let project = s.create_project(&Project::new("p")).unwrap();
        let env = s.create_environment(&project, &Environment::new("local")).unwrap();
        s.create_variable(&Variable::new(&env, "K", "secret")).unwrap();
        SyncState::set(s.conn(), "last_pull", "2026-01-01T00:00:00Z").unwrap();
        assert!(!s.all_variables().unwrap().is_empty());

        let params = KdfParams { m_cost: 2048, t_cost: 1, p_cost: 1, output_len: 32 };
        s.reset_vault(&[9u8; 16], &params, b"new-ct", b"new-nonce", 4).unwrap();

        assert!(s.is_initialized().unwrap(), "the vault still exists after a reset");
        assert!(s.list_projects().unwrap().is_empty());
        assert!(s.all_variables().unwrap().is_empty());
        assert_eq!(SyncState::get(s.conn(), "last_pull").unwrap(), None, "the pull cursor is dropped");
        let meta = s.get_vault_meta().unwrap();
        assert_eq!(meta.salt, vec![9u8; 16]);
        assert_eq!(meta.kdf_params.m_cost, 2048);
        assert_eq!(meta.verifier_ct, b"new-ct".to_vec());
        assert_eq!(meta.verifier_nonce, b"new-nonce".to_vec());
        assert_eq!(meta.key_epoch, 4);
    }

    #[test]
    fn reset_vault_on_uninitialized_vault_errors() {
        let s = Storage::open_in_memory().unwrap();
        assert!(matches!(
            s.reset_vault(&[9u8; 16], &KdfParams::default(), b"c", b"n", 1),
            Err(StorageError::NotInitialized)
        ));
    }
```

Adapt the constructor calls to the real signatures in this crate — read `create_project`, `create_environment` and `create_variable` first and use however they build their arguments. The assertions are the requirement; the setup is mechanical.

- [ ] **Step 2: Run it and confirm it fails**

Run: `cargo test -p storage reset_vault`
Expected: FAIL — `reset_vault` does not exist.

- [ ] **Step 3: Implement `reset_vault`**

In `crates/storage/src/lib.rs`, next to `init_vault` (around line 137):

```rust
    /// Destroy every row and re-install a new key domain on the single
    /// `vault_meta` row. Used by the reset flow, where the previous key is
    /// unrecoverable and its rows cannot be re-encrypted — only deleted.
    ///
    /// `sync_state` is emptied too: the cursor describes rows this vault no
    /// longer has, so carrying it over would silently skip a pull.
    pub fn reset_vault(
        &self,
        salt: &[u8],
        kdf_params: &KdfParams,
        verifier_ct: &[u8],
        verifier_nonce: &[u8],
        key_epoch: i64,
    ) -> Result<(), StorageError> {
        if !self.is_initialized()? {
            return Err(StorageError::NotInitialized);
        }
        let params_json = serde_json::to_string(kdf_params)?;
        let tx = self.conn.unchecked_transaction()?;
        // Children first: variables → environments → projects hold FKs.
        for table in ["variables", "environments", "projects", "sync_state"] {
            tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
        let n = tx.execute(
            "UPDATE vault_meta
             SET salt = ?1, kdf_params = ?2, verifier_ct = ?3, verifier_nonce = ?4,
                 key_epoch = ?5, updated_at = ?6
             WHERE id = 1",
            params![salt, params_json, verifier_ct, verifier_nonce, key_epoch, Utc::now().to_rfc3339()],
        )?;
        if n == 0 {
            return Err(StorageError::NotInitialized);
        }
        tx.commit()?;
        Ok(())
    }
```

The `DELETE FROM {table}` uses `format!` over a fixed literal list — no user input reaches it. If clippy objects to it, use four explicit `execute` calls with literal SQL rather than building the string.

- [ ] **Step 4: Run it and confirm it passes**

Run: `cargo test -p storage reset_vault`
Expected: PASS both tests.

- [ ] **Step 5: Verify the workspace and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/storage/src/lib.rs
git commit -m "feat(storage): reset_vault to install a new key domain"
```

---

### Task 2: Detect a remote reset in the salt guard

**Files:**
- Modify: `crates/core/src/sync.rs` (`SaltAction`, `SaltInputs`, `salt_action`, the `sync` error site)
- Modify: `crates/core/src/lib.rs` (`CoreError`, new `RemoteResetInfo`)
- Test: `crates/core/src/sync.rs` (module `tests`)

**Interfaces:**
- Consumes: `models::constants::KEY_CHANGE_RESET` from the previous plan.
- Produces:
  - `SaltAction::RemoteReset` — a new unit variant, no payload. The caller already holds the remote `VaultRow` and reads `key_epoch`/`key_change`/`key_changed_at` from it.
  - `SaltInputs` gains `remote_key_change: Option<&'a str>`.
  - `pub struct RemoteResetInfo { pub remote_epoch: i64, pub key_change: Option<String>, pub key_changed_at: Option<DateTime<Utc>> }` in `crates/core/src/lib.rs`, exported.
  - `CoreError::RemoteReset(#[source] RemoteResetInfo)` — new variant.

The detection rule, added **inside the salt-differs branch and before the pending-marker check**: remote epoch ahead **and** `key_change == "reset"` → `RemoteReset`. Everything else in that branch is unchanged, so a rekey with the remote ahead still yields `RemoteKeyChanged` and keeps the existing guided-adoption flow.

A device restored from a backup has the old salt and old epoch, so this is the path that must report the reset rather than an opaque failure.

- [ ] **Step 1: Write the failing tests**

In `crates/core/src/sync.rs`'s `tests` module. There is already a `salt_inputs` helper from the previous plan — extend it with the new field, and add:

```rust
    #[test]
    fn remote_reset_is_distinguished_from_a_remote_rekey() {
        let local = [1u8; 16];
        let local_hex = hex::encode(local);
        let other = b64_encode(&[2u8; 16]);

        let mut i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&other),
            remote_epoch: Some(3),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: None,
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteReset);

        // Same shape, but the remote rotated the key rather than being reset.
        i.remote_key_change = Some(models::constants::KEY_CHANGE_REKEY);
        assert_eq!(
            salt_action(&i),
            SaltAction::RemoteKeyChanged,
            "a rekey elsewhere keeps the guided adoption flow"
        );

        // A pre-migration remote row has no key_change: stay conservative.
        i.remote_key_change = None;
        assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn remote_reset_never_triggers_on_matching_salt_or_lower_epoch() {
        let local = [1u8; 16];
        let matching = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&local)),
            remote_epoch: Some(99),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: None,
        };
        assert_eq!(salt_action(&matching), SaltAction::Proceed);

        let mut behind = matching;
        behind.remote_salt_b64 = Some(&b64_encode(&[2u8; 16]));
        behind.local_epoch = 5;
        assert_eq!(salt_action(&behind), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn a_pending_reset_marker_beats_the_rekey_marker_check() {
        // This device has a stale rekey marker and the remote was reset after
        // it. The reset must win, or we would push our stale salt over the wipe.
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(3),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: Some(&hex::encode(local)),
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteReset);
    }
```

Also extend every other `SaltInputs` literal in the test module with `remote_key_change: None` so the module still compiles.

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-core remote_reset`
Expected: FAIL to compile — `SaltAction::RemoteReset` and the `remote_key_change` field do not exist.

- [ ] **Step 3: Add the variant, field and error type**

In `crates/core/src/sync.rs`:

- Add `remote_key_change: Option<&'a str>` to `SaltInputs`.
- Add a `RemoteReset` variant to `SaltAction` with a doc comment saying the remote vault was reset and the caller must ask the user rather than adopt, because adopting would push this device's old rows back over the wipe.
- In `salt_action`, inside the salt-differs branch, before the `pending_marker` check:

```rust
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch)
        && i.remote_key_change == Some(models::constants::KEY_CHANGE_RESET)
    {
        return SaltAction::RemoteReset;
    }
```

In `crates/core/src/lib.rs`, next to `RemoteKeyChanged`:

```rust
/// The remote vault was reset on another device: its epoch advanced and
/// `key_change` says `reset`. Adopting automatically would push this
/// device's pre-wipe rows back over the reset, so the caller must ask.
#[derive(Debug, Clone)]
pub struct RemoteResetInfo {
    pub remote_epoch: i64,
    pub key_change: Option<String>,
    pub key_changed_at: Option<DateTime<Utc>>,
}

#[error("the remote vault was reset on another device")]
RemoteReset(#[source] RemoteResetInfo),
```

Match the file's existing style for `thiserror` variants — if the file's other variants use `#[error(...)]` without `#[source]` attributes, drop the attribute and keep the payload.

At the `sync()` error site, match the new variant and build the info from the row already in hand:

```rust
                SaltAction::RemoteReset => {
                    let v = remote_vault.as_ref().ok_or_else(|| {
                        CoreError::Other("remote reset detected without a remote row".into())
                    })?;
                    return Err(CoreError::RemoteReset(RemoteResetInfo {
                        remote_epoch: v.key_epoch,
                        key_change: v.key_change.clone(),
                        key_changed_at: v.key_changed_at,
                    }));
                }
```

Add `RemoteResetInfo` to the `use crate::{...}` import in `crates/core/src/sync.rs`.

- [ ] **Step 4: Run and confirm it passes**

Run: `cargo test -p vltr-core remote_reset`
Expected: PASS the three new tests. Also run `cargo test -p vltr-core salt` and confirm the pre-existing guard tests still pass — the new check must not have moved the `Proceed` or `PushRekey` branches.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/core/src/sync.rs crates/core/src/lib.rs
git commit -m "feat(core): distinguish a remote reset from a remote rekey"
```

---

### Task 3: Tombstone helpers that preserve ciphertext

**Files:**
- Modify: `crates/core/src/sync.rs` (next to `salt_action` and the other pure helpers)
- Test: `crates/core/src/sync.rs` (module `tests`)

**Interfaces:**
- Consumes: `sync::{ProjectRow, EnvironmentRow, VariableRow}`.
- Produces: three pure functions, each `(row: &XRow, now: DateTime<Utc>) -> XRow`:
  - `fn tombstone_project(row: &ProjectRow, now: DateTime<Utc>) -> ProjectRow`
  - `fn tombstone_environment(row: &EnvironmentRow, now: DateTime<Utc>) -> EnvironmentRow`
  - `fn tombstone_variable(row: &VariableRow, now: DateTime<Utc>) -> VariableRow`

Each sets `deleted = true`, bumps `version` by one, and sets `updated_at = Some(now)`. **Everything else is copied verbatim, especially `value_encrypted` and `nonce`.**

These are the heart of the reset: a tombstone is a metadata write, so the remote can be wiped without the master key. A reset has no key, so it is impossible to re-encrypt — the ciphertext must survive untouched.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn tombstoning_preserves_ciphertext_byte_for_byte() {
        let now = ts(0);
        let row = VariableRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000001".into(),
            environment_id: "018f0000-0000-7000-8000-000000000002".into(),
            key: "SECRET".into(),
            value_encrypted: b64_encode(b"opaque-ciphertext"),
            nonce: b64_encode(b"opaque-nonce-24-bytes-xx"),
            notes: Some("keep me".into()),
            is_readonly: true,
            allow_export: false,
            deleted: false,
            version: 4,
            updated_at: None,
        };

        let dead = tombstone_variable(&row, now);
        assert!(dead.deleted);
        assert_eq!(dead.version, 5);
        assert_eq!(dead.updated_at, Some(now));
        assert_eq!(dead.value_encrypted, row.value_encrypted, "ciphertext must survive");
        assert_eq!(dead.nonce, row.nonce, "nonce must survive");
        assert_eq!(dead.key, row.key);
        assert_eq!(dead.notes, row.notes);
        assert_eq!(dead.owner_id, row.owner_id);
        assert_eq!(dead.is_readonly, row.is_readonly);
        assert_eq!(dead.allow_export, row.allow_export);
    }
```

`ts(mins)` is an existing helper in that test module. If the `VariableRow` literal does not match the real field set, read the DTO and fix the literal — the `value_encrypted`/`nonce` assertions are the requirement.

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-core tombstoning`
Expected: FAIL — `tombstone_variable` does not exist.

- [ ] **Step 3: Implement the three functions**

Each starts from `row.clone()` and overrides the three fields, with a doc comment explaining that the ciphertext is carried through untouched because the reset path has no key to re-encrypt with:

```rust
/// Mark a remote variable as deleted for a reset. The ciphertext and nonce
/// are carried through byte-identical: a reset has no master key, so
/// re-encrypting is impossible, and a row whose ciphertext changed would no
/// longer be readable by any device that still holds the old key.
fn tombstone_variable(row: &VariableRow, now: DateTime<Utc>) -> VariableRow {
    VariableRow {
        deleted: true,
        version: row.version + 1,
        updated_at: Some(now),
        ..row.clone()
    }
}
```

`ProjectRow` and `EnvironmentRow` follow the same shape. Check whether they carry `version` — if `ProjectRow` or `EnvironmentRow` has no `version` field, omit that override rather than adding one.

- [ ] **Step 4: Run and confirm it passes**

Run: `cargo test -p vltr-core tombstoning`
Expected: PASS.

Then confirm the mutation is caught: temporarily make `tombstone_variable` clear `value_encrypted` to `String::new()` and check the test fails, then restore.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/core/src/sync.rs
git commit -m "feat(core): tombstone helpers that preserve ciphertext"
```

---

### Task 4: `App::reset_local` and the pending marker

**Files:**
- Modify: `crates/core/src/sync.rs` (constant + method)
- Modify: `crates/core/src/lib.rs` (`App` impl)
- Test: `crates/core/src/sync.rs`, `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: `crypto::generate_salt`, `crypto::derive_master_key`, `crypto::encrypt`, `Storage::reset_vault` (Task 1), `SyncState::set`/`remove`.
- Produces:
  - `pub const PENDING_LOCAL_RESET_KEY: &str = "pending_local_reset";` in `crates/core/src/sync.rs`, next to `PENDING_REKEY_SALT_KEY`.
  - `pub fn reset_local(&mut self, new_password: SecretString, target_epoch: i64) -> Result<(), CoreError>` on `App`.
  - `App` gains `pub fn pending_reset(&self) -> Result<bool, CoreError>` — true when the marker is set. The CLI and `sync()` need this.

Behaviour: read the current `kdf_params` (reused, not regenerated), generate a fresh 16-byte salt, derive the new key from `new_password` + that salt, encrypt `VAULT_VERIFIER_MESSAGE` under it, call `reset_vault` with `target_epoch`, clear any `pending_rekey_salt`, set `pending_local_reset`, assign `self.master_key = Some(new_key)`, and save the session like `rekey` does.

`reset_local` must not call `require_key()`. The abandoned password is the reason the command exists.

- [ ] **Step 1: Write the failing test**

In `crates/core/src/lib.rs`'s `tests` module:

```rust
    #[test]
    fn reset_local_installs_an_empty_vault_under_a_new_key() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("old-password".into())).unwrap();
        let project = app.create_project("p").unwrap();
        let env = app.default_environment("p").unwrap();
        app.set_variable("p", &env, "K", "secret").unwrap();
        let old_salt = app.storage.get_vault_meta().unwrap().salt;

        // Note: no unlock, and no call supplying the old password anywhere.
        app.reset_local(SecretString::new("brand-new".into()), 7).unwrap();

        assert!(app.storage.list_projects().unwrap().is_empty());
        assert!(app.storage.all_variables().unwrap().is_empty());
        let meta = app.storage.get_vault_meta().unwrap();
        assert_ne!(meta.salt, old_salt, "a reset must rotate the salt, never keep it");
        assert_eq!(meta.key_epoch, 7);
        assert!(!meta.verifier_ct.is_empty());

        // The new password opens it; the old one does not.
        assert!(app.verify_password(SecretString::new("brand-new".into())).is_ok());
        assert!(app.verify_password(SecretString::new("old-password".into())).is_err());

        assert!(app.pending_reset().unwrap());
    }

    #[test]
    fn reset_local_clears_a_pending_rekey_marker() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        app.rekey(SecretString::new("second".into())).unwrap();
        assert!(SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap().is_some());

        app.reset_local(SecretString::new("third".into()), 9).unwrap();
        assert_eq!(SyncState::get(app.storage.conn(), sync::PENDING_REKEY_SALT_KEY).unwrap(), None);
    }
```

Adapt the setup calls to the real signatures — read `create_project`, `default_environment`, `set_variable` and check whether `verify_password` takes a `SecretString` or something else. If `crypto::CIPHERTEXT_OVERHEAD` does not exist, drop that assertion rather than inventing a constant.

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-core reset_local`
Expected: FAIL — `reset_local` and `pending_reset` do not exist.

- [ ] **Step 3: Implement**

In `crates/core/src/sync.rs`, next to `PENDING_REKEY_SALT_KEY`:

```rust
/// `sync_state` marker set by `reset_local`: this device has abandoned its key
/// and installed a new domain locally, but the matching remote wipe may not
/// have landed. A sync with this marker set finishes the wipe before running
/// the salt guard.
pub const PENDING_LOCAL_RESET_KEY: &str = "pending_local_reset";
```

In `crates/core/src/lib.rs`, next to `rekey`:

```rust
    /// Replace the local vault with an empty one under a NEW master key.
    ///
    /// Deliberately does not require an unlocked vault, and never reads
    /// `require_key()`: the lost password is the reason this exists. The old
    /// rows are deleted rather than re-encrypted because their key is gone.
    ///
    /// Records `pending_local_reset` so a later sync pushes the matching
    /// remote wipe, and clears any `pending_rekey_salt` — a reset subsumes
    /// both markers, and only one may be active at a time.
    pub fn reset_local(&mut self, new_password: SecretString, target_epoch: i64) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let kdf_params = self.storage.get_vault_meta()?.kdf_params;
        let salt = crypto::generate_salt();
        let new_key = derive_master_key(&new_password, &salt, &kdf_params)?;
        let (verifier_ct, verifier_nonce) =
            crypto::encrypt(&new_key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.reset_vault(
            &salt,
            &kdf_params,
            &verifier_ct,
            &verifier_nonce,
            target_epoch,
        )?;
        SyncState::remove(self.storage.conn(), sync::PENDING_REKEY_SALT_KEY)?;
        SyncState::set(
            self.storage.conn(),
            sync::PENDING_LOCAL_RESET_KEY,
            &target_epoch.to_string(),
        )?;
        self.last_session_error = session::save_master_key(&new_key)
            .err()
            .map(|e| e.to_string());
        self.master_key = Some(new_key);
        Ok(())
    }

    /// True when a local reset still needs its remote wipe pushed.
    pub fn pending_reset(&self) -> Result<bool, CoreError> {
        Ok(SyncState::get(self.storage.conn(), sync::PENDING_LOCAL_RESET_KEY)?.is_some())
    }
```

Match the file's existing import style — `crypto::generate_salt` may already be imported directly, in which case call `generate_salt()` rather than `crypto::generate_salt()`.

- [ ] **Step 4: Run and confirm it passes**

Run: `cargo test -p vltr-core reset_local`
Expected: PASS both tests.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/core/src/sync.rs crates/core/src/lib.rs
git commit -m "feat(core): reset_local installs a new key domain without unlocking"
```

---

### Task 5: `reset_remote` and the interrupted-wipe retry

**Files:**
- Modify: `crates/core/src/sync.rs`
- Test: `crates/core/src/sync.rs`

**Interfaces:**
- Consumes: `sync::SyncClient::pull_rows`, `push_rows`, `push_vault`, `VaultMetaPush`, the `tombstone_*` helpers (Task 3), `PENDING_LOCAL_RESET_KEY` (Task 4), `Storage::get_vault_meta`.
- Produces:
  - `pub async fn reset_remote(&mut self) -> Result<usize, CoreError>` on `App` — the whole wipe. Returns the number of rows tombstoned.
  - `async fn push_reset(&self, client: &SyncClient, session: &Session, remote: &sync::VaultRow) -> Result<usize, CoreError>` — private, so `sync()` can retry it.

Order inside `push_reset`, and it matters:
1. `push_vault` with the **local** salt, **local** kdf_params, the local verifier, the local epoch, `key_change = "reset"` and `key_changed_at = now()`.
2. `pull_rows` all three tables, tombstone every row, push parents before children (`projects`, then `environments`, then `variables`) so foreign keys hold server-side.
3. `report.pushed` accounting and marker removal are the caller's job.

It requires **no master key** — confirm no call to `require_key()` appears in it.

The `sync()` wiring: when `pending_reset()` is true, call `push_reset` **before** the salt guard runs, then clear the marker. Without this the next sync would see a new local salt against an old remote salt and abort with `RemoteKeyChanged`, leaving the user permanently unable to finish a reset that was interrupted mid-flight. Re-running `push_reset` is safe: tombstoning an already-tombstoned row just bumps its version and `updated_at` again, which the existing LWW merge resolves identically.

- [ ] **Step 1: Write the failing test**

`push_reset` needs HTTP, which the unit suite does not have. Pin the parts that are testable without it — the row conversion and its ordering — as a pure helper:

```rust
    #[test]
    fn reset_tombstones_every_table_and_preserves_parent_order() {
        let now = ts(0);
        let (projects, environments, variables) = reset_tombstone_sets(
            &[sample_project_row()],
            &[sample_environment_row()],
            &[sample_variable_row()],
            now,
        );
        assert_eq!(projects.len(), 1);
        assert_eq!(environments.len(), 1);
        assert_eq!(variables.len(), 1);
        assert!(projects[0].deleted && environments[0].deleted && variables[0].deleted);
        assert_eq!(variables[0].value_encrypted, b64_encode(b"opaque-ciphertext"));
    }
```

where the helper is:

```rust
/// Tombstone every pulled row, grouped so the caller can push parents before
/// children. Pure and order-preserving; the caller does the network.
fn reset_tombstone_sets(
    projects: &[ProjectRow],
    environments: &[EnvironmentRow],
    variables: &[VariableRow],
    now: DateTime<Utc>,
) -> (Vec<ProjectRow>, Vec<EnvironmentRow>, Vec<VariableRow>) {
    (
        projects.iter().map(|r| tombstone_project(r, now)).collect(),
        environments.iter().map(|r| tombstone_environment(r, now)).collect(),
        variables.iter().map(|r| tombstone_variable(r, now)).collect(),
    )
}
```

Build `sample_project_row`, `sample_environment_row` and `sample_variable_row` as local test helpers with `value_encrypted: b64_encode(b"opaque-ciphertext")`. Do not claim this covers the HTTP path — say so in the report.

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-core reset_tombstones`
Expected: FAIL — `reset_tombstone_sets` does not exist.

- [ ] **Step 3: Implement the helper, `push_reset` and `reset_remote`**

Add `reset_tombstone_sets` next to the tombstone helpers.

In `crates/core/src/sync.rs`, next to `adopt_remote_key`:

```rust
    /// Push the remote half of a reset: new vault metadata first, then a
    /// tombstone for every row. Needs no master key — a tombstone is a
    /// metadata write and the ciphertext travels through untouched.
    ///
    /// Idempotent: re-running re-tombstones already-dead rows, bumping their
    /// version and `updated_at`, which the LWW merge resolves the same way.
    /// Returns the number of rows tombstoned.
    async fn push_reset(
        &self,
        client: &SyncClient,
        session: &Session,
        remote: &sync::VaultRow,
    ) -> Result<usize, CoreError> {
        let meta = self.storage.get_vault_meta()?;
        client
            .push_vault(
                session,
                &VaultMetaPush {
                    salt: b64_encode(&meta.salt),
                    kdf_params: serde_json::to_value(&meta.kdf_params)?,
                    verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                    verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                    key_epoch: meta.key_epoch,
                    key_change: models::constants::KEY_CHANGE_RESET.into(),
                    key_changed_at: Some(Utc::now().to_rfc3339()),
                },
            )
            .await?;

        let projects = client.pull_rows::<ProjectRow>(session, "projects").await?;
        let environments = client.pull_rows::<EnvironmentRow>(session, "environments").await?;
        let variables = client.pull_rows::<VariableRow>(session, "variables").await?;
        let (projects, environments, variables) =
            reset_tombstone_sets(&projects, &environments, &variables, Utc::now());
        let count = projects.len() + environments.len() + variables.len();

        // Parents before children: the server enforces the same FKs.
        if !projects.is_empty() {
            client.push_rows(session, "projects", &projects).await?;
        }
        if !environments.is_empty() {
            client.push_rows(session, "environments", &environments).await?;
        }
        if !variables.is_empty() {
            client.push_rows(session, "variables", &variables).await?;
        }
        Ok(count)
    }
```

```rust
    /// Wipe the remote of live secrets and align it with the local vault that
    /// [`App::reset_local`] just installed. Requires a sync session; does not
    /// require the master key.
    pub async fn reset_remote(&mut self) -> Result<usize, CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let client = sync_client()?;
        let session = fresh_session(&client).await?;
        let remote = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;
        let count = self.push_reset(&client, &session, &remote).await?;
        SyncState::remove(self.storage.conn(), PENDING_LOCAL_RESET_KEY)?;
        Ok(count)
    }
```

Then in `sync()`, immediately after `remote_vault` is fetched and **before** the salt guard:

```rust
        // A reset that was interrupted before its remote wipe landed must be
        // finished first. Left to the salt guard it would abort with
        // RemoteKeyChanged forever, since the local salt has already moved.
        if self.pending_reset()? {
            if let Some(remote) = remote_vault.as_ref() {
                let client = sync_client()?;
                let session = fresh_session(&client).await?;
                let count = self.push_reset(&client, &session, remote).await?;
                report.pushed += count + 1;
                SyncState::remove(self.storage.conn(), PENDING_LOCAL_RESET_KEY)?;
            }
        }
```

Reuse the `client` and `session` already built at the top of `sync()` if they are in scope there; do not build a second pair.

- [ ] **Step 4: Run and confirm it passes**

Run: `cargo test -p vltr-core reset_tombstones`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/core/src/sync.rs
git commit -m "feat(core): wipe the remote without the master key, and retry it after a failure"
```

---

### Task 6: The `Reset` CLI command

**Files:**
- Modify: `crates/cli/src/main.rs`
- Test: extracted pure helper in the same file, plus manual verification.

**Interfaces:**
- Consumes: `App::reset_local`, `App::reset_remote`, `App::pending_reset`, `App::remote_has_vault`, `App::is_initialized`, `App::sync_session_exists`, `App::sync_available_config`.
- Produces: a new `Commands::Reset { local: bool }` variant, and a pure helper
  `fn confirmation_matches(input: &str) -> bool` in `crates/cli/src/main.rs`.

`confirmation_matches` is pure and exists so the confirmation rule is unit-testable without a TTY. It must return `true` only for exactly `RESET IT` — no trimming, no case folding, no collapsing internal whitespace. Put a `#[cfg(test)] mod tests` at the bottom of `crates/cli/src/main.rs` if none exists.

`Commands::Reset { #[arg(long)] local: bool }` behaviour, in order:
1. `--local` false and no usable sync session → error naming `vltr login` and `--local`.
2. Print exactly what is lost: the local vault's contents and, when online, the remote's live secrets. State plainly that this is **not** a recovery — data encrypted under the lost key is unrecoverable, and the only thing that can save it is a backup taken before the last rekey.
3. Prompt `Type RESET IT to confirm: `, read a line, and `bail!` unless `confirmation_matches`.
4. Ask for the new master password twice and compare with `crypto::passwords_match`, matching `Rekey`'s existing style.
5. Compute `target_epoch`: fetch the remote vault's epoch when online, `remote + 1`; when the account has no vault row, `1`. Call `App::reset_local`.
6. Unless `--local`, call `reset_remote` and report the tombstoned count. If that fails, say the local reset succeeded but the remote wipe did not, and that the next `vltr sync` retries it — do not pretend it failed.
7. `--local` skips step 6 and says the next `vltr sync` will finish it.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_requires_the_exact_phrase() {
        assert!(confirmation_matches("RESET IT"));
        for rejected in ["", "reset it", "RESET", "RESET  IT", " RESET IT", "RESET IT ", "RESET IT."] {
            assert!(!confirmation_matches(rejected), "must reject {rejected:?}");
        }
    }
}
```

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-cli confirmation`
Expected: FAIL — `confirmation_matches` does not exist.

- [ ] **Step 3: Implement the command**

Add the helper:

```rust
/// The reset confirmation phrase, matched exactly. Not trimmed, not
/// case-folded, not whitespace-collapsed: this phrase arms a destructive,
/// irreversible wipe, and a fuzzy match is a footgun pointed at the user's
/// vault.
fn confirmation_matches(input: &str) -> bool {
    input == "RESET IT"
}
```

Add the enum variant next to `Rekey`:

```rust
    /// Destroy the local vault and start over with a new master password
    /// (use when the current one is lost). Requires typing RESET IT to confirm.
    Reset {
        /// Reset only the local vault; the remote wipe happens on the next sync
        #[arg(long)]
        local: bool,
    },
```

Add the match arm. Read `Commands::Rekey` and `Commands::Sync` first and follow their structure, `anyhow` error style and Spanish/English mix already in the file. Use `prompt_line` for the confirmation and `prompt_password` for the passwords; if `prompt_line` cannot be reused because its prompt styling differs, add a plain variant of it rather than changing its behaviour for other callers.

- [ ] **Step 4: Run and confirm it passes**

Run: `cargo test -p vltr-cli confirmation`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/cli/src/main.rs
git commit -m "feat(cli): reset command with destructive confirmation"
```

---

### Task 7: The divergence prompt

**Files:**
- Modify: `crates/cli/src/main.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/sync.rs`
- Test: `crates/cli/src/main.rs`, `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: `CoreError::RemoteReset`, `App::adopt_remote_key`, `App::bootstrap_from_remote`'s verification approach.
- Produces:
  - `App::discard_local_and_adopt(&mut self, password: SecretString) -> Result<(), CoreError>` in `crates/core/src/lib.rs`.
  - A pure choice parser in `crates/cli/src/main.rs`: `fn divergence_choice(input: &str) -> Option<DivergenceChoice>` where `enum DivergenceChoice { Discard, Keep, Cancel }`, mapping `a`/`d`/`discard` → Discard, `b`/`k`/`keep` → Keep, `c`/`cancel`/empty → Cancel. Unknown input → `None` so the caller re-prompts.

`discard_local_and_adopt` fetches the remote vault, derives the key from **the remote's** salt and kdf params, verifies it against the remote verifier via `verify_key_against_remote` (or `verifier_parts` + `verify_verifier`), then `reset_vault`s the local side with the remote's salt, kdf params, a freshly encrypted verifier under that key, and the remote epoch. The local vault ends up empty and in the remote's key domain, which is exactly what option (a) means after a reset.

It must clear `pending_local_reset`, since the remote wipe has already landed by the time a device sees this prompt.

In `Commands::Sync`, the existing `Err(CoreError::RemoteKeyChanged)` arm gains a sibling `Err(CoreError::RemoteReset(info))` arm that:
- prints the epoch and `key_changed_at` from `info` so the user can see when it happened,
- explains that a reset wipes the remote's secrets and asks which they want,
- on **Discard** asks for the master password and calls `discard_local_and_adopt`, then retries the sync once,
- on **Keep** asks for the master password and calls `adopt_remote_key` (which re-encrypts local rows under the new key and pushes them), then retries the sync once,
- on **Cancel** returns an explanatory error and changes nothing — this is the default on an empty line, because the vault keeps working locally with its old key and only stays unsynced.

The retry-once pattern already exists in the `RemoteKeyChanged` arm; follow it rather than inventing a loop. If the retry again aborts, surface that rather than looping.

- [ ] **Step 1: Write the failing tests**

In `crates/cli/src/main.rs`'s test module:

```rust
    #[test]
    fn divergence_choice_defaults_to_cancel() {
        assert_eq!(divergence_choice(""), Some(DivergenceChoice::Cancel));
        assert_eq!(divergence_choice("c"), Some(DivergenceChoice::Cancel));
        assert_eq!(divergence_choice("a"), Some(DivergenceChoice::Discard));
        assert_eq!(divergence_choice("keep"), Some(DivergenceChoice::Keep));
        assert_eq!(divergence_choice("maybe"), None, "unknown input re-prompts");
    }
```

In `crates/core/src/lib.rs`'s test module, a storage-level check that the discard path leaves an empty vault in the new domain is not reachable without HTTP — so instead assert the invariant the method depends on:

```rust
    #[test]
    fn reset_vault_leaves_no_rows_behind_for_discard() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("pw".into())).unwrap();
        let project = app.create_project("p").unwrap();
        let env = app.default_environment("p").unwrap();
        app.set_variable("p", &env, "K", "v").unwrap();
        app.storage.reset_vault(
            &[7u8; 16],
            &app.storage.get_vault_meta().unwrap().kdf_params,
            b"ct",
            b"nonce",
            5,
        ).unwrap();
        assert!(app.storage.list_projects().unwrap().is_empty());
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 5);
    }
```

Say plainly in the report that `discard_local_and_adopt` itself is only covered by unit tests at this layer; its HTTP path is not covered, and the E2E checklist in the docs is the manual coverage.

- [ ] **Step 2: Run and confirm it fails**

Run: `cargo test -p vltr-cli divergence_choice`
Expected: FAIL — `divergence_choice` does not exist.

- [ ] **Step 3: Implement `discard_local_and_adopt`**

In `crates/core/src/lib.rs`:

```rust
    /// Discard the local vault and adopt the remote's key domain, keeping the
    /// given master password. For the divergence prompt's "discard local"
    /// choice: after a remote reset the remote holds no live secrets, so both
    /// devices end up aligned on an empty vault.
    pub async fn discard_local_and_adopt(&mut self, password: SecretString) -> Result<(), CoreError> {
        if !self.storage.is_initialized()? {
            return Err(CoreError::Other("vault not initialized".into()));
        }
        let client = sync::client()?;
        let session = sync::fresh_session(&client).await?;
        let remote = client
            .get_vault(&session)
            .await?
            .ok_or_else(|| CoreError::Other("no vault found on the server".into()))?;
        let salt = sync::b64_decode(&remote.salt)?;
        let kdf_params: KdfParams = serde_json::from_value(remote.kdf_params)
            .map_err(|e| CoreError::Other(format!("invalid kdf params on server: {e}")))?;
        let key = crypto::derive_master_key(&password, &salt, &kdf_params)?;
        sync::verify_key_against_remote(&client, &session, &key, &remote).await?;
        let (verifier_ct, verifier_nonce) =
            crypto::encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        self.storage.reset_vault(&salt, &kdf_params, &verifier_ct, &verifier_nonce, remote.key_epoch)?;
        SyncState::remove(self.storage.conn(), sync::PENDING_LOCAL_RESET_KEY)?;
        self.last_session_error = session::save_master_key(&key).err().map(|e| e.to_string());
        self.master_key = Some(key);
        Ok(())
    }
```

`sync_client()`, `fresh_session()`, `b64_decode`, `verify_key_against_remote` and `PENDING_LOCAL_RESET_KEY` are private to `crates/core/src/sync.rs` today. If they are not reachable from `lib.rs`, the honest options are to make the ones needed `pub(crate)` or to place this method in `sync.rs` instead of `lib.rs`. **Prefer placing it in `sync.rs`** — that keeps the sync plumbing private and avoids widening visibility. If you do that, say so in the report and adapt the paths.

- [ ] **Step 4: Implement the CLI arm**

Add the enum and parser, then the `RemoteReset` match arm in `Commands::Sync`. Read the existing `RemoteKeyChanged` arm first and mirror its retry-once structure, its Spanish error strings and its `open_and_unlock` usage.

- [ ] **Step 5: Run and confirm it passes**

Run: `cargo test -p vltr-cli divergence_choice` and `cargo test -p vltr-core reset_vault`
Expected: PASS.

- [ ] **Step 6: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

```bash
git add crates/cli/src/main.rs crates/core/src/lib.rs crates/core/src/sync.rs
git commit -m "feat(cli): ask what to do when another device reset the vault"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/SYNC.md`

**Interfaces:**
- Consumes: the behaviour of Tasks 1-7.
- Produces: nothing in code.

- [ ] **Step 1: Document `vltr reset`**

Add a section to `docs/SYNC.md` next to the master-key material, in Spanish and matching the file's voice. It must state:

- what the command does and that it requires typing `RESET IT`,
- that it is **not** a recovery — data encrypted under the lost key is unrecoverable, and only a backup taken before the last `rekey` can save it,
- that `--local` resets just this device and the remote wipe happens on the next `vltr sync`,
- that the remote wipe works without the master key, because a tombstone is a metadata write and the ciphertext is never re-encrypted,
- that the local salt is rotated, which is what makes other devices notice.

Do **not** document `vltr recover` here. It does not exist yet — it is spec section 6, a separate plan. Referencing a command the binary does not have is the kind of doc defect that sends a user looking for a flag that isn't there.

Verify each claim against the code before writing it. If the implementation differs from any of the above, write what the code does and say so in your report.

- [ ] **Step 2: Document the divergence prompt**

Add the three choices — discard local, keep local, cancel — with what each does to local data and to the remote, and state that cancel is the default and leaves the local vault working but unsynced.

- [ ] **Step 3: Add E2E checklist items**

Add steps covering: a reset with the wrong confirmation phrase aborts untouched; a successful reset leaves the remote with zero live rows; a second device prompts on its next sync and its three choices do what the docs say; a reset interrupted mid-wipe is completed by the next sync.

CLARIFIED 2026-10-03: the `.test` TLD **is** rejected by signup (`400 Email address "…" is invalid`), so this note was right. What was wrong was the conclusion drawn from it — that the account was unusable. `e2e@vaultr.test` exists, is confirmed and authenticates; it was SQL-seeded, which is why its bcrypt cost is 6 rather than the default 10. `signup` on an existing address returns a fabricated 200 without creating a row. The real blocker was the seeded vault's unknown master password, solved with `vltr reset`.

- [ ] **Step 4: Verify and commit**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

```bash
git add docs/SYNC.md
git commit -m "docs(sync): document reset and the divergence prompt"
```

---

## Execution notes

- **This plan has no server migration.** Every column it needs landed in `0002_key_epoch_verifier.sql`. If you find yourself wanting a new column, that is a design question, not an implementation detail — stop and report.
- **PARTLY SUPERSEDED 2026-10-03.** Claim (1) was wrong in the other direction: `.test` *is* rejected by signup, so this note was right; what was wrong was inferring that the existing account was unusable — it works, because it was SQL-seeded. Claim (2) stands and grew: the HTTP paths are covered by five integration tests against a PostgREST harness (`crates/core/tests/reset_sync_http.rs`, `bulk_push_http.rs`) plus an end-to-end run against the live project, which found `PGRST102` and the adoption bug the harness had missed. Checklist points 11, 12, 14–20 executed; only point 13, which needs a second account, is outstanding.
- **Do not write to the Supabase project** while implementing this plan. The reset's whole point is to wipe a remote, and this project's remote holds the user's real 101 encrypted variables.