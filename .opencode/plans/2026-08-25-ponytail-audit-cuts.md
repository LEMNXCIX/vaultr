# Ponytail Audit Cuts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the over-engineering audit findings — delete dead code, remove 4 dependencies (`hkdf`, `sha2`, `subtle`, `getrandom`), and shrink duplicated wrappers. Net ~-100 lines.

**Architecture:** Pure subtraction across `crypto`, `core`, `storage` crates plus removal of the `crates/sync` stub crate. No behavior change except two error messages that get simpler. The memory session agent and the sync-prep schema fields (`owner_id`, `version`) are explicitly KEPT per user decision.

**Tech Stack:** Rust workspace, rusqlite, clap. No new dependencies.

**Spec:** Audit findings from this conversation (2026-08-25). User decisions: keep memory agent (docs/SESSION.md stands); keep sync fields (AGENTS.md convention stands).

## Global Constraints

- Run before finishing every task: `cargo clippy --workspace --all-targets -- -D warnings`
- Run before finishing the whole plan: `cargo fmt --all -- --check && cargo test --workspace && cargo check -p vltr-cli`
- Conventional Commits (English or Spanish), e.g. `chore(crypto): remove unused deps`
- Do not touch `is_readonly`/`allow_export`/`owner_id`/`version` fields
- Do not touch anything in `session.rs` related to the memory agent (`start_memory_agent`, `serve_memory_agent`, descriptor functions)

---

### Task 1: Crypto — delete dead code and drop `subtle`, `hkdf`, `sha2`

**Files:**
- Modify: `crates/crypto/src/lib.rs`
- Modify: `crates/crypto/Cargo.toml`
- Modify: `crates/models/src/constants.rs:28-29`

**Interfaces:**
- Consumes: nothing new.
- Produces: `crypto::passwords_match(a: &SecretString, b: &SecretString) -> bool` keeps its exact signature (CLI calls it). `derive_project_key` and `secure_zero` disappear — verified zero callers repo-wide.

- [ ] **Step 1: Delete dead code**

In `crates/crypto/src/lib.rs`:
- Delete the entire `derive_project_key` function (lines ~94-107).
- Delete the entire `secure_zero` function (lines ~109-111).
- Replace the body of `passwords_match` with plain equality:

```rust
/// Password confirmation helper for CLI prompts.
pub fn passwords_match(a: &SecretString, b: &SecretString) -> bool {
    a.expose_secret() == b.expose_secret()
}
```

- Remove now-unused imports if any remain: `use hkdf::Hkdf;`, `use sha2::Sha256;`, `use zeroize::{Zeroize, Zeroizing}` → becomes `use zeroize::Zeroizing;`.

In `crates/models/src/constants.rs`: delete the `PROJECT_KEY_HKDF_INFO` const and its doc comment.

In `crates/crypto/Cargo.toml`: delete lines for `hkdf`, `sha2`, `subtle`, and `getrandom` (crypto uses `rand`'s OsRng only).

- [ ] **Step 2: Verify**

Run: `cargo test -p crypto && cargo clippy -p crypto -p models -- -D warnings`
Expected: PASS. Existing tests `encrypt_decrypt_roundtrip`, `wrong_key_fails`, `deterministic_derive` still pass.

- [ ] **Step 3: Commit**

```bash
git add crates/crypto crates/models
git commit -m "chore(crypto): remove dead project-key/zero helpers and subtle+hkdf+sha2+getrandom deps"
```

---

### Task 2: Core/session — replace `getrandom`, delete dead fn, inline `label()`

**Files:**
- Modify: `crates/core/src/session.rs`
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/crypto/src/lib.rs` (add one tiny helper)
- Test: existing tests in `crates/core/src/session.rs`

**Interfaces:**
- Produces: `crypto::fill_random(buf: &mut [u8])` — used by `start_memory_agent`.
- Deletes: `session::seconds_remaining()` (zero callers; CLI uses `inspect()`).

- [ ] **Step 1: Add random helper to crypto**

Append to `crates/crypto/src/lib.rs` (near `generate_salt`):

```rust
/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}
```

- [ ] **Step 2: Use it in session.rs and clean up**

In `crates/core/src/session.rs` inside `start_memory_agent`, replace:

```rust
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token)
        .map_err(|e| CoreError::Other(format!("session randomness: {e}")))?;
```

with:

```rust
    let mut token = [0u8; 32];
    crypto::fill_random(&mut token);
```

Delete the public `seconds_remaining` function (lines ~154-157).

Replace `SessionStore::label` + `Display` pair with a single `Display`:

```rust
impl fmt::Display for SessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keyring => "OS keyring",
            Self::Memory => "in-memory agent",
        })
    }
}
```

In `crates/core/Cargo.toml`: delete the `getrandom = { workspace = true }` line.

- [ ] **Step 3: Verify**

Run: `cargo test -p core && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. Session tests pass; no warnings about unused imports.

- [ ] **Step 4: Commit**

```bash
git add crates/core crates/crypto
git commit -m "refactor(core): use crypto::fill_random, drop dead seconds_remaining and label"
```

---

### Task 3: Core — collapse session wrapper trio

**Files:**
- Modify: `crates/core/src/lib.rs:137-144`
- Modify: `crates/core/src/session.rs:149-161`

**Interfaces:**
- Keeps exact signatures of `App::has_keyring_session()` and `App::session_store()` (CLI depends on them).
- Deletes: `session::has_session()` and `session::active_store()` (each had exactly one caller, both delegating to `inspect()`).

- [ ] **Step 1: Inline inspect into App methods**

In `crates/core/src/lib.rs`, replace:

```rust
    pub fn has_keyring_session() -> Result<bool, CoreError> {
        session::has_session()
    }
```

and

```rust
    pub fn session_store() -> Result<Option<session::SessionStore>, CoreError> {
        session::active_store()
    }
```

with:

```rust
    pub fn has_keyring_session() -> Result<bool, CoreError> {
        Ok(session::inspect()?.is_some())
    }

    /// Where the current session is stored, if any (does not refresh the TTL).
    pub fn session_store() -> Result<Option<session::SessionStore>, CoreError> {
        Ok(session::inspect()?.map(|info| info.store))
    }
```

In `crates/core/src/session.rs`, delete `has_session` and `active_store`. Keep `inspect` unchanged.

- [ ] **Step 2: Verify**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo run -p vltr-cli -- status`
Expected: compiles clean; `vltr status` prints session info as before.

- [ ] **Step 3: Commit**

```bash
git add crates/core
git commit -m "refactor(core): inline has_session/active_store into App via inspect"
```

---

### Task 4: Core/backup — make `open_backup` private

**Files:**
- Modify: `crates/core/src/backup.rs:132`

- [ ] **Step 1: Change visibility**

Change `pub fn open_backup(` to `fn open_backup(`. Its only caller is `open_backup_with_password` in the same module.

- [ ] **Step 2: Verify**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no dead_code warning (still called internally).

- [ ] **Step 3: Commit**

```bash
git add crates/core/src/backup.rs
git commit -m "refactor(core): make backup::open_backup private"
```

---

### Task 5: Storage — reuse `parse_uuid` in search

**Files:**
- Modify: `crates/storage/src/lib.rs:312-343`

- [ ] **Step 1: Deduplicate UUID parsing**

Inside the `query_map` closure of `search_variables`, replace the three hand-rolled blocks of the form:

```rust
                id: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
```

with direct helper calls (the closure already returns `rusqlite::Result<_>`, so `?` works):

```rust
                id: parse_uuid(&row.get::<_, String>(0)?)?,
```

Apply the same replacement for `project_id` (column index 1) and `environment_id` (index 3).

- [ ] **Step 2: Verify**

Run: `cargo test -p storage && cargo test -p core`
Expected: PASS. `search_finds_key` in core exercises this path end-to-end.

- [ ] **Step 3: Commit**

```bash
git add crates/storage/src/lib.rs
git commit -m "refactor(storage): reuse parse_uuid in search_variables"
```

---

### Task 6: Delete `crates/sync` stub

**Files:**
- Delete: `crates/sync/` (entire directory)
- Modify: `Cargo.toml` (root)
- Modify: `AGENTS.md` (structure block listing `sync/`)
- Modify: `docs/ARCHITECTURE.md:28`

**Interfaces:**
- Verified prerequisite: no crate depends on `sync` (grep confirmed). Only root `Cargo.toml` references it.

- [ ] **Step 1: Remove the crate and references**

```bash
git rm -r crates/sync
```

Root `Cargo.toml`:
- Remove `"crates/sync",` from `[workspace] members`.
- Remove the `sync = { path = "crates/sync" }` line from `[workspace.dependencies]`.

`AGENTS.md`: in the workspace structure block, delete the line `` sync/     # Stub (Supabase futuro) ``.

`docs/ARCHITECTURE.md:28`: reword "`crates/sync` es un stub. Solo se activará cuando el MVP local esté sólido." → "`crates/sync` se creará cuando el MVP local esté sólido."

- [ ] **Step 2: Verify**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo check -p vltr-cli`
Expected: PASS with `sync` gone from the build graph.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore: remove empty sync crate stub"
```

---

### Task 7: Final verification

- [ ] **Step 1: Full gate (mirrors pre-push hook)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p vltr-cli
```

Expected: all green. Smoke test optional (`vltr status` con un vault temporal) — behavior unchanged by design.

- [ ] **Step 2: Confirm dependency removal**

Check every `crates/*/Cargo.toml` and confirm `hkdf`, `sha2`, `subtle`, `getrandom` no longer appear as declared deps. Pueden aparecer transitivamente en `cargo tree` — eso está bien; el objetivo son las dependencias declaradas del workspace.
