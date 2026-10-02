# Verificador remoto y key epoch — Plan 1

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reemplazar la verificación de contraseña por muestra de ciphertext por un verificador cifrado en el servidor, y añadir un `key_epoch` que impida que un dispositivo con un rekey viejo pise un remoto más nuevo.

**Architecture:** El servidor gana columnas en `vaults` (`verifier_ct`, `verifier_nonce`, `key_epoch`, `key_change`, `key_changed_at`). El verificador es el mensaje constante `vault-ok` cifrado con la master key actual: probar la contraseña pasa a ser descifrarlo, sin depender de que el vault tenga variables. El epoch distingue "el remoto cambió antes que yo" de "yo cambié y todavía no subí". Ambas son compatibles hacia atrás vía `NULL`/defaults.

**Tech Stack:** Rust 2021, `rusqlite` (bundled), `serde`, `argon2`/`chacha20poly1305` vía el crate `crypto`, Supabase/PostgREST, SQL migraciones.

**Spec:** `docs/superpowers/specs/2026-10-02-vault-reset-recovery-design.md`

Este plan cubre la sección 1–3 del spec. **No** cubre el comando `vltr reset`, ni `vltr recover`, ni el prompt a/b/c de la sección 5: son el Plan 2.

## Global Constraints

- `VAULT_VERIFIER_MESSAGE` es `"vault-ok"` (`crates/models/src/constants.rs:7`). No cambiar su valor: los vaults existentes lo tienen cifrado.
- `kdf_params` se serializa como JSON de `models::KdfParams` (`m_cost`, `t_cost`, `p_cost`, `output_len`).
- Zero-knowledge: por el cable solo viajan ciphertext, `salt` y `kdf_params`. El verificador remoto **no** es un secreto del usuario — es un mensaje constante cifrado — pero el plan no introduce ninguna otra cosa que descifre valores.
- Todo error de contraseña debe ser `CoreError::InvalidPassword`, nunca `CoreError::Other`.
- Migraciones SQLite: archivo nuevo bajo `crates/storage/migrations/NNN_name.sql` **y** registro en `MIGRATIONS` de `crates/storage/src/migrations.rs`. Nunca editar SQL ya aplicado.
- Migración Supabase: archivo nuevo bajo `supabase/migrations/`, applied-only-additive (sin `drop`).
- Ningún archivo nuevo de código en `core` que contenga lógica de negocio de sync: `crates/core/src/sync.rs` ya la tiene y sigue siendo su casa.
- Base de test de Supabase: `https://qabqeiyyviauvxzmblze.supabase.co`, publishable key `sb_publishable_Cmt3PDbV0ACaOMLHW01Ong_pJ1WhzWE` (solo lectura/anón; nunca `service_role`).
- La cuenta `e2e@vaultr.test` **no sirve** para signup ni recovery: GoTrue la rechaza con `400 email_address_invalid`. Para cualquier prueba que necesite sesión hay que usar una dirección entregable real.

## Review Focus

Cinco modos de fallo que el spec implica y que es más probable que muerda a una persona real. Cada línea tiene su test en la tarea indicada.

1. **Vault remoto vacío con verificador presente, contraseña incorrecta** → debe rechazar. Hoy `verify_key_against_sample` acepta cualquier contraseña cuando no hay variables (`sync.rs:476`); con verificador presente ese hole se cierra. → Task 4.
2. **Servidor viejo sin columnas nuevas** (`verifier_ct` a `NULL`) → el fallback por muestra debe seguir funcionando y nunca rechazar una contraseña correcta. → Task 4.
3. **Rekey local con marcador, pero el remoto ya tiene un epoch mayor** → el sync debe abortar, no pisar el remoto con el meta local viejo. → Task 6.
4. **`verifier_ct` presente pero `verifier_nonce` ausente** (escritura a medio hacer, o fila editada a mano) → error explícito, no panic y no "verificación Skyfalla en silencio".
5. **Backfill del verificador**: un vault que ya existía sin verificador debe quedar con verificador tras un sync, y el backfill **no** debe alterar `salt`, `kdf_params` ni `key_epoch`. → Task 7.

---

### Task 1: Migración del servidor `vaults`

**Files:**
- Create: `supabase/migrations/0002_key_epoch_verifier.sql`

**Interfaces:**
- Consumes: nada.
- Produces: columnas `verifier_ct text`, `verifier_nonce text`, `key_epoch bigint not null default 1`, `key_change text not null default 'init'`, `key_changed_at timestamptz` en `public.vaults`. `vaults` tiene hoy 5 columnas y una fila con `key_epoch = 1` implícito.

- [ ] **Step 1: Crear el archivo de migración**

`supabase/migrations/0002_key_epoch_verifier.sql`:

```sql
-- Remote verifier + key epoch.
--
-- verifier_ct/verifier_nonce hold VAULT_VERIFIER_MESSAGE ("vault-ok") encrypted
-- under the current master key. The server stores ciphertext of a known
-- constant, so this leaks nothing. It lets the client prove possession of the
-- master key without depending on the vault having any variables.
--
-- key_epoch increments on every rekey and every reset. A device whose local
-- epoch is behind the remote must not overwrite the remote meta.
--
-- Additive only: nullable columns and defaults keep pre-existing rows valid.

alter table public.vaults
  add column verifier_ct    text,
  add column verifier_nonce text,
  add column key_epoch      bigint not null default 1,
  add column key_change     text not null default 'init',
  add column key_changed_at timestamptz;

comment on column public.vaults.verifier_ct is
  'ciphertext of VAULT_VERIFIER_MESSAGE under the current master key; nullable for vaults predating this migration';
comment on column public.vaults.key_epoch is
  'incremented on every rekey and reset; guards against stale devices overwriting newer vault meta';
comment on column public.vaults.key_change is
  'init | rekey | reset — why key_epoch last changed';
```

- [ ] **Step 2: Aplicar la migración con el MCP de Supabase**

Usar `tools["supabase-vaultr"].apply_migration` con el nombre `key_epoch_verifier` y el SQL de arriba.

Expected: la herramienta responde sin error.

- [ ] **Step 3: Verificar las columnas con una query de solo lectura**

Ejecutar por `tools["supabase-vaultr"].execute_sql`:

```sql
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema='public' and table_name='vaults'
order by ordinal_position;
```

Expected: 10 filas, incluyendo `verifier_ct` y `verifier_nonce` con `is_nullable = 'YES'` y `column_default` nulo, y `key_epoch` con `column_default` `'1'`.

- [ ] **Step 4: Confirmar que la fila existente conservó su contenido**

Ejecutar:

```sql
select count(*) as vaults, min(key_epoch) as min_epoch, min(key_change) as change_kind
from public.vaults;
```

Expected: `vaults = 1`, `min_epoch = 1`, `change_kind = 'init'`. Si `vaults` fuera 0, parar y reportar: el proyecto de test no tiene la fila esperada.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/0002_key_epoch_verifier.sql
git commit -m "feat(sync): add remote verifier and key_epoch to vaults"
```

---

### Task 2: DTO y push de `vaults`

**Files:**
- Modify: `crates/sync/src/dto.rs:9-14` (`VaultRow`)
- Modify: `crates/sync/src/lib.rs:53-83` (`push_vault`, `get_vault`)
- Test: `crates/sync/src/dto.rs` (módulo `tests` existente, línea ~139)

**Interfaces:**
- Consumes: columnas de la Task 1.
- Produces:
  - `sync::VaultRow` con `verifier_ct: Option<String>`, `verifier_nonce: Option<String>`, `key_epoch: i64`, `key_change: Option<String>`, `key_changed_at: Option<DateTime<Utc>>`. Todos con `#[serde(default)]`.
  - `sync::VaultMetaPush { salt: String, kdf_params: serde_json::Value, verifier_ct: Option<String>, verifier_nonce: Option<String>, key_epoch: i64, key_change: String, key_changed_at: Option<String> }`, derivando `Debug, Clone, Serialize, Deserialize, PartialEq`.
  - `SyncClient::push_vault(&self, session: &Session, meta: &VaultMetaPush) -> Result<()>` — **firma cambiada**, reemplaza la de `(session, salt_b64, kdf_params_json)`.

- [ ] **Step 1: Escribir el test que falla**

En el módulo `tests` de `crates/sync/src/dto.rs`, agregar:

```rust
#[test]
fn vault_row_parses_post_migration_shape() {
    let json = r#"{
        "owner_id": "u",
        "salt": "c2FsdA==",
        "kdf_params": {"m_cost": 19456, "t_cost": 2, "p_cost": 1, "output_len": 32},
        "verifier_ct": "Y3Q=",
        "verifier_nonce": "bm9uY2U=",
        "key_epoch": 3,
        "key_change": "reset",
        "key_changed_at": "2026-10-02T00:00:00Z"
    }"#;
    let row: VaultRow = serde_json::from_str(json).unwrap();
    assert_eq!(row.verifier_ct.as_deref(), Some("Y3Q="));
    assert_eq!(row.key_epoch, 3);
    assert_eq!(row.key_change.as_deref(), Some("reset"));
}

#[test]
fn vault_row_parses_pre_migration_shape_with_defaults() {
    // Row written before 0002_key_epoch_verifier: no verifier, no epoch.
    let json = r#"{"salt": "c2FsdA==", "kdf_params": {"m_cost": 19456, "t_cost": 2, "p_cost": 1, "output_len": 32}}"#;
    let row: VaultRow = serde_json::from_str(json).unwrap();
    assert_eq!(row.verifier_ct, None);
    assert_eq!(row.verifier_nonce, None);
    assert_eq!(row.key_epoch, 1, "missing key_epoch defaults to 1");
    assert_eq!(row.key_change, Some("init".into()));
    assert_eq!(row.key_changed_at, None);
}
```

- [ ] **Step 2: Correr el test y verificar que falla**

Run: `cargo test -p sync vault_row_parses`
Expected: FAIL con error de compilación — `VaultRow` no tiene los campos `verifier_ct` ni `key_epoch`.

- [ ] **Step 3: Extender `VaultRow`**

Reemplazar la definición en `crates/sync/src/dto.rs:9-14` por:

```rust
pub struct VaultRow {
    pub owner_id: Option<String>,
    /// base64
    pub salt: String,
    pub kdf_params: serde_json::Value,
    /// base64 ciphertext of `VAULT_VERIFIER_MESSAGE` under the current master key.
    /// `None` for vaults written before 0002_key_epoch_verifier.
    #[serde(default)]
    pub verifier_ct: Option<String>,
    #[serde(default)]
    pub verifier_nonce: Option<String>,
    #[serde(default = "default_key_epoch")]
    pub key_epoch: i64,
    #[serde(default = "default_key_change")]
    pub key_change: Option<String>,
    #[serde(default)]
    pub key_changed_at: Option<DateTime<Utc>>,
}

fn default_key_epoch() -> i64 {
    1
}

fn default_key_change() -> Option<String> {
    Some("init".to_string())
}
```

`chrono::{DateTime, Utc}` y `serde::{Deserialize, Serialize}` ya están importados en `dto.rs:5-6` y `VaultRow` ya deriva `Deserialize`, así que no hace falta tocar imports.

- [ ] **Step 4: Correr el test y verificar que pasa**

Run: `cargo test -p sync vault_row_parses`
Expected: PASS, los dos tests.

- [ ] **Step 5: Agregar `VaultMetaPush` y cambiar `push_vault`**

Agregar `use chrono::{DateTime, Utc};` a los imports de `crates/sync/src/lib.rs` (hoy solo importa `serde::{de::DeserializeOwned, Serialize}`), y reemplazar `push_vault` (`crates/sync/src/lib.rs:53-67`) por:

```rust
/// Body sent to `vaults`. A struct rather than a parameter list: the row has
/// enough fields that positional args stop being readable at the call site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultMetaPush {
    pub salt: String,
    pub kdf_params: serde_json::Value,
    pub verifier_ct: Option<String>,
    pub verifier_nonce: Option<String>,
    pub key_epoch: i64,
    pub key_change: String,
    pub key_changed_at: Option<String>,
}

/// Upsert into `vaults` keyed by `owner_id` (its primary key).
pub async fn push_vault(&self, session: &Session, meta: &VaultMetaPush) -> Result<()> {
    let mut row = VaultRow {
        owner_id: Some(session.user_id.clone()),
        salt: meta.salt.clone(),
        kdf_params: meta.kdf_params.clone(),
        verifier_ct: meta.verifier_ct.clone(),
        verifier_nonce: meta.verifier_nonce.clone(),
        key_epoch: meta.key_epoch,
        key_change: Some(meta.key_change.clone()),
        key_changed_at: None,
    };
    if let Some(ts) = &meta.key_changed_at {
        row.key_changed_at = Some(
            DateTime::parse_from_rfc3339(ts)
                .map_err(|e| SyncError::Config(format!("invalid key_changed_at: {e}")))?
                .with_timezone(&Utc),
        );
    }
    self.post_upsert(session, "vaults", "owner_id", &[row]).await
}
```

`push_vault` deja de aceptar `kdf_params_json: &str` y de parsearlo: el caller ya tiene el valor `serde_json::Value` vía `get_vault_meta`. Eso elimina el `SyncError::Config` por JSON inválido en este camino.

- [ ] **Step 6: Correr el check del crate**

Run: `cargo clippy -p sync --all-targets`
Expected: el crate `sync` compila. Los errores por la firma vieja de `push_vault` son esperables en `core` y se resuelven en la Task 3; si el compilador los reporta, agregar `#[allow]` no — seguir hasta la Task 3.

Si el error bloquea el clippy de `sync`, usar `cargo check -p sync` y anotar que el fallo restante es el de `core`.

- [ ] **Step 7: Commit**

```bash
git add crates/sync/src/dto.rs crates/sync/src/lib.rs
git commit -m "feat(sync): extend VaultRow with verifier and epoch, push via struct"
```

---

### Task 3: `key_epoch` en el vault local

**Files:**
- Create: `crates/storage/migrations/003_key_epoch.sql`
- Modify: `crates/storage/src/migrations.rs` (array `MIGRATIONS`, ~línea 30)
- Modify: `crates/models/src/lib.rs:15-23` (`VaultMeta`)
- Modify: `crates/storage/src/lib.rs:139-170` (`get_vault_meta`)
- Modify: `crates/storage/src/lib.rs:184-224` (`apply_key_rotation`)
- Modify: `crates/storage/src/lib.rs:832` (test `init_vault` call site)
- Modify: `crates/core/src/backup.rs:162` (restauración: sin cambio de firma necesario)
- Test: `crates/storage/src/migrations.rs` (`runs_initial_migration`), `crates/storage/src/lib.rs`

**Interfaces:**
- Consumes: nada de Tasks anteriores.
- Produces:
  - `models::VaultMeta` gana `key_epoch: i64`.
  - `Storage::get_vault_meta()` incluye `key_epoch` en el `SELECT`.
  - `Storage::apply_key_rotation(&self, reencrypted: &[(Id, Vec<u8>, Vec<u8>)], salt: &[u8], kdf_params: &KdfParams, verifier_ct: &[u8], verifier_nonce: &[u8], key_epoch: i64)` — **firma cambiada**, nuevo parámetro al final.
  - `Storage::set_key_epoch(&self, epoch: i64) -> Result<(), StorageError>` — nuevo. Usado por el Plan 2; se agrega ahora para que el epoch sea escribible sin abrir otra migración.
  - `Storage::current_migration_version()` no cambia. `migrations::current_version` sigue igual.

- [ ] **Step 1: Escribir el test de migración que falla**

En el módulo `tests` de `crates/storage/src/migrations.rs`, agregar:

```rust
#[test]
fn key_epoch_defaults_to_one_and_is_writable() {
    let conn = Connection::open_in_memory().unwrap();
    run(&conn).unwrap();
    assert_eq!(current_version(&conn).unwrap(), 3);

    let epoch: i64 = conn
        .query_row("SELECT key_epoch FROM vault_meta WHERE id = 1", [], |r| r.get(0))
        .unwrap_or_default();
    assert_eq!(epoch, 0, "no vault_meta row yet; query yields default");

    conn.execute(
        "INSERT INTO vault_meta (id, salt, kdf_params, verifier_ct, verifier_nonce, created_at, updated_at, key_epoch)
         VALUES (1, x'00', '{}', x'00', x'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 7)",
        [],
    ).unwrap();
    let epoch: i64 = conn
        .query_row("SELECT key_epoch FROM vault_meta WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(epoch, 7);
}
```

El `assert_eq!(epoch, 0, ...)` usa `unwrap_or_default` porque la tabla está vacía; el punto del test es que el `INSERT` sin `key_epoch` explícito funciona y que la columna existe.

- [ ] **Step 2: Correr el test y verificar que falla**

Run: `cargo test -p storage key_epoch_defaults_to_one_and_is_writable`
Expected: FAIL — `current_version` devuelve 2, no 3, o `no such column: key_epoch`.

- [ ] **Step 3: Crear la migración y registrarla**

`crates/storage/migrations/003_key_epoch.sql`:

```sql
-- Key epoch on the local vault meta.
--
-- Mirrors the server-side `vaults.key_epoch`. A device whose epoch is behind
-- the remote must not overwrite remote vault meta. Defaults to 1, which is
-- also what pre-existing vaults get: they were all initialized at epoch 1.
--
-- Additive only; no table rebuild, so foreign_keys stays on.

ALTER TABLE vault_meta
    ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1;
```

En `crates/storage/src/migrations.rs`, agregar al array `MIGRATIONS` después del `version: 2`:

```rust
    Migration {
        version: 3,
        name: "003_key_epoch",
        sql: include_str!("../migrations/003_key_epoch.sql"),
        disable_foreign_keys: false,
    },
```

- [ ] **Step 4: Actualizar `runs_initial_migration`**

En el mismo archivo, cambiar `assert_eq!(current_version(&conn).unwrap(), 2);` por `assert_eq!(current_version(&conn).unwrap(), 3);`.

- [ ] **Step 5: Correr los tests de storage y verificar que pasan**

Run: `cargo test -p storage`
Expected: PASS, incluidos `runs_initial_migration` y `key_epoch_defaults_to_one_and_is_writable`.

- [ ] **Step 6: Agregar `key_epoch` a `models::VaultMeta` y leerlo**

En `crates/models/src/lib.rs`, agregar el campo a `VaultMeta` después de `verifier_nonce`:

```rust
    /// Monotonic counter of master-key changes, mirrored from `vaults.key_epoch`.
    pub key_epoch: i64,
```

En `crates/storage/src/lib.rs`, en `get_vault_meta`, agregar `key_epoch` al `SELECT` y a la tupla de `query_row`, y al constructor de `VaultMeta`:

```rust
            "SELECT salt, kdf_params, verifier_ct, verifier_nonce, key_epoch, created_at, updated_at
             FROM vault_meta WHERE id = 1",
```
con `row.get::<_, i64>(4)?` en la posición 4, `created` en 5 y `updated` en 6, y `key_epoch` en el `VaultMeta { .. }` que ya existe.

- [ ] **Step 7: Agregar el parámetro `key_epoch` a `apply_key_rotation`**

En `crates/storage/src/lib.rs:184`, agregar `key_epoch: i64` como último parámetro y extender el `UPDATE vault_meta` con `key_epoch = ?6`, corrido los índices de `params!` que quedan después (`updated_at` pasa de `?5` a `?6`).

- [ ] **Step 8: Agregar `set_key_epoch`**

En `crates/storage/src/lib.rs`, junto a los otros métodos de `vault_meta`:

```rust
    /// Overwrite the local key epoch. Used by flows that rotate the master key
    /// without re-encrypting rows (the reset flow in a later plan).
    pub fn set_key_epoch(&self, epoch: i64) -> Result<(), StorageError> {
        let n = self.conn.execute(
            "UPDATE vault_meta SET key_epoch = ?1, updated_at = ?2 WHERE id = 1",
            params![epoch, Utc::now().to_rfc3339()],
        )?;
        if n == 0 {
            return Err(StorageError::NotInitialized);
        }
        Ok(())
    }
```

- [ ] **Step 9: Agregar un test para `set_key_epoch`**

En el módulo `tests` de `crates/storage/src/lib.rs`:

```rust
    #[test]
    fn set_key_epoch_on_uninitialized_vault_errors() {
        let s = Storage::open_in_memory().unwrap();
        assert!(matches!(s.set_key_epoch(2), Err(StorageError::NotInitialized)));
    }
```

- [ ] **Step 10: Correr clippy y tests de storage**

Run: `cargo clippy -p storage --all-targets && cargo test -p storage`
Expected: PASS. `cargo test -p core` falla todavía porque `bootstrap_from_remote` y `App::rekey` siguen llamando `apply_key_rotation` con 5 argumentos; se arregla en la Task 5.

- [ ] **Step 11: Commit**

```bash
git add crates/storage/migrations/003_key_epoch.sql crates/storage/src/migrations.rs crates/storage/src/lib.rs crates/models/src/lib.rs
git commit -m "feat(storage): add key_epoch to vault meta"
```

---

### Task 4: Verificación por verificador

**Files:**
- Modify: `crates/core/src/sync.rs:474-506` (`verify_key_against_sample`, `verify_password_against_remote`)
- Test: `crates/core/src/sync.rs` (módulo `tests`, junto a `remote_sample_verification_accepts_right_key_and_empty_sample`, ~línea 1197)

**Interfaces:**
- Consumes: `sync::VaultRow` de la Task 2 (campos `verifier_ct`, `verifier_nonce`).
- Produces:
  - `fn verify_verifier(key: &MasterKey, ct: &[u8], nonce: &[u8]) -> Result<(), CoreError>` — puro. `Ok(())` si descifra a `VAULT_VERIFIER_MESSAGE`; `Err(CoreError::InvalidPassword(_))` si no.
  - `async fn verify_key_against_remote(client: &SyncClient, session: &Session, key: &MasterKey, vault: Option<&sync::VaultRow>) -> Result<(), CoreError>` — **reemplaza** `verify_password_against_remote`. Si `vault` tiene verificador completo, verifica contra él; si no, cae a `verify_key_against_sample` con la página actual.
  - `CoreError::RemoteVerifierIncomplete` — variante nueva en `crates/core/src/lib.rs`, para `verifier_ct` presente con `verifier_nonce` ausente.

- [ ] **Step 1: Escribir los tests que fallan**

En el módulo `tests` de `crates/core/src/sync.rs`, agregar:

```rust
    fn vault_row_with_verifier(key: &MasterKey) -> VaultRow {
        let (ct, nonce) = encrypt(key, models::constants::VAULT_VERIFIER_MESSAGE).unwrap();
        sync::VaultRow {
            owner_id: None,
            salt: "c2FsdA==".into(),
            kdf_params: serde_json::json!({"m_cost": 2048, "t_cost": 1, "p_cost": 1, "output_len": 32}),
            verifier_ct: Some(b64_encode(&ct)),
            verifier_nonce: Some(b64_encode(&nonce)),
            key_epoch: 1,
            key_change: Some("init".into()),
            key_changed_at: None,
        }
    }

    fn test_keys() -> (MasterKey, MasterKey, KdfParams, Vec<u8>) {
        let params = KdfParams { m_cost: 2048, t_cost: 1, p_cost: 1, output_len: 32 };
        let salt = vec![9u8; 16];
        let good = derive_master_key(&SecretString::new("correct-horse".into()), &salt, &params).unwrap();
        let bad = derive_master_key(&SecretString::new("wrong".into()), &salt, &params).unwrap();
        (good, bad, params, salt)
    }

    #[test]
    fn verifier_accepts_only_the_right_key() {
        let (good, bad, _, _) = test_keys();
        let row = vault_row_with_verifier(&good);
        let (ct, nonce) = (
            b64_decode(row.verifier_ct.as_ref().unwrap()).unwrap(),
            b64_decode(row.verifier_nonce.as_ref().unwrap()).unwrap(),
        );
        assert!(verify_verifier(&good, &ct, &nonce).is_ok());
        assert!(matches!(
            verify_verifier(&bad, &ct, &nonce),
            Err(CoreError::InvalidPassword(_))
        ));
    }

    #[test]
    fn verifier_rejects_ciphertext_of_the_wrong_constant() {
        // Right key, but the row was encrypted over some other plaintext: the
        // AEAD tag passes yet the message must not match.
        let (good, _, _, _) = test_keys();
        let (ct, nonce) = encrypt(&good, "some-other-value").unwrap();
        assert!(matches!(
            verify_verifier(&good, &ct, &nonce),
            Err(CoreError::InvalidPassword(_))
        ));
    }

    #[test]
    fn verifier_row_without_nonce_is_an_explicit_error() {
        let (good, _, _, _) = test_keys();
        let mut row = vault_row_with_verifier(&good);
        row.verifier_nonce = None;
        assert!(matches!(
            verifier_parts(&row),
            Err(CoreError::RemoteVerifierIncomplete)
        ));
    }
```

- [ ] **Step 2: Correr los tests y verificar que fallan**

Run: `cargo test -p core verifier_`
Expected: FAIL con error de compilación — `verify_verifier` y `verifier_parts` no existen.

- [ ] **Step 3: Implementar `verify_verifier` y `verifier_parts`**

Primero, agregar `VaultRow` al import de la línea 19 de `crates/core/src/sync.rs`: `use sync::{EnvironmentRow, ProjectRow, Session, SyncClient, VariableRow, VaultRow};`. Las firmas de abajo usan `VaultRow`, no `sync::VaultRow`.

Luego, en `crates/core/src/sync.rs`, antes de `verify_key_against_sample` (línea 474):

```rust
/// Decide how to verify a derived key against the remote vault, given what
/// the `vaults` row carries. Pure; unit-testable without HTTP.
///
/// A complete verifier pair is the strongest signal: it is independent of the
/// vault's contents, so an empty vault still rejects a wrong password. A row
/// written before the verifier migration has neither field and falls back to
/// the sample. A verifier without a nonce is a half-written row and must not
/// be mistaken for "no verifier".
fn verifier_parts(vault: &VaultRow) -> Result<Option<(Vec<u8>, Vec<u8>)>, CoreError> {
    match (&vault.verifier_ct, &vault.verifier_nonce) {
        (None, None) => Ok(None),
        (Some(ct), Some(nonce)) => Ok(Some((b64_decode(ct)?, b64_decode(nonce)?))),
        _ => Err(CoreError::RemoteVerifierIncomplete),
    }
}

/// Verify a master key against the remote verifier ciphertext.
fn verify_verifier(key: &MasterKey, ct: &[u8], nonce: &[u8]) -> Result<(), CoreError> {
    let plaintext = decrypt(key, ct, nonce)
        .map_err(|_| CoreError::invalid_password())?;
    if plaintext == models::constants::VAULT_VERIFIER_MESSAGE {
        Ok(())
    } else {
        Err(CoreError::invalid_password())
    }
}
```

Usar `CoreError::invalid_password()` — el helper de `crates/core/src/lib.rs:53` — en vez de construir el `InvalidPassword` a mano, para que el mensaje sea el mismo en todos los caminos.

- [ ] **Step 4: Correr los tests y verificar que pasan**

Run: `cargo test -p core verifier_`
Expected: PASS los tres. `verifier_rejects_ciphertext_of_the_wrong_constant` exige comparar el plaintext contra la constante, no solo confiar en que el tag verificó.

- [ ] **Step 5: Reemplazar `verify_password_against_remote` por `verify_key_against_remote`**

Reemplazar `crates/core/src/sync.rs:496-506`:

```rust
/// Verify a derived key against the remote vault. Prefers the verifier
/// ciphertext, which works regardless of how many variables exist; falls back
/// to a sample of variable ciphertexts for vaults predating the verifier
/// migration.
async fn verify_key_against_remote(
    client: &SyncClient,
    session: &Session,
    key: &MasterKey,
    vault: Option<&VaultRow>,
) -> Result<(), CoreError> {
    if let Some((ct, nonce)) = vault.map(verifier_parts).transpose()?.flatten() {
        return verify_verifier(key, &ct, &nonce);
    }
    let sample = client.pull_page::<VariableRow>(session, "variables").await?;
    verify_key_against_sample(key, &sample)
}
```

- [ ] **Step 6: Agregar la variante de error**

En `crates/core/src/lib.rs`, junto a `RemoteKeyChanged`:

```rust
    /// The remote `vaults` row carries `verifier_ct` without `verifier_nonce`.
    /// Refusing to sync beats verifying against a half-written row.
    #[error("the remote vault verifier is incomplete (ciphertext without nonce)")]
    RemoteVerifierIncomplete,
```

- [ ] **Step 7: Correr tests y clippy de core**

Run: `cargo clippy -p core --all-targets && cargo test -p core`
Expected: los tests de `core` compilan y pasan salvo los que llaman `apply_key_rotation` con 5 argumentos, que se actualizan en la Task 5. Si el error decompila el binario de tests, ir directo a la Task 5 y volver.

- [ ] **Step 8: Commit**

```bash
git add crates/core/src/sync.rs crates/core/src/lib.rs
git commit -m "feat(core): verify master key against remote verifier ciphertext"
```

---

### Task 5: Cablear el verificador en bootstrap, adopción y rekey

**Files:**
- Modify: `crates/core/src/sync.rs:571-599` (`bootstrap_from_remote`)
- Modify: `crates/core/src/sync.rs:612-654` (`adopt_remote_key`)
- Modify: `crates/core/src/lib.rs:148-186` (`App::rekey`)
- Test: `crates/core/src/sync.rs`, `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: `verify_key_against_remote` (Task 4), `apply_key_rotation` con `key_epoch` (Task 3), `VaultMetaPush` (Task 2).
- Produce: los tres métodos usan la verificación por verificador y escriben `key_epoch` en el remoto. `App::rekey` incrementa el epoch local en 1.

- [ ] **Step 1: Actualizar `bootstrap_from_remote`**

En `crates/core/src/sync.rs:588-591`, reemplazar el derivar-y-verificar:

```rust
        // Derive locally and verify against the remote vault before touching
        // the local vault. The verifier is preferred over a variable sample:
        // a vault with no variables yet must still reject a wrong password.
        let key = derive_master_key(&password, &salt, &kdf_params)?;
        verify_key_against_remote(&client, &session, &key, Some(&vault)).await?;
```

En el `init_vault` de la línea 595-596 no cambia nada: el epoch local queda en 1 por default del schema, que es lo correcto para un dispositivo que se une a un vault existente… salvo que el remoto ya haya rotado. Para eso, después del `init_vault`, agregar:

```rust
        self.storage.set_key_epoch(vault.key_epoch)?;
```

antes de `self.master_key = Some(key);`. Sin esto un dispositivo nuevo que entra después de un rekey seractable como divergente en el siguiente sync.

- [ ] **Step 2: Actualizar `adopt_remote_key`**

En `crates/core/src/sync.rs:627-628`:

```rust
        let new_key = derive_master_key(&password, &remote_salt, &kdf_params)?;
        verify_key_against_remote(&client, &session, &new_key, Some(&vault)).await?;
```

En la llamada a `apply_key_rotation` (línea 641-647), agregar el argumento `vault.key_epoch` al final. La adopción no incrementa el epoch: adopta el que ya es remoto.

- [ ] **Step 3: Actualizar `App::rekey` para incrementar el epoch**

En `crates/core/src/lib.rs:148-186`, dentro de `rekey`, leer el epoch actual antes de rotar y pasar `epoch + 1` a `apply_key_rotation`. El epoch local previo se lee del meta que el método ya consulta para re-cifrar:

```rust
        let next_epoch = self.storage.get_vault_meta()?.key_epoch + 1;
```

y `apply_key_rotation(&reencrypted, &salt, &kdf_params, &verifier_ct, &verifier_nonce, next_epoch)`.

- [ ] **Step 4: Agregar el test de que rekey incrementa el epoch**

En el módulo `tests` de `crates/core/src/lib.rs`, extender el test de rekey existente (agrega uno nuevo si el archivo ya tiene uno que cubre el camino feliz):

```rust
    #[test]
    fn rekey_increments_key_epoch() {
        let mut app = App::open_in_memory().unwrap();
        app.init(SecretString::new("first".into())).unwrap();
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 1);
        app.unlock(SecretString::new("first".into())).unwrap();
        app.rekey(SecretString::new("second".into())).unwrap();
        assert_eq!(app.storage.get_vault_meta().unwrap().key_epoch, 2);
    }
```

- [ ] **Step 5: Agregar el test de que la adopción adopta el epoch remoto**

En `crates/core/src/sync.rs`, agregar un test puro sobre `verifier_parts` ya cubierto en la Task 4. Para la adopción, lo que importa es que el epoch remoto gana, y eso lo ejercita el test de `salt_action` de la Task 6 con epoch remoto mayor. No agregar un test de `adopt_remote_key`: requiere HTTP y el Supabase de test rejects la única cuenta disponible (ver Global Constraints).

- [ ] **Step 6: Correr clippy y tests de core**

Run: `cargo clippy --workspace --all-targets && cargo test -p core`
Expected: PASS, incluidos `rekey_increments_key_epoch` y los tests de verifier.

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/sync.rs crates/core/src/lib.rs
git commit -m "feat(core): use remote verifier in bootstrap and adoption, bump epoch on rekey"
```

---

### Task 6: Guard de salt consciente del epoch

**Files:**
- Modify: `crates/core/src/sync.rs:373-409` (`SaltAction`, `salt_action`)
- Modify: `crates/core/src/sync.rs:663-689` (llamada a `salt_action` en `sync`)
- Test: `crates/core/src/sync.rs:1035-1070` (tests existentes de `salt_action`)

**Interfaces:**
- Consumes: `VaultMeta.key_epoch` (Task 3), `VaultRow.key_epoch` (Task 2).
- Produce:
  - `struct SaltInputs<'a> { local_salt: &'a [u8], local_epoch: i64, remote_salt_b64: Option<&'a str>, remote_epoch: Option<i64>, pending_marker: Option<&'a str> }`
  - `fn salt_action(i: &SaltInputs) -> SaltAction` — **firma cambiada**, reemplaza los 3 posicionales.
  - `SaltAction` sin variantes nuevas.

- [ ] **Step 1: Reescribir los tests existentes y agregar los casos de epoch**

Los cinco tests de `salt_action` que ya están en `crates/core/src/sync.rs:1035-1070` se adaptan mecánicamente: envolver los tres argumentos posicionales en `SaltInputs` con `local_epoch: 1` y `remote_epoch: None`. Los nombres y las aserciones no cambian.

Agregar este helper junto a ellos:

```rust
    fn salt_inputs<'a>(
        local: &'a [u8],
        remote: Option<&'a str>,
        marker: Option<&'a str>,
    ) -> SaltInputs<'a> {
        SaltInputs {
            local_salt: local,
            local_epoch: 1,
            remote_salt_b64: remote,
            remote_epoch: None,
            pending_marker: marker,
        }
    }
```

Y los tres tests nuevos del epoch:

```rust
    #[test]
    fn remote_epoch_ahead_blocks_a_stale_local_rekey() {
        // This device rekeyed and has a pending marker, but the remote has
        // since rotated again. Pushing our stale meta would clobber it.
        let local = [1u8; 16];
        let local_hex = hex::encode(local);
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 2,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(3),
            pending_marker: Some(&local_hex),
        };
        assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
    }

    #[test]
    fn remote_epoch_ahead_with_matching_salt_still_proceeds() {
        // Salts match, so the key domains agree; a higher remote epoch is
        // bookkeeping, not a reason to abort.
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 1,
            remote_salt_b64: Some(&b64_encode(&local)),
            remote_epoch: Some(9),
            pending_marker: None,
        };
        assert_eq!(salt_action(&i), SaltAction::Proceed);
    }

    #[test]
    fn remote_epoch_behind_does_not_block_our_newer_rekey() {
        let local = [1u8; 16];
        let i = SaltInputs {
            local_salt: &local,
            local_epoch: 5,
            remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
            remote_epoch: Some(4),
            pending_marker: Some(&hex::encode(local)),
        };
        assert_eq!(salt_action(&i), SaltAction::PushRekey);
    }
```

- [ ] **Step 2: Correr los tests y verificar que fallan**

Run: `cargo test -p core salt_action`
Expected: FAIL con error de compilación — `SaltInputs` no existe y `salt_action` toma 3 argumentos.

- [ ] **Step 3: Implementar `SaltInputs` y el nuevo `salt_action`**

Reemplazar la firma de `salt_action` (`crates/core/src/sync.rs:393-409`) por:

```rust
/// Local and remote vault state, gathered by the caller so this stays pure.
struct SaltInputs<'a> {
    local_salt: &'a [u8],
    local_epoch: i64,
    remote_salt_b64: Option<&'a str>,
    remote_epoch: Option<i64>,
    pending_marker: Option<&'a str>,
}

fn salt_action(i: &SaltInputs) -> SaltAction {
    let Some(remote) = i.remote_salt_b64 else {
        return SaltAction::PushLocal;
    };
    // A remote that has rotated past us wins, even when this device has a
    // pending rekey marker: our meta is stale and pushing it would clobber a
    // newer key domain. Checked before the salt comparison so it also covers
    // the degenerate case of two devices that somehow share a salt.
    if i.remote_epoch.is_some_and(|re| re > i.local_epoch) {
        return SaltAction::RemoteKeyChanged;
    }
    if remote == b64_encode(i.local_salt) {
        return SaltAction::Proceed;
    }
    if i.pending_marker.is_some_and(|m| m == hex::encode(i.local_salt)) {
        return SaltAction::PushRekey;
    }
    SaltAction::RemoteKeyChanged
}
```

- [ ] **Step 4: Correr los tests y verificar que pasan**

Run: `cargo test -p core salt_action`
Expected: PASS los siete.

- [ ] **Step 5: Actualizar la llamada en `sync`**

En `crates/core/src/sync.rs:670-688`, reemplazar el bloque que arma `salt_action`:

```rust
        if self.storage.is_initialized()? {
            let meta = self.storage.get_vault_meta()?;
            let pending = SyncState::get(self.storage.conn(), PENDING_REKEY_SALT_KEY)?;
            let inputs = SaltInputs {
                local_salt: &meta.salt,
                local_epoch: meta.key_epoch,
                remote_salt_b64: remote_vault.as_ref().map(|v| v.salt.as_str()),
                remote_epoch: remote_vault.as_ref().map(|v| v.key_epoch),
                pending_marker: pending.as_deref(),
            };
            let action = salt_action(&inputs);
```

El resto del `match` sobre `SaltAction` queda igual.

- [ ] **Step 6: Agregar el `key_epoch` al push de `vaults`**

En `crates/core/src/sync.rs:697-707`, `vault_push` pasa a llevar el epoch y el motivo. Cambiar el tipo de `vault_push` a `Option<VaultMetaPush>` y el armado:

```rust
                SaltAction::PushLocal => {
                    vault_push = Some(VaultMetaPush {
                        salt: b64_encode(&meta.salt),
                        kdf_params: serde_json::to_value(&meta.kdf_params)?,
                        verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                        verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                        key_epoch: meta.key_epoch,
                        key_change: models::constants::KEY_CHANGE_INIT.into(),
                        key_changed_at: None,
                    });
                }
                SaltAction::PushRekey => {
                    vault_push = Some(VaultMetaPush {
                        salt: b64_encode(&meta.salt),
                        kdf_params: serde_json::to_value(&meta.kdf_params)?,
                        verifier_ct: Some(b64_encode(&meta.verifier_ct)),
                        verifier_nonce: Some(b64_encode(&meta.verifier_nonce)),
                        key_epoch: meta.key_epoch,
                        key_change: models::constants::KEY_CHANGE_REKEY.into(),
                        key_changed_at: Some(Utc::now().to_rfc3339()),
                    });
                    clear_rekey_marker = true;
                }
```

`clear_rekey_marker` pasa a setterse solo en `PushRekey`. El push pasa a `client.push_vault(&session, vault_meta).await?` sobre el `Option<VaultMetaPush>` desenrollado.

- [ ] **Step 7: Agregar las constantes de `key_change`**

En `crates/models/src/constants.rs`:

```rust
/// `vaults.key_change` values: why `key_epoch` last changed.
pub const KEY_CHANGE_INIT: &str = "init";
pub const KEY_CHANGE_REKEY: &str = "rekey";
pub const KEY_CHANGE_RESET: &str = "reset";
```

- [ ] **Step 8: Correr el workspace entero**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: PASS en todos los crates.

- [ ] **Step 9: Commit**

```bash
git add crates/core/src/sync.rs crates/models/src/constants.rs
git commit -m "feat(core): guard salt mismatch against remote key epoch"
```

---

### Task 7: Backfill del verificador

**Files:**
- Modify: `crates/core/src/sync.rs` (dentro de `sync`, ~línea 697)
- Test: `crates/core/src/sync.rs`

**Interfaces:**
- Consumes: `VaultMeta.verifier_ct` / `verifier_nonce` (locales, desde `init`), `VaultMetaPush` (Task 2).
- Produce: en `sync`, cuando el vault remoto existe, coincide el salt y su `verifier_ct` es `None`, una ascentura de `vaults` que completa el verificador sin tocar `salt`, `kdf_params` ni `key_epoch`.

- [ ] **Step 1: Extraer la decisión de backfill a una función pura**

Agregar en `crates/core/src/sync.rs`, cerca de `salt_action`:

```rust
/// True when the remote vault shares our key domain but predates the verifier
/// migration, so this sync should fill in the verifier. Deliberately only for
/// `Proceed`: a salt mismatch must abort before anything is written.
fn needs_verifier_backfill(action: SaltAction, remote: Option<&VaultRow>) -> bool {
    matches!(action, SaltAction::Proceed)
        && remote.is_some_and(|v| v.verifier_ct.is_none() && v.verifier_nonce.is_none())
}
```

- [ ] **Step 2: Escribir el test**

En el módulo `tests` de `crates/core/src/sync.rs`:

```rust
    #[test]
    fn backfill_only_on_matching_domain_without_verifier() {
        let key = test_keys().0;
        let mut old_row = vault_row_with_verifier(&key);
        old_row.verifier_ct = None;
        old_row.verifier_nonce = None;

        assert!(needs_verifier_backfill(SaltAction::Proceed, Some(&old_row)));
        assert!(
            !needs_verifier_backfill(SaltAction::Proceed, None),
            "no remote vault: the first push already carries the verifier"
        );
        assert!(
            !needs_verifier_backfill(SaltAction::RemoteKeyChanged, Some(&old_row)),
            "a salt mismatch must abort, never write"
        );
        assert!(
            !needs_verifier_backfill(SaltAction::PushRekey, Some(&old_row)),
            "a rekey push already carries a verifier"
        );
        assert!(
            !needs_verifier_backfill(
                SaltAction::Proceed,
                Some(&vault_row_with_verifier(&key))
            ),
            "already has a verifier"
        );
    }
```

- [ ] **Step 3: Correr el test y verificar que falla**

Run: `cargo test -p core backfill_only_on_matching_domain`
Expected: FAIL — `needs_verifier_backfill` no existe.

- [ ] **Step 4: Implementar la función**

Implementar `needs_verifier_backfill` exactamente como en el Step 1.

- [ ] **Step 5: Correr el test y verificar que pasa**

Run: `cargo test -p core backfill_only_on_matching_domain`
Expected: PASS.

- [ ] **Step 6: Cablear el backfill en `sync`**

En `crates/core/src/sync.rs`, dentro de `sync`, después del `match` que fija `action` y antes del push de filas. Capturar `action` en una variable para reutilizarla:

```rust
    let action = salt_action(&inputs);
```

y luego, tras el bloque `if let Some((salt_b64, kdf_json)) = vault_push { ... }` existente, agregar:

```rust
    // Backfill: this vault predates the verifier migration. Completing the
    // verifier makes the next device's password check real. It never touches
    // salt, kdf_params or key_epoch — only additive fields.
    if needs_verifier_backfill(action, remote_vault.as_ref()) {
        let meta = self.storage.get_vault_meta()?;
        let key = self.require_key()?;
        let (ct, nonce) = encrypt(&key, models::constants::VAULT_VERIFIER_MESSAGE)?;
        client
            .push_vault(
                &session,
                &VaultMetaPush {
                    salt: remote_vault.as_ref().map(|v| v.salt.clone()).unwrap_or_default(),
                    kdf_params: remote_vault.as_ref().map(|v| v.kdf_params.clone()).unwrap_or_default(),
                    verifier_ct: Some(b64_encode(&ct)),
                    verifier_nonce: Some(b64_encode(&nonce)),
                    key_epoch: meta.key_epoch,
                    key_change: models::constants::KEY_CHANGE_INIT.into(),
                    key_changed_at: None,
                },
            )
            .await?;
    }
```

`key_epoch: meta.key_epoch` y no `remote_vault.key_epoch` a propósito: en `Proceed` los dominios coinciden y ambos valen lo mismo, pero usar el local evita escribir un epoch de otro dispositivo sobre el remoto. `require_key()` falla si el vault está bloqueado, lo que es lo correcto: no se puede cifrar un verificador sin la clave.

- [ ] **Step 7: Correr clippy y el workspace**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/core/src/sync.rs
git commit -m "feat(core): backfill remote verifier for pre-migration vaults"
```

---

### Task 8: Documentación

**Files:**
- Modify: `docs/SYNC.md`

**Interfaces:**
- Consumes: el comportamiento implementado en las Tasks 1-7.
- Produce: nada en código.

- [ ] **Step 1: Actualizar la sección de master key**

En `docs/SYNC.md`, en la sección "Master key: guard de salt y rotación", agregar un párrafo después del bullet del guard de sync:

```markdown
- **Verificador remoto:** `vaults` guarda `verifier_ct`/`verifier_nonce`, el
  ciphertext del mensaje constante `vault-ok` bajo la master key actual. Permite
  probar la contraseña sin depender de que el vault tenga variables: un vault
  vacío rechaza igual una contraseña incorrecta. Los vaults anteriores a la
  migración `0002_key_epoch_verifier` no lo tienen y caen a la verificación por
  muestra de ciphertext; el primer sync los completa.
- **Key epoch:** `vaults.key_epoch` (y su espejo local) sube en cada `rekey`.
  Un dispositivo cuyo epoch local quedó atrás aborta el sync en vez de pisar el
  meta remoto con uno viejo, aunque tenga un `pending_rekey_salt` válido.
```

- [ ] **Step 2: Actualizar "Qué NO se sincroniza"**

Agregar el verifier a la lista, aclarando por qué no es un secreto:

```markdown
- El verificador remoto (`vaults.verifier_ct`): es el mensaje constante `vault-ok`
  cifrado con la master key. El servidor solo ve ciphertext de un valor conocido,
  igual que en cualquier variable.
```

- [ ] **Step 3: Documentar la limitación conocida**

En `docs/SYNC.md`, sección "Qué NO se sincroniza" o en una nota al pie, agregar:

```markdown
> **Limitación conocida:** la policy de `vaults` es `for all`, así que cualquier
> usuario autenticado de la cuenta puede sobrescribir `salt` y `kdf_params` con
> solo su contraseña de Supabase, sin conocer la master key. El cliente exige la
> contraseña correcta para adoptar o pushear el meta del vault, pero esa es una
> política del cliente, no una garantía del servidor: un atacante con la contraseña
> de la cuenta puede dejar el vault indescifrable. Cerrarlo requiere mover la
> validación al servidor con un rol que la CLI no tiene.
```

- [ ] **Step 4: Agregar el caso al checklist E2E**

En la sección "Checklist de verificación E2E (manual)", agregar:

```markdown
6. Vault existente sin verificador (creado antes de `0002_key_epoch_verifier`):
   `vltr sync` debe completarse y, al consultar `vaults`, `verifier_ct` debe
   quedar poblado sin que cambien `salt` ni `key_epoch`.
7. Con `verifier_ct` poblado: un dispositivo nuevo con la contraseña
   **incorrecta** debe fallar el `vltr bootstrap` aunque el remoto no tenga
   ninguna variable.
8. Tras un `rekey` en A, el `sync` en B debe abortar con `RemoteKeyChanged` y
   adoptar con la contraseña nueva.
```

- [ ] **Step 5: Correr el check de docs-only y commitear**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets`
Expected: PASS (el cambio es solo docs, pero el hook de pre-commit corre igual).

```bash
git add docs/SYNC.md
git commit -m "docs(sync): document remote verifier and key epoch"
```

---

## Notas de ejecución

- **Orden de despliegue:** primero la Task 1 (migración del servidor), después el
  cliente. Al revés, el cliente nuevo lee `key_epoch` de una columna que no existe y
  falla el `SELECT`. La sección de rollback del spec cubre el orden inverso.
- **Task 1 es la única que toca el servidor.** Si el MCP de Supabase vuelve a caer,
  el resto del plan se puede ejecutar igual; la Task 7 queda sin poder probarse
  contra el servidor real pero compila y sus tests de unidad pasan.
- Los tests de `adopt_remote_key` y `bootstrap_from_remote` end-to-end requieren una
  cuenta Supabase con email entregable, que este proyecto no tiene. Los pasos que
  dependen de eso están marcados en las tareas correspondientes.