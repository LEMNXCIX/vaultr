# CLI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rediseñar la superficie del CLI `vltr`: resolución implícita de proyecto (directorio actual) y environment (el default), comandos aplanados (`create/projects/rm/del/ls/use`), password obligatoria en destructivos, `apply` que solo agrega keys faltantes, `status -p/-a`, e `init` que instala completions.

**Architecture:** La lógica nueva vive en `core`/`storage` (resolución de default env, re-verificación de password, search con filtros, merge de `.env`); el CLI queda como transcripción del spec. Sin migraciones SQL (el campo `environments.is_default` ya existe). Breaking change sin alias.

**Tech Stack:** Rust workspace, clap derive, rusqlite. Sin dependencias nuevas.

**Spec:** Tablas de comandos definidas por el usuario en la conversación (2026-08-25). Decisiones: merge-only en `apply` (solo agrega faltantes); sin alias de compatibilidad; `rm`/`del` verifican password contra el verifier sin abrir sesión.

## Global Constraints

- Regla de resolución: sin `-p` → nombre del directorio actual como proyecto; sin `-e` → environment `is_default=true` del proyecto.
- `rm` y `del` SIEMPRE piden master password y la verifican contra el vault verifier antes de ejecutar.
- Gate por tarea: `cargo clippy --workspace --all-targets -- -D warnings`; gate final: `cargo fmt --all -- --check && cargo test --workspace && cargo check -p vltr-cli`
- Conventional Commits.
- No tocar el memory agent ni los campos owner_id/version/is_readonly/allow_export existentes (is_default sí se usa).

---

### Task 0: Mergear rama del audit

- [ ] Ejecutar (fuera del plan, controller): `git checkout main && git merge chore/ponytail-audit-cuts && git branch -d chore/ponytail-audit-cuts`. Nueva rama: `feat/cli-redesign`.

---

### Task 1: Default environment — storage + core

**Files:**
- Modify: `crates/storage/src/lib.rs` (sección Environments)
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Produces:
  - `Storage::get_default_environment(project_id: Id) -> Result<Option<Environment>, StorageError>` — `WHERE project_id = ?1 AND is_default = 1 LIMIT 1`.
  - `Storage::set_default_environment(project_id: Id, env_id: Id) -> Result<(), StorageError>` — transacción: `UPDATE environments SET is_default = 0 WHERE project_id = ?1` luego `UPDATE environments SET is_default = 1 WHERE id = ?2 AND project_id = ?1`; usar `unchecked_transaction` (patrón de migrations.rs).
  - `App::use_environment(project_name: &str, env_name: &str) -> Result<(), CoreError>` — resuelve project+env vía `resolve_env`, llama set_default. Devuelve `EnvironmentNotFound`/`ProjectNotFound` si no existen.

- [ ] **Step 1:** Implementar las dos funciones de storage + `use_environment` en core.
- [ ] **Step 2:** Test en `crates/core/src/lib.rs`:

```rust
#[test]
fn use_environment_switches_default() {
    let mut app = unlocked_app();
    app.create_project("P", None, None, None).unwrap();
    app.create_environment("P", "staging").unwrap();
    assert_eq!(
        app.storage.get_default_environment(/* necesita id */).unwrap().unwrap().name,
        "local"
    );
}
```

Nota para el implementador: `storage` es privado en `App`. Si el test lo necesita, añadir `pub(crate) fn storage(&self) -> &Storage` o hacer el assertion vía un método público `App::default_environment(project_name) -> Result<Environment, CoreError>` (preferir esto último; también lo usará el CLI para resolver `-e`). Firma: `pub fn default_environment(&self, project_name: &str) -> Result<Environment, CoreError>`.
- [ ] **Step 3:** `cargo clippy --workspace --all-targets -- -D warnings && cargo test -p core`
- [ ] **Step 4:** Commit: `feat(core): switchable default environment`

---

### Task 2: Re-verificación de password sin sesión

**Files:**
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Produces: `App::verify_password(&self, password: SecretString) -> Result<(), CoreError>` — deriva key con salt+kdf_params del vault, descifra el verifier, compara con `VAULT_VERIFIER_MESSAGE`; `Err(CoreError::InvalidPassword)` si falla. NO guarda la key ni toca sesión (a diferencia de `unlock`).

- [ ] **Step 1:** Implementar (casi copia del cuerpo de `unlock` sin asignar `self.master_key` ni llamar `save_master_key`).
- [ ] **Step 2:** Test:

```rust
#[test]
fn verify_password_rejects_wrong_without_session() {
    let app = unlocked_app();
    assert!(app.verify_password(SecretString::new("test-password-123".into())).is_ok());
    assert!(app.verify_password(SecretString::new("wrong".into())).is_err());
    assert!(!app.is_unlocked()); // no abre sesión
}
```

(ajustar al password real de `unlocked_app`: "test-password-123")
- [ ] **Step 3:** clippy + `cargo test -p core`
- [ ] **Step 4:** Commit: `feat(core): verify master password without opening session`

---

### Task 3: Search con filtros + conteo para status

**Files:**
- Modify: `crates/storage/src/lib.rs` (`search_variables`)
- Modify: `crates/core/src/lib.rs` (`search`, nuevo `project_status`)

**Interfaces:**
- Cambia: `Storage::search_variables(query: &str, project: Option<&str>, env: Option<&str>) -> Result<Vec<VariableSummary>, StorageError>` — añade `WHERE` condicionales (`AND p.name = ?N`, `AND e.name = ?N`) construidos con params dinámicos (vec de `Box<dyn ToSql>` o dos ramas simples; preferir construir SQL con strings fijas + `params_from_iter`).
- Cambia firma upstream: `CoreError`-wrapped `App::search(query, project: Option<&str>, env: Option<&str>)`.
- Produces: `App::project_status(project_name: &str) -> Result<Vec<(Environment, i64)>, CoreError>` — environments del proyecto con conteo de variables. Storage: una query agrupada:

```sql
SELECT e.id, e.project_id, e.name, e.is_default, e.sort_order, e.created_at, e.updated_at,
       COUNT(v.id) AS var_count
FROM environments e LEFT JOIN variables v ON v.environment_id = e.id
WHERE e.project_id = ?1
GROUP BY e.id ORDER BY e.sort_order, e.name
```

con su row-mapper (reusar patrón de `map_environment`).

- [ ] **Step 1:** Storage + core.
- [ ] **Step 2:** Test en core:

```rust
#[test]
fn search_scopes_by_project_and_env() {
    let app = unlocked_app();
    app.create_project("A", None, None, None).unwrap();
    app.create_project("B", None, None, None).unwrap();
    app.set_variable("A", "local", "K", "1", None).unwrap();
    app.set_variable("B", "local", "K", "2", None).unwrap();
    assert_eq!(app.search("k", Some("A"), None).unwrap().len(), 1);
    let status = app.project_status("A").unwrap();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].1, 1); // 1 variable en local
}
```

- [ ] **Step 3:** clippy + `cargo test -p storage -p core`
- [ ] **Step 4:** Commit: `feat(core): scoped search and per-environment counts`

---

### Task 4: Apply con merge (solo agrega faltantes)

**Files:**
- Modify: `crates/core/src/envfile.rs` (nueva función)
- Modify: `crates/core/src/lib.rs` (`apply_env`)

**Interfaces:**
- Produces: `envfile::merge_missing(existing: &str, vars: &[DecryptedVariable]) -> String` — parsea `existing` con `parse_env`, respeta `allow_export` (ya lo hace `format_env`), y devuelve `existing` + líneas nuevas SOLO para keys ausentes, preservando el contenido original byte a byte (garantiza comentarios/orden intactos). Asegurar `\n` final si el archivo no termina en newline antes de appendear.
- Cambia: `App::apply_env(project_name, env_name, path)` — si `path` existe: lee contenido, escribe `merge_missing(...)`; si no existe: comportamiento actual (format_env completo). Mantener `create_dir_all` del parent.

- [ ] **Step 1:** `merge_missing` + cambio en `apply_env`.

```rust
pub fn merge_missing(existing: &str, vars: &[DecryptedVariable]) -> String {
    let present: std::collections::HashSet<&str> =
        parse_env(existing).into_iter().map(|(k, _)| k.as_str()).collect();
    let missing: Vec<_> = vars.iter().filter(|v| !present.contains(v.key.as_str())).collect();
    if missing.is_empty() {
        return existing.to_string();
    }
    let mut out = existing.to_string();
    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format_env(&missing));
    out
}
```

- [ ] **Step 2:** Test en envfile.rs:

```rust
#[test]
fn merge_only_adds_missing_keys() {
    let vars = vec![mk_var("A", "1"), mk_var("B", "2")]; // helper local que construye DecryptedVariable
    let out = merge_missing("# comment\nA=old\n", &vars);
    assert_eq!(out, "# comment\nA=old\nB=2\n");
    assert_eq!(merge_missing("A=x\n", &vars), "A=x\n");
}
```

- [ ] **Step 3:** Test roundtrip en lib.rs: escribir `.env` con `A=keep\n`, aplicar proyecto que tiene A y B, verificar `A=keep` sigue y `B` se agregó.
- [ ] **Step 4:** clippy + `cargo test -p core`
- [ ] **Step 5:** Commit: `feat(core): apply merges missing keys into existing env file`

---

### Task 5: Reescritura del CLI

**Files:**
- Rewrite: `crates/cli/src/main.rs`

**Interfaces:**
- Consume: todo lo de Tasks 1–4 más `App::*` existente.

Nueva surface completa (transcripción del spec):

```rust
enum Commands {
    Init,
    Unlock,
    Lock,
    Status { #[arg(short, long)] project: Option<String>, #[arg(short, long)] all: bool }, // -p y -a exclusivos
    Create { #[arg(short, long)] project: Option<String>, #[arg(short, long)] env: Option<String>, #[arg(long)] desc: Option<String>, #[arg(long)] color: Option<String> },
    Projects,
    Rm { #[command(subcommand)] target: Option<RmTarget>, #[arg(short, long)] project: Option<String> },
    Env { name: Option<String>, #[arg(short, long)] project: Option<String> }, // sin name: lista; con name: crea
    Use { env: String, #[arg(short, long)] project: Option<String> },
    Set { key: String, value: Option<String>, #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Get { key: String, #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Ls { #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Del { key: String, #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Search { query: String, #[arg(short, long)] project: Option<String>, #[arg(short, long)] env: Option<String> },
    Apply { #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String>, #[arg(short, long)] output: Option<PathBuf> },
    Export { #[arg(short, long)] output: Option<PathBuf>, #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Import { path: PathBuf, #[arg(short, long)] env: Option<String>, #[arg(short, long)] project: Option<String> },
    Backup { path: Option<PathBuf> },          // default: <data_dir>/vault-backup.enc
    Restore { backup: PathBuf },               // default target: <dir del vault>/vault-restored.db
    Completions { target: String, #[arg(long)] shell: Option<String> },
    #[command(hide = true, name = "__session-agent")] SessionAgent,
}
```

Notas de implementación:

- **Resolución central** (dos helpers, únicos puntos que conocen la regla):

```rust
fn resolve_project(app: &App, flag: Option<String>) -> Result<String> {
    let name = match flag {
        Some(p) => p,
        None => current_dir_name()?, // ya existe como project_name(None)
    };
    if app.list_projects()?.iter().any(|p| p.name == name) { Ok(name) }
    else { anyhow::bail!("No project '{}' in this vault. Run `vltr create -p {name}`.", name) }
}

fn resolve_env(app: &App, project: &str, flag: Option<String>) -> Result<String> {
    match flag {
        Some(e) => Ok(e),
        None => Ok(app.default_environment(project)?.name),
    }
}
```

- **open_and_unlock**: igual que hoy, pero los comandos `rm`/`del` usan una variante `open_and_verify(db_path)` que NO intenta unlock de sesión: abre App, pide password con `prompt_password`, llama `app.verify_password(password)?`, y luego ejecuta. Si además hay sesión activa sirve igual (verify no depende de sesión).
- **Create**: nombre = `-p` o dir actual (reusar `project_name`). Crear env extra `-e` después de crear el proyecto. Errores existentes de `ProjectExists` se propagan.
- **Status**: sin flags → salida actual; `-p X` → header general corto + por-env del proyecto (`project_status`) marcando el default con `(default)`; `-a` → eso mismo para todos los proyectos. Validar exclusividad manualmente (`bail!` si ambos).
- **Rm**: `target: None` + `-p` → borrar ese proyecto; `target: None` sin `-p` → borrar proyecto del dir actual; `Some(RmTarget::Env{name, project})` → resolver proyecto (flag o dir) y borrar env. Ambos tras `verify_password`.
- **Del**: resolver proyecto/env, `verify_password`, `delete_variable`.
- **Get**: imprimir valor; `-c/--copy` mantiene arboard (nota: el spec dice `-c` muestra Y copia).
- **Backup default path**: `<data_dir>/vault-backup.enc` via `default_db_path().with_file_name(...)`.
- **Init auto-completions**: tras inicializar, intentar `install_completions(None)` dentro de `let _ = ...` (best-effort, nunca falla el init); imprimir ruta si tuvo éxito.
- Mantener `mask`, `prompt_secret`, `append_profile_line`, `install_completions`, handler `__session-agent`, y el flujo legacy-migration de `main()` tal cual están.

- [ ] **Step 1:** Escribir el nuevo enum + helpers + handlers.
- [ ] **Step 2:** Verificación manual del surface: `cargo run -p vltr-cli -- --help` y sub-helps reflejan la tabla del spec.
- [ ] **Step 3:** Smoke E2E en temp dir:

```bash
export SECRETS_DB=/tmp/opencode/vault-e2e.db
cargo run -p vltr-cli -- init            # + instala completions best-effort
mkdir /tmp/opencode/demo && cd /tmp/opencode/demo
cargo run -p vltr-cli -- create          # proyecto "demo"
cargo run -p vltr-cli -- set FOO bar
cargo run -p vltr-cli -- get FOO         # → bar
cargo run -p vltr-cli -- ls              # FOO=****
cargo run -p vltr-cli -- env staging && cargo run -p vltr-cli -- use staging
cargo run -p vltr-cli -- apply           # escribe ./.env
printf 'KEEP=yes\n' > ./.env && cargo run -p vltr-cli -- apply && cat ./.env  # KEEP=yes + FOO
cargo run -p vltr-cli -- del FOO         # pide password
cargo run -p vltr-cli -- rm -p demo      # pide password
```

- [ ] **Step 4:** clippy + check workspace.
- [ ] **Step 5:** Commit: `feat(cli)! redesign command surface around implicit project/env`

---

### Task 6: Docs

**Files:**
- Modify: `README.md` (secciones de uso: líneas ~77–154)
- Modify: `docs/ARCHITECTURE.md:32` (ejemplo `vltr set Fudi local KEY val` → `vltr set KEY val`)
- Verify only: `docs/COMPLETIONS.md` (los ejemplos de completions siguen válidos)

- [ ] Actualizar ejemplos a la nueva sintaxis (sin args posicionales de proyecto/env salvo flags).
- [ ] Commit: `docs: update usage examples for redesigned cli`

---

### Task 7: Gate final

- [ ] `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo check -p vltr-cli`
- [ ] Confirmar que ningún comando viejo responde (breaking): `vltr project` y `vltr delete` deben fallar con error de clap.

## Fuera de alcance

- Sharing, sync, móvil, extensiones (MVP).
- Alias de compatibilidad con la interfaz vieja.
- Confirmación extra tipo "¿seguro?" además de la password en rm/del.
