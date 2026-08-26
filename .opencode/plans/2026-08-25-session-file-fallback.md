# Session Store Fix: File-Based Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Arreglar el warning "no session store is available" en WSL reemplazando el agente en memoria (TCP + subprocess) por un archivo de sesión 0600 con TTL deslizante, y mostrar la causa real cuando el guardado de sesión falle.

**Architecture:** `session.rs` conserva keyring como store primario; el fallback pasa de un daemon TCP efímero a un archivo `~/.local/share/vaultr/session.json` (permiso 0600, payload JSON idéntico al del keyring). Mismo contrato público (`save_master_key`, `load_master_key`, `inspect`, `clear_session`, `SessionStore::Memory`), cero cambios en core/CLI salvo propagar el error real. El binario oculto `__session-agent` desaparece junto con ~200 líneas de socket/spawn.

**Tech Stack:** Sin dependencias nuevas. std::fs + serde_json ya presentes.

**Spec:** Diagnóstico 2026-08-25 — WSL sin Secret Service (keyring imposible) y WSL reapando el subprocess del agente. Decisión del usuario: archivo 0600 + mostrar causa real.

## Global Constraints

- La master key JAMÁS se loguea ni aparece en mensajes.
- El archivo de sesión se crea con modo 0600 ANTES de escribir contenido (unix) y se borra en lock/expiry/corrupción.
- TTL deslizante de 30 min: cada lectura exitosa refresca `expires_at` (igual que hoy).
- Gate por tarea: `cargo clippy --workspace --all-targets -- -D warnings`; final: fmt + test + check.
- Conventional Commits.

---

### Task 1: Fallback file-based en session.rs

**Files:**
- Modify: `crates/core/src/session.rs`

**Interfaces (públicas, sin cambios):**
- `save_master_key(&MasterKey) -> Result<SessionStore, CoreError>`
- `load_master_key() -> Result<Option<MasterKey>, CoreError>`
- `clear_session()`, `has_session()`, `active_store()` (si existe), `inspect()`
- `SessionStore { Keyring, Memory }`

Cambios:

1. **Borrar todo el código del agente TCP**: `AgentDescriptor`, `agent_path`, `start_memory_agent`, `serve_memory_agent`, `read_agent_descriptor`, `write_agent_descriptor`, `load_memory_agent`, `memory_seconds_remaining`, `stop_memory_agent`, `is_cli_binary`.
2. **Nuevo fallback** (~50 líneas):

```rust
fn session_file_path() -> Result<std::path::PathBuf, CoreError> {
    let dir = directories::ProjectDirs::from("dev", "Vaultr", "vaultr")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| CoreError::Other("cannot determine Vaultr data directory".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("session.json"))
}

fn save_memory_file(key: &MasterKey) -> Result<(), CoreError> {
    let path = session_file_path()?;
    let json = serde_json::to_string(&build_payload(key))
        .map_err(|e| CoreError::Other(format!("serialize session: {e}")))?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{PermissionsExt, OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(json.as_bytes())?;
        // ponytail: chmod tras crear cubre filesystems que ignoran mode() en create
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, json)?; // Windows: ACLs fuera de scope del MVP
    Ok(())
}
```

3. **Reescribir las funciones memory** para leer/escribir ese archivo:
   - `load_memory_file() -> Option<MasterKey>`: parse payload, chequear `payload_seconds_remaining`; si expiró/corrupto → borrar archivo y None; si válido → refresh TTL (reescribir con nuevo expires_at, patrón del keyring).
   - `memory_seconds_remaining()`: leer archivo sin refrescar; expirado → borrar.
   - `stop_memory_file()`: borrar si existe (`let _ = remove_file`).
4. **`SessionStore::Memory` label** → `"local session file"` (antes "in-memory agent").
5. Mantener tests existentes adaptados; añadir uno:

```rust
#[test]
fn memory_file_roundtrip_and_expiry() { /* save → load ok; escribir expires_at pasado → load None y archivo borrado */ }
```

(los tests tocan el archivo real del usuario — aceptar o parametrizar path via `#[cfg(test)]` override; preferir variable de entorno `VLTR_SESSION_FILE` solo leída en tests… decisión: función `session_file_path` usa `std::env::var_os("VLTR_SESSION_FILE")` si está definida — 2 líneas, útil también para debug.)

6. **Eliminar el subcommand** `__session-agent` de `Commands` en cli/main.rs y su handler en `main()`.

- [ ] Implementar. Verificar E2E manual: `vltr unlock` → `ls ~/.local/share/vaultr/session.json` existe modo 600 → `vltr status` muestra sesión activa → `vltr lock` borra el archivo.
- [ ] Commit: `fix(core): replace tcp memory agent with 0600 session file`

---

### Task 2: Mostrar la causa real del fallo de sesión

**Files:**
- Modify: `crates/core/src/lib.rs` (`unlock`, `init`: quitar `let _ =`)
- Modify: `crates/cli/src/main.rs`

Cambios:

1. En `App::unlock` e `App::init`: cambiar `let _ = session::save_master_key(&key);` por guardar el resultado:

```rust
self.master_key = Some(key);
self.last_session_error = session::save_master_key(&key).err().map(|e| e.to_string());
```

con campo `last_session_error: Option<String>` en `App` (None al abrir; limpiar en lock).
2. Nuevo getter `App::take_session_error(&mut self) -> Option<String>`.
3. CLI: donde hoy imprime el warning genérico (`warn_if_session_unavailable`), imprimir la causa:

```rust
if let Some(reason) = app.take_session_error() {
    eprintln!("Warning: no session store could be saved ({reason}); the password will be requested for future commands.");
} else if !App::has_keyring_session().unwrap_or(false) { /* warning actual */ }
```

4. Nunca incluir contenido de la key en el error (los errores actuales de session.rs no la contienen — verificar).

- [ ] Implementar + verificar: forzar fallo (env var rara) no trivial — basta revisión visual del flujo y smoke normal.
- [ ] Commit: `feat(cli): surface real cause when session cannot be saved`

---

### Task 3: Docs + gate

**Files:**
- Modify: `docs/SESSION.md` (agente TCP → archivo 0600, tradeoff documentado), `README.md` si menciona "in-memory".

- [ ] Actualizar docs. Commit: `docs: document session file fallback`
- [ ] Gate final: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo check -p vltr-cli`
- [ ] Smoke WSL del usuario: unlock → nueva consola → comando sin password → lock.

## Fuera de alcance

- Cifrar el archivo de sesión con algo derivado del password (derrota el propósito del remember-me).
- Integración con secret-service vía dbus (instalar gnome-keyring es alternativa del usuario, no código nuestro).
- Cambios al plan de Supabase sync (usa el mismo mecanismo de sesión para su JWT; se beneficia automáticamente).
