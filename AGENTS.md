# AGENTS.md — Instrucciones para agentes de IA

Este archivo orienta a cualquier agente (Cursor, Claude Code, Codex, Aider, etc.) que trabaje en este repositorio.

## Qué es este proyecto

Gestor de secretos **local-first** y **zero-knowledge** para desarrolladores, escrito en Rust.

- Fuente de verdad: SQLite local cifrado a nivel de aplicación
- UI principal futura: GPUI (Zed)
- Interfaz prioritaria del MVP: CLI (`secrets`)
- Modelo mental: `Project → Environment → Variable` (como un `.env` enriquecido)

## Principios no negociables

1. **Local First** — SQLite es la fuente de verdad. Sync es opcional y nunca bloquea el uso offline.
2. **Zero Knowledge** — Los valores se cifran *antes* de salir del dispositivo. Ni Supabase ni el desarrollador de la app pueden leer secretos.
3. **Developer Experience First** — Cada feature debe responder: ¿hace la vida del desarrollador más fácil?
4. **Separación de capas** — `cli` / `desktop` → `core` → `storage` + `crypto` + `models`. La UI no conoce SQLite ni Supabase.

## Estructura del workspace

```
crates/
  models/   # Structs de dominio puros (sin I/O ni crypto)
  crypto/   # Argon2id + XChaCha20-Poly1305 + key hierarchy
  storage/  # SQLite + schema + repositorio
  core/     # Use cases / servicios de negocio
  sync/     # Stub (Supabase futuro)
  cli/      # Binario `secrets`
apps/
  desktop/  # GPUI (fase posterior)
```

## Stack técnico

| Área            | Elección                                      |
|-----------------|-----------------------------------------------|
| Lenguaje        | Rust (edition 2021, MSRV objetivo reciente)   |
| KDF             | Argon2id (`argon2` crate)                     |
| AEAD            | XChaCha20-Poly1305 (`chacha20poly1305`)       |
| Secretos en RAM | `zeroize` / `Zeroizing` + `secrecy`           |
| DB              | SQLite vía `rusqlite` (bundled)               |
| CLI             | `clap`                                        |
| IDs             | UUID v7                                       |
| Errores         | `thiserror` en libs, `anyhow` en bins         |

## Modelo de datos clave

- Todo secreto vive dentro de un **Environment**.
- Al crear un **Project** se crea automáticamente el environment `local`.
- Cada `Variable` tiene flags `is_readonly` y `allow_export` (preparados para sharing futuro; no implementar sharing en MVP).
- Los valores se guardan solo como `value_encrypted` + `nonce`.

## Cómo trabajar (flujo recomendado)

1. Leer `docs/ARCHITECTURE.md` y este archivo antes de cambios grandes.
2. Preferir cambios pequeños y testeados.
3. Ejecutar antes de dar por terminado:
   ```bash
   cargo fmt
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. La lógica de negocio nueva va en `core`. Storage solo persiste. Crypto solo cifra/descifra.
5. No añadir dependencias C si se puede evitar (preferir pure Rust).
6. No implementar sharing, móvil, extensiones de navegador ni resolución avanzada de conflictos en el MVP.

## Comandos útiles

```bash
cargo build -p secrets-cli
cargo run -p secrets-cli -- --help
cargo test -p crypto
cargo test -p core
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

## Convención de commits

Conventional Commits en inglés o español, preferiblemente:

- `feat(core): add import env`
- `fix(crypto): handle short argon2 output`
- `docs: update architecture`
- `chore: bump clap`

## Qué NO hacer

- No poner lógica de negocio en `cli` o en `storage`.
- No loguear ni imprimir valores de secretos en claro (usar `mask`).
- No persistir plaintext de variables.
- No acoplar GPUI o clap a `crypto`/`storage`.
- No ampliar el scope a “clon de 1Password” en el MVP.

## Archivos de referencia

- `docs/ARCHITECTURE.md` — diseño y capas
- `docs/ROADMAP.md` — fases del MVP
- `crates/storage/src/schema.rs` — schema SQL
- `.agents/skills/secrets-dev/SKILL.md` — skill específica del proyecto

## Completions

```bash
secrets completions bash|zsh|fish|elvish|powershell
```

Ver `docs/COMPLETIONS.md`.

## Sesión keyring

Tras unlock, la master key se guarda en el OS keyring (`core::session`).  
`secrets lock` la elimina. Ver `docs/SESSION.md`.

## Schema / migraciones

No editar schema inline. Añadir `crates/storage/migrations/NNN_*.sql` y registrarlo en `migrations.rs`. Ver `docs/MIGRATIONS.md`.
