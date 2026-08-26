# Supabase Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sincronizar proyectos/environments/variables entre dispositivos vía Supabase (Postgres + Auth), zero-knowledge: solo viajan ciphertexts (`value_encrypted`+`nonce`); la master password y el verifier nunca salen del dispositivo.

**Architecture:** Nuevo crate `crates/sync` (cliente HTTP REST puro-Rust contra PostgREST/Auth de Supabase) orquestado desde `core` con push/pull manual (`vltr sync`). Local SQLite sigue siendo fuente de verdad. Deletes pasan a soft-delete (tombstones) para propagarse. Conflictos: Last-Write-Wins por `updated_at` con reporte en el output. El schema del server vive como SQL en el repo (`supabase/migrations/`) para que el usuario lo aplique en SU proyecto Supabase.

**Tech Stack:** reqwest (rustls-tls, pure Rust), serde_json ya presente, keyring para JWT, rusqlite. Nueva dependencia: solo `reqwest`.

**Spec:** Conversación 2026-08-25. Decisiones: Auth email+password; sync manual; LWW + reporte; usuario aplica el SQL a su propio proyecto Supabase.

## Global Constraints

- Offline nunca bloquea: sync solo corre dentro de `vltr sync/login/logout`.
- Zero-knowledge: jamás enviar password maestra, verifier, ni plaintext. Solo ciphertexts + metadata.
- Capas: HTTP en `crates/sync`; orquestación/LWW en `core`; SQLite en `storage`; clap en `cli`. El CLI no conoce URLs ni SQL.
- Credenciales Supabase por env vars `VLTR_SUPABASE_URL` y `VLTR_SUPABASE_ANON_KEY` (config file queda fuera; ponytail).
- Gate por tarea: `cargo clippy --workspace --all-targets -- -D warnings`; final: fmt + test + check.
- Conventional Commits.

---

### Task 1: SQL del server (aplicable por el usuario)

**Files:**
- Create: `supabase/migrations/0001_init.sql`
- Create: `docs/SYNC.md`

**Interfaces:** Tablas que Task 3 consumirá vía PostgREST.

```sql
-- 0001_init.sql
create table public.vaults (
  owner_id uuid primary key references auth.users(id) on delete cascade,
  salt text not null,            -- base64
  kdf_params jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.projects (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null,
  description text,
  color text,
  icon text,
  deleted boolean not null default false,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (owner_id, name)
);

create table public.environments (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  project_id uuid not null references public.projects(id) on delete cascade,
  name text not null,
  is_default boolean not null default false,
  sort_order int not null default 0,
  deleted boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, name)
);

create table public.variables (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  environment_id uuid not null references public.environments(id) on delete cascade,
  key text not null,
  value_encrypted text not null,   -- base64 del ciphertext XChaCha20-Poly1305
  nonce text not null,             -- base64, 24 bytes
  notes text,
  is_readonly boolean not null default false,
  allow_export boolean not null default true,
  deleted boolean not null default false,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (environment_id, key)
);

alter table public.projects enable row level security;
alter table public.environments enable row level security;
alter table public.variables enable row level security;
alter table public.vaults enable row level security;

create policy "own rows" on public.projects    for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own rows" on public.environments for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own rows" on public.variables   for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own row"  on public.vaults      for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
```

`docs/SYNC.md`: cómo aplicar (dashboard SQL editor o `supabase db push`), cómo crear las env vars, qué se sincroniza y qué no.

- [ ] Escribir ambos archivos. Commit: `feat(sync): supabase schema and setup docs`

---

### Task 2: Tombstones + dirty tracking en SQLite (migración local)

**Files:**
- Create: `crates/storage/migrations/002_sync_support.sql`
- Modify: `crates/storage/src/migrations.rs` (registrar)
- Modify: `crates/storage/src/lib.rs`

```sql
alter table projects add column deleted integer not null default 0;
alter table environments add column deleted integer not null default 0;
alter table variables add column deleted integer not null default 0;
alter table projects add column synced_at text;
alter table environments add column synced_at text;
alter table variables add column synced_at text;
create table sync_state (key text primary key, value text not null);
```

Cambios en storage:
- Models: añadir `deleted: bool` a `Project`/`Environment`/`Variable` (models es puro dato — sí toca models).
- Todos los SELECT/listas añaden `WHERE ... AND deleted = 0` (y los JOINs de search también).
- `delete_project`/`delete_environment`/`delete_variable` → UPDATE `deleted = 1, updated_at = now, version = version + 1` (devuelven bool igual).
- Unique constraints locales: borrar una variable y recrearla con la misma key chocaría con UNIQUE(environment_id,key) si la fila vieja queda. Solución lazy: el UNIQUE local incluye `deleted`: no se puede cambiar un UNIQUE sin reconstruir la tabla… alternativa: en `create_variable`/`get_variable` tratar filas deleted como inexistentes requiere índice parcial. Decisión: crear índice único parcial nuevo en 002 (`DROP INDEX`/nuevo `CREATE UNIQUE INDEX ... WHERE deleted = 0`) y soltar el constraint UNIQUE original de las tablas (rebuild de tabla en SQLite: crear tabla nueva + copiar + drop + rename, patrón estándar). Documentar en la migración.
- Helpers nuevos: `Storage::mark_synced(table, ids, ts)`, `Storage::dirty_rows(table) -> rows con synced_at IS NULL OR updated_at > synced_at`, `SyncState::get/set(conn, key)` para el cursor `last_pull`.

- [ ] Migración + cambios + tests (roundtrip soft-delete: variable borrada no aparece en list/get/search pero sí en dirty_rows). Commit: `feat(storage): tombstones and dirty tracking for sync`

---

### Task 3: Cliente HTTP Supabase (`crates/sync`)

**Files:**
- Modify: root `Cargo.toml` (miembro `crates/sync`, dep workspace `reqwest = { version = "...", default-features = false, features = ["json", "rustls-tls"] }`)
- Create: `crates/sync/Cargo.toml`, `crates/sync/src/lib.rs`, `crates/sync/src/auth.rs`

**Interfaces:**
- `SyncClient::new(base_url: &str, anon_key: &str) -> Result<Self>` (reqwest::Client interno).
- `login(email, password) -> Result<Session>` — POST `{base}/auth/v1/token?grant_type=password`, headers `apikey: anon`. Session { access_token, refresh_token, expires_in }.
- `refresh(&refresh_token) -> Result<Session>` — grant_type=refresh_token.
- `push_vault(salt_b64, kdf_params_json)`, `get_vault()` — tabla `vaults` (upsert `on_conflict=owner_id` con header `Prefer: resolution=merge-duplicates`).
- `push_rows<T: Serialize>(table: &str, rows: &[T])` — POST con `Prefer: resolution=merge-duplicates,return=minimal` (upsert masivo).
- `pull_rows<T: DeserializeOwned>(table: &str, since: Option<&str>) -> Result<Vec<T>>` — GET `/rest/v1/{table}?select=*&updated_at=gt.{since}&order=updated_at.asc` con paginación Range (2000 por página hasta página corta).
- Errores: `SyncError` (thiserror) con variantes Http/Auth/Config.
- Sin lógica de negocio: solo transporte. Base64 de blobs lo hace quien llama (core).

- [ ] Implementar + test unitario de serialización de payloads y parse de error 401 (sin red real; mockear con `httpmock`? No — ponytail: probar parse con fixtures JSON inline, la red se prueba E2E manual). Commit: `feat(sync): supabase rest client with auth`

---

### Task 4: Orquestación en `core` (LWW + reporte)

**Files:**
- Create: `crates/core/src/sync.rs`
- Modify: `crates/core/src/lib.rs`, `Cargo.toml` de core (dep `sync`, `base64` — añadir `base64` workspace dep)

**Interfaces:**
- `App::sync_login(email, password) -> Result<(), CoreError>` — login vía sync crate, guarda sesión JWT en keyring (entry distinta: `KEYRING_SERVICE` + account `supabase-session`), guarda refresh token igual.
- `App::sync_logout()`, `App::sync_enabled() -> bool` (env vars presentes + hay sesión).
- `App::bootstrap_from_remote(password: SecretString) -> Result<(), CoreError>` — dispositivo nuevo: get_vault remoto → escribir vault_meta local (salt+kdf) → derivar key con password → unlock. Falla si vault local ya inicializado.
- `App::sync() -> Result<SyncReport, CoreError>`:
  1. Push vault_meta (salt/kdf) si local más nuevo o remoto vacío.
  2. Push dirty rows de cada tabla (mapear a JSON: blobs→base64, timestamps RFC3339, incluir `deleted`).
  3. Pull `updated_at > cursor(last_pull)` de vaults/projects/environments/variables.
  4. Merge LWW por fila: si remoto.updated_at > local.updated_at → sobrescribir fila local completa (incluye tombstones: aplicar soft-delete); si local gana o igual → nada (ya se pusheó). Insertar si no existe localmente.
  5. Marcar synced_at = now en lo pusheado; actualizar cursor last_pull = max(updated_at visto).
  - `SyncReport { pushed: usize, pulled: usize, conflicts_won_remote: Vec<String>, deleted_pulled: usize }` — Display legible para el CLI ("3 subidas, 5 bajadas, 2 actualizados remotamente: …").
- Todo bajo `require_key` NO necesario: sync mueve ciphertexts, no descifra.

Tests: LWW merge y tombstone-pull con Storage en memoria y DTOs construidos a mano (sin red). Commit: `feat(core): sync orchestration with lww merge`

---

### Task 5: CLI (`login`, `logout`, `sync`)

**Files:**
- Modify: `crates/cli/src/main.rs`

- `vltr login` — pide email + password (rpassword), llama `sync_login`, imprime ok. Requiere env vars; si faltan, mensaje claro apuntando a docs/SYNC.md.
- `vltr logout` — limpia sesión Supabase del keyring.
- `vltr sync` — si vault local vacío Y remoto tiene vault → sugerir `vltr bootstrap`; si no, correr `App::sync()` e imprimir el reporte. Errores de red: mensaje "offline, intenta luego" exit code 1 sin corromper nada.
- `vltr init --from-remote` o comando aparte `vltr bootstrap` (elegir bootstrap explícito: menos magia en init).
- [ ] Implementar + smoke local con servidor fake no trivial — probar solo help/rutas de error sin env vars. Commit: `feat(cli): login logout and sync commands`

---

### Task 6: Verificación E2E (manual, la hace el usuario)

**Files:**
- `docs/SYNC.md` ampliado con checklist E2E.

Checklist para el usuario con SU proyecto Supabase:
1. Exportar `VLTR_SUPABASE_URL`/`VLTR_SUPABASE_ANON_KEY`, aplicar `0001_init.sql`.
2. Dispositivo A: `vltr login && vltr sync` (sube vault).
3. Dispositivo B (o dir limpio): `vltr bootstrap` + password → `vltr ls` muestra los secretos.
4. Editar en B, `vltr sync`; editar en A, `vltr sync` → verificar LWW.
5. `vltr rm` en B, sync, sync en A → desaparece.
- Commit: `docs(sync): e2e verification checklist`

---

### Task 7: Gate final

- [ ] `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo check -p vltr-cli`
- [ ] Confirmar: sin env vars, ningún comando existente cambia de comportamiento (sync es opt-in total).

## Fuera de alcance

- Auto-sync en background, CRDTs, sharing multiusuario, key rotation remota, config file para credenciales, cifrado adicional del payload completo (los valores ya están cifrados campo a campo).
