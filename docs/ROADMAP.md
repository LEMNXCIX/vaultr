# Roadmap MVP

## Completado

- [x] Scaffolding + AGENTS/docs/skill
- [x] Crypto + storage + core use cases
- [x] Import/export/search/delete
- [x] Backup cifrado + restore + apply
- [x] CLI completa del MVP
- [x] Tests unitarios/integración
- [x] Autocompletado shell (`vltr completions <shell>`)
- [x] Clippy workspace lints + CI endurecido
- [x] Migraciones SQL versionadas (`001_initial` + runner)

## Siguiente (post-MVP lógico)

- [ ] Desktop GPUI
- [x] Sync Supabase (un usuario)
- [x] Session keyring (no pedir password cada comando)

## Sync Supabase — qué se envió

Un solo usuario, opcional: el vault local sigue siendo la fuente de verdad y
solo viaja ciphertext. Detalle completo en [SYNC.md](SYNC.md).

- [x] Schema remoto con RLS por `owner_id` (`supabase/migrations/0001_init.sql`)
- [x] `signup` / `login` / `logout` con Supabase Auth (email + password)
- [x] `sync` bidireccional: projects, environments y variables
- [x] Guard de salt: si el salt local difiere del remoto, aborta **sin tocar
      nada** en vez de mezclar dos dominios de clave
- [x] Adopción guiada de la clave remota tras ese aborto
- [x] Rotación de la master password (`rekey`) propagada al resto de
      dispositivos vía marcador `pending_rekey_salt`
- [x] Deletes como **tombstones** con cascada project → env → variable
- [x] Cursor incremental de pull (`sync_state.last_pull` + `updated_at`)
- [x] Verificación de la contraseña contra el vault remoto derivando la clave
      en local y probándola sobre un ciphertext de muestra que nunca viaja en
      claro
- [x] `bootstrap` para clonar el vault remoto en un dispositivo nuevo
- [x] Conflictos por LWW sobre `updated_at`

## Fuera de MVP

Sharing, historial, TOTP, VS Code, móvil, CRDTs
