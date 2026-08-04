# Arquitectura

## Diagrama de capas

```
┌─────────────────────────────────────────┐
│  apps/desktop (GPUI)    crates/cli      │  Presentación
└─────────────────┬───────────────────────┘
                  │ solo llama a core
┌─────────────────▼───────────────────────┐
│              crates/core                │  Casos de uso
│  init, unlock, create_project, set/get, │
│  import/export, search, backup…         │
└───────┬─────────────────────┬───────────┘
        │                     │
┌───────▼────────┐   ┌────────▼────────┐
│ crates/storage │   │  crates/crypto  │
│ SQLite + repo  │   │ Argon2 + XChaCha│
└───────▲────────┘   └────────▲────────┘
        │                     │
        └──────────┬──────────┘
                   │
          ┌────────▼────────┐
          │  crates/models  │  Dominio puro
          └─────────────────┘
```

`crates/sync` es un stub. Solo se activará cuando el MVP local esté sólido.

## Flujo de un secreto

1. Usuario: `vltr set Fudi local OPENAI_API_KEY sk-...`
2. CLI parsea y pide unlock si hace falta.
3. `core::App::set_variable`:
   - Resuelve project + environment
   - Llama a `crypto::encrypt(master_key, value)`
   - Persiste vía `storage` (ciphertext + nonce)
4. Nunca se escribe plaintext en disco.

## Jerarquía de claves

```
Master Password
      │ Argon2id (salt + params en vault_meta)
      ▼
Master Key (32 bytes, Zeroizing)
      │ (futuro) HKDF / envelope
      ▼
Project Key (preparado, no obligatorio en MVP)
      │
      ▼
Cada Variable: XChaCha20-Poly1305 (nonce 24 bytes aleatorio)
```

## Schema (resumen)

- `vault_meta` — salt + parámetros KDF (1 fila)
- `projects`
- `environments` (FK project, UNIQUE name por project)
- `variables` (FK environment, UNIQUE key por environment, flags readonly/export)

Ver `crates/storage/src/schema.rs`.

## Reglas de diseño

| Regla | Motivo |
|-------|--------|
| UUID v7 como PK | Orden temporal + sync futuro |
| Cifrado por variable | Rotación y sharing granular |
| Environment obligatorio | Refleja flujo real de dev |
| Flags `is_readonly` / `allow_export` desde día 1 | Evitar migraciones dolorosas |
| WAL + foreign_keys en SQLite | Integridad y concurrencia básica |

## Testing

- Unit: `crypto` (roundtrip, wrong key)
- Unit/integration: `storage` con `open_in_memory`
- Integration: `core` con vault en memoria
- CLI: tests manuales o `assert_cmd` más adelante
