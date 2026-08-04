---
name: vltr
description: Develop the local-first Rust secrets manager (CLI first, GPUI later). Use when working on crates models crypto storage core sync cli, schema, encryption, .env import export, or MVP features. Enforces Local First, Zero Knowledge, and layer separation.
---

# Secrets Manager — skill de desarrollo

## Antes de escribir código

1. Leer `AGENTS.md` y `docs/ARCHITECTURE.md`.
2. Confirmar en qué crate debe vivir el cambio:
   - Datos puros → `models`
   - Cifrado / KDF → `crypto`
   - SQL / persistencia → `storage`
   - Orquestación / reglas de negocio → `core`
   - Flags CLI / UX terminal → `cli`
3. No implementar sharing, móvil ni UI desktop hasta que la CLI del MVP esté usable.

## Checklist al terminar un cambio

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Patrones obligatorios

- Secretos en memoria: `Zeroizing<Vec<u8>>` o `secrecy::SecretString`. Nunca `String` persistente para master key o valores descifrados más de lo necesario.
- Persistencia: solo ciphertext + nonce en `variables`.
- Errores de librería: `thiserror`. Binarios: `anyhow`.
- IDs nuevos: `Uuid::now_v7()`.
- Al crear project: crear environment `local` con `is_default = true`.
- Respetar `allow_export` en export (saltar variables con flag false).

## Añadir un use case nuevo

1. Método en `core::App`.
2. Persistencia mínima en `storage` si falta.
3. Comando en `cli` que solo llama a `core`.
4. Test en `core` o `crypto` según corresponda.

## Import .env (referencia de diseño)

- Parsear líneas `KEY=VALUE`, ignorar comentarios y líneas vacías.
- Soportar valores entre comillas simples/dobles.
- Escribir cada par con `set_variable` (o batch en transacción).
- Environment destino obligatorio (ej. `local`).

## Backup cifrado (referencia de diseño)

- Exportar meta + projects + environments + variables (ciphertext tal cual).
- Envolver el blob con XChaCha20-Poly1305 usando una clave derivada del master password (o pedir password de backup).
- Restore: validar, reinsertar, no mezclar con vault ya inicializado sin confirmación.

## Lo que no debes hacer

- Loguear o `println!` de valores de secretos en claro.
- Acceder a `rusqlite` desde `cli` o `crypto`.
- Añadir SQLCipher en el MVP (cifrado a nivel de aplicación es suficiente).
- Introducir dependencias nativas C sin necesidad fuerte.
