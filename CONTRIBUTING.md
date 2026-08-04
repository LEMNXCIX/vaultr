# Contribuir

## Requisitos

- Rust estable reciente (1.85+ recomendado)
- `cargo`, `rustfmt`, `clippy`

## Setup

```bash
git clone <repo>
cd secrets-manager
cargo build -p secrets-cli
cargo test --workspace
```

## Estilo

- `cargo fmt --all` (ver `rustfmt.toml`)
- `cargo clippy --workspace -- -D warnings`
- Conventional Commits
- Código y comentarios de dominio en inglés; docs de producto pueden ir en español

## Capas

No saltes capas. La CLI y el futuro desktop solo hablan con `core`.

## Seguridad

- Nunca commitear vaults, `.env` reales ni backups cifrados de prueba con secretos reales.
- No imprimir secretos en logs de CI.

## PRs

1. Descripción clara del problema y del enfoque
2. Tests cuando toque lógica de crypto o core
3. CI en verde
