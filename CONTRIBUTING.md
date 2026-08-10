# Contribuir

## Requisitos

- Rust estable reciente (1.85+ recomendado)
- `cargo`, `rustfmt`, `clippy`
- `make` (opcional, para los atajos)

## Setup

```bash
git clone <repo>
cd vaultr
cargo build -p vltr-cli
cargo test --workspace

# Activa los hooks de git (fmt+clippy en commit, tests en push)
./scripts/install-hooks.sh
```

## Estilo

- `cargo fmt --all` (ver `rustfmt.toml`)
- `cargo clippy --workspace --all-targets -- -D warnings`
- Conventional Commits
- Código y comentarios de dominio en inglés; docs de producto pueden ir en español

## Flujo de validación (local-first)

| Fase | Qué corre |
|------|-----------|
| `git commit` (hook pre-commit) | fmt + clippy |
| `git push` (hook pre-push) | tests + `cargo check -p vltr-cli` |
| PR en GitHub (`ci.yml`) | fmt + clippy + test (sin `--release`) |
| tag `v*` (`release.yml`) | validate + build release |

- **No** se corre `cargo build --release` en cada PR.
- Un PR que solo cambia docs/`*.md` no ejecuta jobs de Rust.
- Saltar hooks solo en emergencia: `git commit --no-verify` / `git push --no-verify`.
- Ver `docs/CI_CD.md`.

## Capas

No saltes capas. La CLI y el futuro desktop solo hablan con `core`.

## Seguridad

- Nunca commitear vaults, `.env` reales ni backups cifrados de prueba con secretos reales.
- No imprimir secretos en logs de CI.

## PRs

1. Descripción clara del problema y del enfoque
2. Tests cuando toque lógica de crypto o core
3. CI en verde