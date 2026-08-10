# CI/CD — local-first

Este proyecto aplica el mismo principio *local-first* del producto a su propio
flujo de desarrollo: **las validaciones frecuentes ocurren primero en local**;
GitHub Actions solo confirma en entorno limpio y publica releases.

```
commits ──► pre-commit (local, rápido)     fmt + clippy
pushes  ──► pre-push (local)               tests + cargo check
PR      ──► ci.yml (GitHub, limpio)        fmt + clippy + test  (sin release)
tag v*  ──► release.yml (GitHub)           validate + build release + Release
semana  ──► audit.yml (GitHub)             cargo-deny (advisories/licencias)
```

## Activar los hooks

```bash
./scripts/install-hooks.sh
```

Esto ejecuta `git config core.hooksPath .githooks` (no hay symlinks ni
dependencias extra). Verifica que quedó activo:

```bash
git config core.hooksPath   # → .githooks
```

Saltar los hooks **solo para emergencias**:

```bash
git commit --no-verify
git push --no-verify
```

## Qué corre dónde

| Etapa | Dónde | Qué ejecuta | Coste |
|-------|-------|-------------|-------|
| pre-commit | local | `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` | rápido (< 30–60 s en caliente) |
| pre-push | local | `cargo test --workspace` + `cargo check -p vltr-cli` | medio (incluye Argon2id) |
| CI de PR | GitHub (ci.yml) | fmt + clippy + test + completions smoke (binario **debug**) | solo cuando cambia Rust |
| Release | GitHub (release.yml) | validate (fmt+clippy+test) + `cargo build --release` | solo en tags `v*` |
| Audit | GitHub (audit.yml) | `cargo-deny check` (advisories + licencias + bans) | semanal |

Reglas de oro:

- **Nunca** `cargo build --release` en cada PR ni en cada push a main.
- Los tests de `crypto` usan Argon2id y son lentos → **no** corren en
  pre-commit (sí en pre-push y en CI).
- Un PR que solo cambia `*.md`/docs **no** ejecuta jobs de Rust (lo decide
  `dorny/paths-filter` en el job `changes` de `ci.yml`).

## Antes → después

| | Antes | Después |
|---|-------|---------|
| Commit local | nada (solo el editor) | fmt + clippy automáticos |
| Push local | nada | tests + check del CLI |
| CI por PR | un job que incluía `build --release` | jobs paralelos fmt/clippy/test, sin release |
| Docs-only PR | compilaba toda la cadena | skips todos los jobs de Rust |
| Cambios de dependencias | solo al hacer el PR | + audit semanal de `cargo-deny` |
| Release | no definido | tags `v*` → binario + completions + Release |

## CI (`ci.yml`) en detalle

- Triggers: `pull_request`, `push` a `main`/`master`, `workflow_dispatch`.
- `concurrency` con `cancel-in-progress: true`: si un nuevo push llega al mismo
  PR/ref, cancela la ejecución anterior y ahorra minutos.
- Job `changes` (paths-filter) decide si algo de Rust cambió (`crates/**`,
  `Cargo.toml`, `Cargo.lock`, `rustfmt.toml`, `clippy.toml`, `.cargo/**`,
  `.githooks/**`, `scripts/**`, `Makefile`, `deny.toml`).
- `fmt`, `clippy` y `test` corren **en paralelo** y solo si `rust == 'true'`.
- `Swatinem/rust-cache` en cada job (caché de compilación de Actions).
- `RUSTFLAGS=-Dwarnings` y `CARGO_INCREMENTAL=0` (CI limpio y determinista).
- El job `test` además hace `cargo check -p vltr-cli`, un build debug y smoke de
  completions (`./target/debug/vltr completions bash|zsh|fish`).

## Releases (`release.yml`)

1. `git tag v0.1.0` y `git push origin v0.1.0` (o `git push --tags`).
2. `release.yml` corre: job `validate` (fmt + clippy + test) y job `release`
   con matrix **Linux x86_64** (`x86_64-unknown-linux-gnu`).
3. Genera completions (bash/zsh/fish), empaqueta en `tar.gz` el binario `vltr`
   + completions + README, sube artefacto y crea el GitHub Release con notas.

Para un release manual sin tag (solo artefactos): `workflow_dispatch`.

Multi-OS (macOS/Windows) está preparado pero comentado en la matrix; se activa
cuando el proyecto lo necesite.

## Audit (`audit.yml`)

Semanal (lunes 03:00 UTC) + `workflow_dispatch`. Usa `cargo-deny` con la
configuración de `deny.toml`: advisories de seguridad, licencias (MIT/Apache y
permisivas) y bans. **No** corre en cada PR: para un mantenedor, el feedback
semanal es suficiente y no gasta minutos por PR.

## Fallo de un hook local: qué mirar

```bash
git config core.hooksPath          # debe ser .githooks
.githooks/pre-commit               # ejecutar a mano para ver el error real
make check                         # gate completo local
```

Los hooks exigen el workspace completo (`crates/*`). Si `cargo` falla con
*"workspace member … not found"*, los crates aún no existen en el árbol.

## Referencia rápida

| Comando | Equivale a |
|---------|-----------|
| `make pre-commit` | `.githooks/pre-commit` |
| `make pre-push` | `.githooks/pre-push` |
| `make check` | `fmt-check` + `clippy` + `test` |
| `make ci` | réplica local de `ci.yml` (sin release) |
| `make release` | `cargo build -p vltr-cli --release` |
