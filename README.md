# Vaultr — Secrets Manager

Gestor de secretos **local-first** y **zero-knowledge** para desarrolladores.

Pensado para API keys, `.env`, JWT, credenciales de DB, tokens OAuth, SSH, certificados y config de Docker/K8s — no como reemplazo de un gestor de contraseñas personal.

## Principios

1. **Local First** — SQLite es la fuente de verdad
2. **Zero Knowledge** — cifrado antes de salir del dispositivo
3. **Developer Experience First** — proyectos + environments (como un `.env` enriquecido)

## Modelo

```
Project
 └── Environment (local, development, staging, production…)
      └── Variable (KEY=value cifrado)
```

Al crear un proyecto se crea automáticamente el environment `local`.

## Desarrollo

```bash
# Requisitos: Rust estable reciente
cargo build -p vltr-cli
cargo test --workspace
cargo run -p vltr-cli -- --help
# `cargo run -- --help` also works because the CLI is the workspace default.

# Activa los hooks de git (fmt+clippy en commit, tests en push)
./scripts/install-hooks.sh
```

## Windows PowerShell 7 + WSL

Vaultr se compila y se instala dentro de la distribución WSL; el directorio raíz
es un workspace de Cargo y no se puede instalar con `cargo install` sin
argumentos. Desde PowerShell 7.6.4, ejecuta:

```powershell
wsl -d archlinux -- bash -lc 'cd ~/Repositories/vaultr && cargo run -- --help'
wsl -d archlinux -- bash -lc 'cd ~/Repositories/vaultr && cargo install --path crates/cli --locked'
```

Después de instalarlo, úsalo desde PowerShell mediante WSL:

```powershell
wsl -d archlinux -- vltr status
wsl -d archlinux -- vltr completions powershell
```

`cargo install` sin `--path crates/cli` falla correctamente porque `Cargo.toml`
en la raíz es un manifiesto virtual de workspace, no un paquete instalable.

## Usar Vaultr desde otro repositorio

El vault es local y global para tu usuario. Cada repositorio debe tener su
propio proyecto de Vaultr; al importarlo se crea automáticamente el environment
`local`.

```bash
cd ~/Repositories/mi-otro-repo

vltr unlock
vltr project create                 # usa el nombre del directorio actual
vltr import mi-otro-repo .env       # usa el environment `local`
vltr list mi-otro-repo local
```

`list` enmascara los valores. Para comprobar la importación sin reemplazar el
`.env` real, genera un archivo temporal y compáralo sin imprimir secretos:

```bash
vltr apply mi-otro-repo local --path /tmp/mi-otro-repo.vaultr.env
cmp --silent .env /tmp/mi-otro-repo.vaultr.env && echo "Import/export correcto"
```

Para consultar un valor concreto, ten en cuenta que se imprimirá en la
terminal:

```bash
vltr get mi-otro-repo local NOMBRE_DE_LA_VARIABLE
```

Para importar a otro environment, indícalo explícitamente:

```bash
vltr import mi-otro-repo .env --env development
```

Desde PowerShell, ejecuta los mismos comandos mediante WSL:

```powershell
wsl -d archlinux -- bash -lc 'cd ~/Repositories/mi-otro-repo && vltr list mi-otro-repo local'
```

Atajos (`Makefile` / cargo aliases):

```bash
make check          # fmt + clippy + test (gate local)
make ci             # replica local de ci.yml, sin release
make cli ARGS=status
cargo cli -- status
```

## Estructura

```
crates/models|crypto|storage|core|sync|cli
apps/desktop          # GPUI (fase 2)
docs/                 # Arquitectura y roadmap
.agents/skills/       # Skill para agentes de IA
AGENTS.md             # Instrucciones para cualquier agente
```

## Documentación para humanos y agentes

| Archivo | Uso |
|---------|-----|
| [AGENTS.md](AGENTS.md) | Contrato principal para IAs |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Capas y cifrado |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Fases del MVP |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Estilo y PRs |
| [docs/CI_CD.md](docs/CI_CD.md) | Flujo de hooks, CI y releases |
| `.agents/skills/vaultr/` | Skill de desarrollo del proyecto |

## CLI (MVP en progreso)

```bash
vltr completions zsh > ~/.zfunc/_vltr
```


```bash
vltr init
vltr project create Fudi
vltr set Fudi local OPENAI_API_KEY sk-...
vltr get Fudi local OPENAI_API_KEY --copy
vltr export Fudi local
vltr list Fudi local
vltr status
```

## Licencia

MIT OR Apache-2.0
