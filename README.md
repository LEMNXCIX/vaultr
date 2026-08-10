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

# Activa los hooks de git (fmt+clippy en commit, tests en push)
./scripts/install-hooks.sh
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
