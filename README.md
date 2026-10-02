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

Instala completions una sola vez; el comando escribe el script y actualiza el
perfil del shell detectado. También puedes indicar el shell explícitamente:

```bash
vltr completions install
vltr completions install --shell bash
vltr completions install --shell zsh
vltr completions install --shell fish
vltr completions install --shell powershell
```

`cargo install` sin `--path crates/cli` falla correctamente porque `Cargo.toml`
en la raíz es un manifiesto virtual de workspace, no un paquete instalable.

## Usar Vaultr desde otro repositorio

El vault es local y global para tu usuario. Cada repositorio debe tener su
propio proyecto de Vaultr; al importarlo se crea automáticamente el environment
`local`.

Sin `-p` se usa el proyecto del directorio actual; sin `-e`, el environment por defecto.

```bash
cd ~/Repositories/mi-otro-repo

vltr unlock
vltr create                         # usa el nombre del directorio actual
vltr import .env                    # usa el environment `local`
vltr ls
```

`ls` enmascara los valores. Para comprobar la importación sin reemplazar el
`.env` real, genera un archivo temporal y compáralo sin imprimir secretos:

```bash
vltr apply -o /tmp/mi-otro-repo.vaultr.env
cmp --silent .env /tmp/mi-otro-repo.vaultr.env && echo "Import/export correcto"
```

Para consultar un valor concreto, ten en cuenta que se imprimirá en la
terminal:

```bash
vltr get NOMBRE_DE_LA_VARIABLE
```

Para importar a otro environment, indícalo explícitamente:

```bash
vltr import .env -e development
```

Desde PowerShell, ejecuta los mismos comandos mediante WSL:

```powershell
wsl -d archlinux -- bash -lc 'cd ~/Repositories/mi-otro-repo && vltr ls'
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
| [docs/SYNC.md](docs/SYNC.md) | Sync con Supabase, guard de salt, conflictos |
| [docs/SESSION.md](docs/SESSION.md) | Sesión con keyring y su fallback en disco |
| [docs/MIGRATIONS.md](docs/MIGRATIONS.md) | Schema y migraciones SQL versionadas |
| [docs/COMPLETIONS.md](docs/COMPLETIONS.md) | Autocompletado shell |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Estilo y PRs |
| [docs/CI_CD.md](docs/CI_CD.md) | Flujo de hooks, CI y releases |
| `.agents/skills/vaultr/` | Skill de desarrollo del proyecto |

## CLI

```bash
# 1. Vault y sesión (la master key vive en el keyring del SO)
vltr init                  # crea el vault en la ruta por defecto
vltr unlock                # abre el vault y guarda la sesión

# 2. Proyecto y environments (el nombre sale del directorio actual)
cd ~/work/mi-api
vltr create                # proyecto "mi-api" + environment `local`
vltr env development       # crea un environment extra
vltr env                   # lista los environments del proyecto
vltr use development       # cambia el environment por defecto

# 3. Variables — sin -p se usa el proyecto del directorio actual,
#    y sin -e el environment por defecto de ese proyecto
vltr set DATABASE_URL postgres://localhost/mi_api
vltr set STRIPE_KEY sk-... -e production
vltr ls                    # lista enmascarando los valores
vltr get STRIPE_KEY        # imprime el valor
vltr get STRIPE_KEY --copy # además lo copia al portapapeles
vltr search stripe         # busca claves en todo el vault
vltr del STRIPE_KEY        # borra la variable
```

```bash
# 4. .env de entrada y salida
vltr import .env -e development
vltr export -o /tmp/mi_api.env
vltr apply                 # escribe/actualiza el .env del proyecto

# 5. Backup cifrado y rotación de la master password
vltr backup ~/backups/vaultr.bak
vltr restore ~/backups/vaultr.bak
vltr rekey                 # nueva contraseña; re-cifra el vault

# 6. Estado
vltr status --all          # proyectos y environments con su conteo
vltr projects
```

Sync opcional con Supabase — solo viaja ciphertext, nunca la master key.
Ver [docs/SYNC.md](docs/SYNC.md) para el setup y el modelo de conflictos.

```bash
vltr signup                # crea la cuenta remota
vltr login                 # sesión (JWT + refresh) en el keyring
vltr sync                  # sube y baja cambios
vltr bootstrap             # otro dispositivo: parte del vault remoto
vltr logout
```

Autocompletado:

```bash
vltr completions zsh > ~/.zfunc/_vltr
vltr completions install            # instala y actualiza el perfil del shell
```

La variable de entorno `SECRETS_DB` sobreescribe la ruta por defecto del vault
(`~/.local/share/vaultr/vault.db`). Debe tener un valor **no vacío**: si está
vacía o solo contiene espacios se ignora y gana la ruta por defecto, para que un
`export SECRETS_DB=` accidental no abra un vault vacío.

```bash
export SECRETS_DB=~/.local/share/vaultr/otro-vault.db
```

## Licencia

MIT OR Apache-2.0
