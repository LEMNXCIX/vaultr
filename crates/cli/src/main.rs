use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;
use storage::{default_db_path, migrate_legacy_db};
use vltr_core::App;

#[derive(Parser, Debug)]
#[command(
    name = "vltr",
    about = "Local-first secrets manager for developers",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new local vault
    Init,
    /// Unlock the vault and store a session (OS keyring, 0600 session file if unavailable)
    Unlock,
    /// Clear session (keyring + session file)
    Lock,
    /// Show vault status (optionally per-environment)
    Status {
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        all: bool,
    },
    /// Create a project (name defaults to the current directory name)
    Create {
        #[arg(short, long)]
        project: Option<String>,
        /// Extra environment to create besides the default 'local'
        #[arg(short, long)]
        env: Option<String>,
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        color: Option<String>,
    },
    /// List projects
    Projects,
    /// Remove a project or environment (asks for the master password)
    Rm {
        #[command(subcommand)]
        target: Option<RmTarget>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// List environments of a project, or create one
    Env {
        name: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Make an environment the project's default
    Use {
        env: String,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Set or update a variable in the current project
    Set {
        key: String,
        value: Option<String>,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Get a variable (prints its value)
    Get {
        key: String,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
        /// Also copy the value to the clipboard
        #[arg(short, long)]
        copy: bool,
    },
    /// List variables of an environment (values masked)
    Ls {
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Delete a variable (asks for the master password)
    Del {
        key: String,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Search keys across the vault
    Search {
        query: String,
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Write .env file for the current project (merges missing keys into existing files)
    Apply {
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Export as .env
    Export {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Import from .env file
    Import {
        path: PathBuf,
        #[arg(short, long)]
        env: Option<String>,
        #[arg(short, long)]
        project: Option<String>,
    },
    /// Create encrypted backup of the whole vault
    Backup { path: Option<PathBuf> },
    /// Restore vault from encrypted backup into a new db path
    Restore { backup: PathBuf },
    /// Change the master password (re-encrypts the vault with a new key)
    Rekey,
    /// Destroy the vault and start over with a new master password, for when
    /// the current one is lost. This is NOT a recovery. Requires typing
    /// RESET IT to confirm.
    Reset {
        /// Reset only this device; the remote wipe happens on the next `vltr sync`
        #[arg(long)]
        local: bool,
    },
    /// Log in to Supabase sync (see docs/SYNC.md for required env vars)
    Login,
    /// Create a Supabase sync account (see docs/SYNC.md)
    Signup,
    /// Close the Supabase sync session
    Logout,
    /// Initialize this device's vault from the remote vault
    Bootstrap,
    /// Sync local changes with the remote (Supabase)
    Sync,
    /// Generate or install shell completions
    Completions {
        /// Shell name (bash, zsh, fish, elvish, powershell) or `install`
        target: String,
        /// Shell to configure when target is `install`; detected from $SHELL when omitted
        #[arg(long)]
        shell: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RmTarget {
    /// Remove an environment from a project
    Env {
        name: String,
        #[arg(short, long)]
        project: Option<String>,
    },
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let db_path = default_db_path();
    if migrate_legacy_db(&db_path)? {
        println!("Migrated vault to {}", db_path.display());
    }

    match cli.command {
        Commands::Init => {
            let app = App::open(&db_path)?;
            if app.is_initialized()? {
                bail!(
                    "vault already initialized at {}. Create a project with `vltr create` instead",
                    db_path.display()
                );
            }
            // Remote guard: initializing here when this account already has a
            // vault on the server would create a divergent key domain. Never
            // block init on network trouble — local-first above all.
            if vltr_core::sync::init_remote_guard_needed(
                App::sync_available_config(),
                App::sync_session_exists(),
            ) {
                match block_on(App::remote_has_vault()) {
                    Ok(true) => bail!(
                        "A vault already exists on the server for this account. Run `vltr bootstrap` to join it with the same master password."
                    ),
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("Warning: could not check the remote vault ({e}); proceeding with local init.");
                    }
                }
            }
            let password = prompt_password("Create master password: ")?;
            let confirm = prompt_password("Confirm master password: ")?;
            if !crypto::passwords_match(&password, &confirm) {
                bail!("Passwords do not match");
            }
            let mut app = app;
            app.init(password)?;
            println!("Vault initialized at {}", db_path.display());
            print_session_status(&mut app);
            let _ = install_completions(None);
        }
        Commands::Unlock => {
            let mut app = App::open(&db_path)?;
            if !app.is_initialized()? {
                bail!("Vault not initialized. Run `vltr init` first.");
            }
            let password = prompt_password("Master password: ")?;
            app.unlock(password)?;
            // Taken before the store is asked, and taken unconditionally: the
            // error is consumed on read, so asking the store first would decide
            // by accident whether anybody gets to hear about a failed save.
            let save_error = app.take_session_error();
            let store = app.session_store()?;
            for line in unlock_lines(store, save_error.as_deref()) {
                line.emit();
            }
        }
        Commands::Lock => {
            let mut app = App::open(&db_path)?;
            app.lock()?;
            println!("Session cleared.");
        }
        Commands::Status { project, all } => {
            if project.is_some() && all {
                bail!("-p and -a are mutually exclusive");
            }
            let mut app = App::open(&db_path)?;
            let initialized = app.is_initialized()?;
            let info = vltr_core::session::inspect(app.db_path()).ok().flatten();
            if info.is_some() {
                // `let _ =` here reported a session that cannot open this vault
                // as a healthy one: `Session: active` next to `Unlocked: false`,
                // with nothing to explain the contradiction. A session that
                // cannot open its vault is discarded, so the next `status` would
                // print `Session: none` — a third state for a vault that is
                // perfectly fine. Say what happened instead of discarding it.
                if let Err(e) = app.try_unlock_from_session() {
                    eprintln!(
                        "Note: the stored session could not be used to unlock this vault ({e}); \
                         a session that cannot open its vault is discarded."
                    );
                }
            }
            match (&project, all) {
                (None, false) => {
                    println!("Database:    {}", db_path.display());
                    println!("Schema:      v{}", app.schema_version().unwrap_or(0));
                    println!("Initialized: {}", initialized);
                    if let Some(info) = info {
                        let mins = info.remaining_secs / 60;
                        let rem = info.remaining_secs % 60;
                        println!(
                            "Session:     active (~{}m {}s left, {}, refreshes on use)",
                            mins, rem, info.store
                        );
                    } else {
                        println!("Session:     none");
                    }
                    println!("Unlocked:    {}", app.is_unlocked());
                    println!(
                        "TTL:         {} minutes (sliding)",
                        models::constants::SESSION_TTL_SECS / 60
                    );
                }
                (Some(name), false) => {
                    let name = resolve_project(&app, Some(name.clone()))?;
                    print_project_status(&app, &name)?;
                }
                (_, true) => {
                    let projects = app.list_projects()?;
                    if projects.is_empty() {
                        println!("No projects yet.");
                    }
                    for p in projects {
                        print_project_status(&app, &p.name)?;
                    }
                }
            }
        }
        Commands::Create {
            project,
            env,
            desc,
            color,
        } => {
            let app = open_and_unlock(&db_path)?;
            let name = project_name(project)?;
            let created = app.create_project(&name, desc, color, None)?;
            println!("Created project '{}' (id: {})", created.name, created.id);
            println!("  → default environment 'local' created");
            if let Some(env) = env {
                app.create_environment(&created.name, &env)?;
                println!("  → environment '{}' created", env);
            }
        }
        Commands::Projects => {
            let app = open_and_unlock(&db_path)?;
            let projects = app.list_projects()?;
            if projects.is_empty() {
                println!("No projects yet.");
            } else {
                for p in projects {
                    println!("• {} {}", p.name, p.description.unwrap_or_default());
                }
            }
        }
        Commands::Rm { target, project } => {
            let app = open_and_verify(&db_path)?;
            match target {
                None => {
                    let name = project_name(project)?;
                    app.delete_project(&name)?;
                    println!("Deleted project '{}'", name);
                }
                Some(RmTarget::Env { name, project }) => {
                    let project = resolve_project(&app, project)?;
                    app.delete_environment(&project, &name)?;
                    println!("Deleted environment '{}/{}'", project, name);
                }
            }
        }
        Commands::Env { name, project } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            match name {
                None => {
                    let envs = app.list_environments(&project)?;
                    for e in envs {
                        let marker = if e.is_default { " (default)" } else { "" };
                        println!("• {}{}", e.name, marker);
                    }
                }
                Some(env) => {
                    app.create_environment(&project, &env)?;
                    println!("Created environment '{}/{}'", project, env);
                }
            }
        }
        Commands::Use { env, project } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            app.use_environment(&project, &env)?;
            println!("Default environment for '{}' is now '{}'", project, env);
        }
        Commands::Set {
            key,
            value,
            env,
            project,
        } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let value = match value {
                Some(v) => v,
                None => prompt_secret(&format!("Value for {}=", key))?,
            };
            app.set_variable(&project, &env, &key, &value, None)?;
            println!("Set {}={} in {}/{}", key, mask(&value), project, env);
        }
        Commands::Get {
            key,
            env,
            project,
            copy,
        } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let var = app.get_variable(&project, &env, &key)?;
            println!("{}", var.value);
            if copy {
                let mut clipboard = arboard::Clipboard::new().context("clipboard")?;
                clipboard.set_text(&var.value)?;
                eprintln!("Copied {} to clipboard", key);
            }
        }
        Commands::Ls { env, project } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let vars = app.list_variables(&project, &env)?;
            if vars.is_empty() {
                println!("No variables in {}/{}", project, env);
            } else {
                for v in vars {
                    println!("{}={}", v.key, mask(&v.value));
                }
            }
        }
        Commands::Del { key, env, project } => {
            let app = open_and_verify(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            app.delete_variable(&project, &env, &key)?;
            println!("Deleted {}/{}/{}", project, env, key);
        }
        Commands::Search {
            query,
            project,
            env,
        } => {
            let app = open_and_unlock(&db_path)?;
            let hits = app.search(&query, project.as_deref(), env.as_deref())?;
            if hits.is_empty() {
                println!("No matches for '{}'", query);
            } else {
                for h in hits {
                    println!("{}/{}  {}", h.project_name, h.environment_name, h.key);
                }
            }
        }
        Commands::Apply {
            env,
            project,
            output,
        } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let path = output.unwrap_or_else(|| PathBuf::from(".env"));
            app.apply_env(&project, &env, &path)?;
            println!("Wrote {}", path.display());
        }
        Commands::Export {
            output,
            env,
            project,
        } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let content = app.export_env(&project, &env)?;
            if let Some(path) = output {
                std::fs::write(&path, &content)?;
                println!("Wrote {}", path.display());
            } else {
                print!("{}", content);
            }
        }
        Commands::Import { path, env, project } => {
            let app = open_and_unlock(&db_path)?;
            let project = resolve_project(&app, project)?;
            let env = resolve_env(&app, &project, env)?;
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let n = app.import_env(&project, &env, &content)?;
            println!("Imported {} variables into {}/{}", n, project, env);
        }
        Commands::Backup { path } => {
            let path = path.unwrap_or_else(|| default_db_path().with_file_name("vault-backup.enc"));
            let app = open_and_unlock(&db_path)?;
            app.backup(&path)?;
            println!("Backup written to {}", path.display());
        }
        Commands::Restore { backup } => {
            let target = db_path.with_file_name("vault-restored.db");
            if target.exists() {
                bail!("Target already exists: {}", target.display());
            }
            let blob =
                std::fs::read(&backup).with_context(|| format!("read {}", backup.display()))?;
            let password = prompt_password("Master password for backup: ")?;
            App::restore(&target, password, &blob)?;
            println!("Restored vault to {}", target.display());
            println!("Use SECRETS_DB or move file to the default path to open it.");
        }
        Commands::Rekey => {
            let mut app = App::open(&db_path)?;
            if !app.is_initialized()? {
                bail!("Vault not initialized. Run `vltr init` first.");
            }
            let current = prompt_password("Current master password: ")?;
            app.unlock(current)?;
            let new = prompt_password("New master password: ")?;
            let confirm = prompt_password("Confirm new master password: ")?;
            if !crypto::passwords_match(&new, &confirm) {
                bail!("Passwords do not match");
            }
            let count = app.rekey(new)?;
            println!(
                "Master password changed; {count} variable{} re-encrypted.",
                if count == 1 { "" } else { "s" }
            );
            println!("Run `vltr sync` to propagate the new key to other devices.");
            print_session_status(&mut app);
        }
        Commands::Reset { local } => {
            let mut app = App::open(&db_path)?;
            if !app.is_initialized()? {
                bail!("Vault not initialized. Nothing to reset.");
            }
            // `--local` skips the remote wipe, so it is also the way out when
            // there is no sync session: the epoch the wipe publishes is
            // computed in core, where the remote row is in hand.
            if !local && !(App::sync_available_config() && App::sync_session_exists()) {
                bail!(
                    "Reset sin sincronización no puede borrar el vault remoto: ejecuta `vltr login` \
                     y repite, o usa `--local` para resetear solo este dispositivo (el borrado \
                     remoto queda para el próximo `vltr sync`)."
                );
            }
            // Everything from here to the confirmation is read-only: no write, no
            // network call, no session saved. The vault is only touched below.
            println!("Esto NO es una recuperación.");
            println!(
                "Se destruye el vault local ({}): todos sus proyectos, entornos y variables.",
                db_path.display()
            );
            if local {
                println!("El vault remoto no se toca ahora: se borrará en el próximo `vltr sync`.");
            } else {
                println!("También se borra el vault remoto: sus secretos vivos quedan eliminados.");
            }
            println!(
                "Lo cifrado con la contraseña perdida NO se puede recuperar. Lo único que puede \
                 salvarlo es un backup hecho antes del último `vltr rekey`."
            );
            let typed = prompt_line_verbatim("Type RESET IT to confirm: ")?;
            if !confirmation_matches(&typed) {
                bail!("Confirmation phrase does not match. Nothing was changed.");
            }
            let new = prompt_password("New master password: ")?;
            let confirm = prompt_password("Confirm new master password: ")?;
            if !crypto::passwords_match(&new, &confirm) {
                bail!("Passwords do not match");
            }
            // No epoch argument: core derives the local placeholder from this vault
            // and publishes `remote + 1` from the row it fetches.
            let epoch = app.reset_local(new)?;
            println!(
                "Vault local destruido y reiniciado con nueva contraseña maestra (key_epoch \
                 {epoch})."
            );
            print_session_status(&mut app);
            if local {
                println!("El próximo `vltr sync` termina el borrado del vault remoto.");
            } else {
                // A failed remote wipe is not a failed reset: the local vault is
                // already the new domain and `pending_local_reset` survives for
                // the next `vltr sync` to retry.
                match block_on(app.reset_remote()) {
                    Ok(count) => println!(
                        "Vault remoto borrado: {count} fila{} eliminada{}.",
                        if count == 1 { "" } else { "s" },
                        if count == 1 { "" } else { "s" }
                    ),
                    // Nothing to wipe, so nothing failed either: saying "falló"
                    // here would report a failure that never happened.
                    Err(e) if no_remote_vault(&e) => {
                        println!("No hay vault remoto que borrar; el reset local está completo.");
                    }
                    Err(e) => {
                        eprintln!("El reset local se completó, pero el borrado remoto falló: {e}");
                        eprintln!("El próximo `vltr sync` reintenta el borrado remoto.");
                    }
                }
            }
        }
        Commands::Login => {
            require_sync_config()?;
            let app = App::open(&db_path)?;
            let email = prompt_line("Email: ")?;
            let password = prompt_password("Contraseña: ")?;
            block_on(app.sync_login(&email, password.expose_secret()))?;
            println!("Sesión de sincronización iniciada para {email}");
        }
        Commands::Signup => {
            require_sync_config()?;
            let app = App::open(&db_path)?;
            let email = prompt_line("Email: ")?;
            let password = prompt_password("Create password: ")?;
            let confirm = prompt_password("Confirm password: ")?;
            if !crypto::passwords_match(&password, &confirm) {
                bail!("Passwords do not match");
            }
            if block_on(app.sync_signup(&email, password.expose_secret()))? {
                println!("Cuenta creada para {email}. Sesión de sincronización iniciada.");
            } else {
                println!("Cuenta creada. Confirma tu email y luego ejecuta `vltr login`.");
            }
        }
        Commands::Logout => {
            require_sync_config()?;
            let app = App::open(&db_path)?;
            app.sync_logout()?;
            println!("Sesión de sincronización cerrada.");
        }
        Commands::Bootstrap => {
            require_sync_config()?;
            let mut app = App::open(&db_path)?;
            if app.is_initialized()? {
                bail!("este dispositivo ya tiene un vault; usa `vltr sync`");
            }
            let password = prompt_password("Master password: ")?;
            let confirm = prompt_password("Confirm master password: ")?;
            if !crypto::passwords_match(&password, &confirm) {
                bail!("Passwords do not match");
            }
            block_on(app.bootstrap_from_remote(password))?;
            println!("Vault inicializado desde el remoto. Ya puedes usar `vltr sync`.");
        }
        Commands::Sync => {
            require_sync_config()?;
            let mut app = App::open(&db_path)?;
            if !app.is_initialized()? {
                match block_on(App::remote_has_vault()) {
                    Ok(true) => bail!(
                        "este dispositivo no tiene vault pero el remoto sí; usa `vltr bootstrap`"
                    ),
                    Ok(false) => bail!("no hay vault local; ejecuta `vltr init` primero"),
                    Err(e) => {
                        bail!("Sin conexión con Supabase: {e}");
                    }
                }
            }
            // NO unlocking here, on purpose — see `restore_session_quietly` and
            // `unlock_for_adoption` for why, and for the branch that does need
            // the master password.
            restore_session_quietly(&mut app);
            match block_on(app.sync()) {
                Ok(report) => println!("Sincronización completada: {report}"),
                Err(vltr_core::CoreError::RemoteKeyChanged) => {
                    eprintln!(
                        "La contraseña maestra del vault cambió en otro dispositivo (o este vault se inicializó de forma independiente); hace falta la contraseña del vault remoto para continuar."
                    );
                    unlock_for_adoption(&mut app)?;
                    let password =
                        prompt_password("REMOTE vault master password (the one that changed): ")?;
                    block_on(app.adopt_remote_key(password))?;
                    // The adoption saved a session like every other key change,
                    // and this was the one branch that never said whether it
                    // landed. `RemoteKeyChanged` is the most frequent
                    // divergence there is, which made the silent one the common
                    // one.
                    print_session_status(&mut app);
                    // Same retry-once as the divergence prompt below, and for
                    // the same reason: salts match after a successful adopt, so
                    // this re-run cannot loop on the same abort — but a reset
                    // can land in between, and that deserves its own message
                    // rather than "Sin conexión con Supabase".
                    retry_sync_after_divergence(&mut app)?;
                }
                Err(vltr_core::CoreError::RemoteReset(info)) => {
                    eprintln!(
                        "El vault remoto se reseteó en otro dispositivo \
                         (key_epoch {}, key_change {}).",
                        info.remote_epoch,
                        key_change_label(info.key_change.as_deref()),
                    );
                    if let Some(when) = info.key_changed_at {
                        eprintln!("El cambio de clave se registró el {when}.");
                    }
                    eprintln!(
                        "Un reseteo borra los secretos vivos del vault remoto. Este vault local \
                         aún conserva los suyos, y nada se ha subido ni bajado."
                    );
                    eprintln!("  a) Descartar lo local: se destruye este vault y se adopta el del remoto (vacío en ambos)");
                    eprintln!("  b) Conservar lo local: se re-cifra con la contraseña del remoto y se vuelve a subir");
                    eprintln!("  c) Cancelar: no se cambia nada; este vault sigue funcionando, sin sincronizar");
                    match prompt_divergence_choice()? {
                        DivergenceChoice::Discard => {
                            let password = prompt_password("Master password del vault remoto: ")?;
                            block_on(app.discard_local_and_adopt(password))?;
                            println!(
                                "Vault local descartado: ahora vive en el dominio del remoto, \
                                 vacío en ambos dispositivos."
                            );
                            print_session_status(&mut app);
                        }
                        DivergenceChoice::Keep => {
                            // Same as `RemoteKeyChanged`: this choice re-encrypts
                            // the local rows under the remote key, so it needs
                            // them readable first.
                            unlock_for_adoption(&mut app)?;
                            let password = prompt_password("Master password del vault remoto: ")?;
                            block_on(app.adopt_remote_key(password))?;
                            print_session_status(&mut app);
                        }
                        DivergenceChoice::Cancel => {
                            bail!(
                                "Sin cambios. Este vault sigue funcionando con su contraseña actual, \
                                 pero no se sincronizará hasta que decidas qué hacer."
                            );
                        }
                    }
                    // One retry, never a loop: the choice just aligned this vault
                    // with the remote, so a second abort is a new event and is
                    // surfaced instead of retried.
                    retry_sync_after_divergence(&mut app)?;
                }
                Err(e) => bail!("Sin conexión con Supabase: {e}"),
            }
        }
        Commands::Completions { target, shell } => {
            if target == "install" {
                install_completions(shell.as_deref())?;
            } else {
                let shell = Shell::from_str(&target)
                    .map_err(|_| anyhow::anyhow!("unsupported shell: {target}"))?;
                write_completions(shell, &mut io::stdout());
            }
        }
    }

    Ok(())
}

fn require_sync_config() -> Result<()> {
    if !App::sync_available_config() {
        bail!(
            "Sync no configurado: define {} y {} o crea sync.json (ver docs/SYNC.md)",
            vltr_core::sync::SUPABASE_URL_ENV,
            vltr_core::sync::SUPABASE_KEY_ENV
        );
    }
    Ok(())
}

fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut)
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt} ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Read one line verbatim: the prompt is printed exactly as given and only the
/// trailing line terminator is stripped. [`prompt_line`] trims because its
/// callers (project names, emails) want that; a confirmation phrase must be
/// compared exactly as typed, so trimming would turn a footgun into a shortcut.
fn prompt_line_verbatim(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    Ok(line.to_owned())
}

/// Use a stored session for a `vltr sync`, if there is one — and never fail
/// because there isn't.
///
/// `App::sync()` reads the master key in exactly one place: the verifier
/// backfill at `crates/core/src/sync/mod.rs:585`, reachable only when the salt
/// guard answers `Proceed` AND the remote row carries no verifier — a shape no
/// reset path can produce, since `push_reset` always publishes one. Everything
/// else the sync does — finishing a pending wipe, the push, the pull, the merge,
/// the cascade — moves ciphertext and metadata only. `crates/core/tests/
/// reset_locked_sync.rs` pins both halves of that.
///
/// So the vault is opened WITHOUT unlocking. Gating on the password bought the
/// user nothing and cost two things: `vltr sync` became unrunnable without a
/// TTY (cron, CI, hooks, `docker exec`) even on the one command that finishes
/// the wipe a lost password made necessary, and the prompt was a bare
/// "Master password: " with no hint that it was optional or which of the two
/// passwords the user was being asked for.
///
/// A stale session — the old key left behind by a `save_master_key` that
/// failed — is dropped by `App::unlock_with_key` itself, and it is worth saying
/// so out loud, because the alternative is `open_and_unlock`'s `?` turning it
/// into "invalid master password" with no way forward: the password that works
/// is the new one, which the message never mentions.
///
/// The error is reported, not propagated, and deliberately not claimed as a
/// discard: `try_unlock_from_session` can also fail on an I/O error reading the
/// session, which clears nothing.
fn restore_session_quietly(app: &mut App) {
    match app.try_unlock_from_session() {
        Ok(_) => {}
        Err(e) => eprintln!(
            "The stored session could not be used to unlock this vault ({e}); a session that \
             cannot open its vault is discarded. `vltr sync` does not need the master password, \
             so it goes on without one — run `vltr unlock` if a command does."
        ),
    }
}

/// Ask for THIS vault's master password, and only if there is no key in memory.
///
/// The one branch of `vltr sync` that genuinely needs it: `adopt_remote_key`
/// reads every local row to re-encrypt it under the remote key
/// (`crates/core/src/sync/mod.rs:246`), so a locked vault has to be opened
/// first. Its counterpart `discard_local_and_adopt` never reads `require_key()`
/// — it destroys the local rows instead of re-encrypting them — so the
/// "descartar lo local" choice asks for nothing but the remote's password, which
/// is exactly the path the person who reset for a lost password needs.
///
/// The prompt names which vault it wants, because the remote's is asked for
/// immediately after and the two are not interchangeable: after a `reset --local`
/// the password in the user's head is the NEW local one, and typing it into the
/// remote prompt verifies nothing while looking like it might.
fn unlock_for_adoption(app: &mut App) -> Result<()> {
    if app.is_unlocked() {
        return Ok(());
    }
    let password = prompt_password(
        "LOCAL vault master password (to decrypt its variables before re-encrypting them \
         with the remote key): ",
    )?;
    app.unlock(password)?;
    warn_if_session_unavailable(app);
    Ok(())
}

/// Re-run the sync once a divergence was resolved — by the guided adoption
/// after a `RemoteKeyChanged`, or by the three-way prompt after a
/// `RemoteReset`.
///
/// One retry, never a loop: the step before it aligned this vault with the
/// remote, so a second abort is a new event and is surfaced instead of retried.
/// Both aborts need naming, not the catch-all: a reset landing between an
/// adopt and its retry used to be reported as `Sin conexión con Supabase: the
/// remote vault was reset on another device`, which is a connection failure
/// wrapped around a state change — and hides a real condition behind a
/// misleading one.
fn retry_sync_after_divergence(app: &mut App) -> Result<()> {
    match block_on(app.sync()) {
        Ok(report) => {
            println!("Sincronización completada: {report}");
            Ok(())
        }
        Err(vltr_core::CoreError::RemoteReset(_)) => {
            bail!("El remoto se reseteó otra vez; vuelve a intentarlo.")
        }
        Err(vltr_core::CoreError::RemoteKeyChanged) => {
            bail!("El vault remoto cambió de nuevo; vuelve a intentarlo.")
        }
        Err(e) => bail!("Sin conexión con Supabase: {e}"),
    }
}

/// The `key_change` value to show next to the divergence menu, or
/// `desconocido` for anything outside the vocabulary.
///
/// The server is untrusted — `vaults.key_change` is a free-text column — and
/// this value is printed directly above the three options, so echoing it
/// verbatim would let the server print a line that reads like a fourth one.
/// Only the three known values are ever shown. The parser is exact-match
/// either way, so the exposure was social rather than mechanical; this closes
/// it.
fn key_change_label(value: Option<&str>) -> &'static str {
    match value {
        Some(v) if v == models::constants::KEY_CHANGE_INIT => models::constants::KEY_CHANGE_INIT,
        Some(v) if v == models::constants::KEY_CHANGE_REKEY => models::constants::KEY_CHANGE_REKEY,
        Some(v) if v == models::constants::KEY_CHANGE_RESET => models::constants::KEY_CHANGE_RESET,
        _ => "desconocido",
    }
}

/// What to do when a sync finds the remote vault was reset on another device.
///
/// `Discard` is the destructive one and is listed first only because it is the
/// option the reset's author most likely wants; the variant order is not a
/// safety ranking, and the default is the only choice that loses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DivergenceChoice {
    /// Destroy the local vault and adopt the remote's key domain, which after a
    /// reset holds no live secrets. Both devices end up aligned and empty.
    Discard,
    /// Re-encrypt this device's rows under the new key and push them, so the
    /// local data survives the remote's wipe.
    Keep,
    /// Change nothing. The local vault keeps working under its old key, just
    /// unsynced. The default, because it is the only choice that loses nothing.
    Cancel,
}

/// Map one answer line to a choice, or `None` to ask again.
///
/// Pure, and separate from the prompting, because the rule that matters here is
/// testable without a TTY: an empty line must be `Cancel`, and an unrecognized
/// line must re-prompt rather than fall back to *any* default. A default that
/// resolved to `Discard` on a typo would destroy a vault the user never chose
/// to discard, so unknown input is deliberately not a choice at all.
///
/// Only the letters the prompt advertises (`[a/b/c]`) and the full words are
/// accepted. There is no `d`/`k` shorthand: an alias the menu never mentions is
/// an alias the user cannot see they are using, and on this — the one path that
/// can destroy a vault — the accepted set is exactly the documented one.
fn divergence_choice(input: &str) -> Option<DivergenceChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "c" | "cancel" => Some(DivergenceChoice::Cancel),
        "a" | "discard" => Some(DivergenceChoice::Discard),
        "b" | "keep" => Some(DivergenceChoice::Keep),
        _ => None,
    }
}

/// Ask until the answer is one this prompt understands. Only the choice is read
/// here; the password is asked for afterwards, by the branch that needs it, so
/// no answer can destroy anything on its own.
fn prompt_divergence_choice() -> Result<DivergenceChoice> {
    loop {
        let answer = prompt_line("Elige [a/b/c] (Enter = cancelar):")?;
        match divergence_choice(&answer) {
            Some(choice) => return Ok(choice),
            None => eprintln!("Opción no reconocida. Responde a, b, c o Enter para cancelar."),
        }
    }
}

/// The reset confirmation phrase, matched exactly: not trimmed, not case-folded,
/// not whitespace-collapsed. This phrase arms a destructive, irreversible wipe
/// of a vault that may be the last copy of its contents, so a fuzzy match is a
/// footgun pointed at the user's data.
fn confirmation_matches(input: &str) -> bool {
    input == "RESET IT"
}

/// True when `reset_remote`'s error means "this account has no `vaults` row"
/// rather than a failure — nothing was left to wipe, so the caller must not
/// report a failed wipe.
///
/// Matched on the message because `core` returns a plain `CoreError::Other` for
/// it and has no dedicated variant. If that message ever changes, this stops
/// matching and the case falls back to the transport-failure branch, which
/// warns instead of claiming success: the safe direction to fail.
fn no_remote_vault(error: &vltr_core::CoreError) -> bool {
    matches!(
        error,
        vltr_core::CoreError::Other(message) if message == "no vault found on the server"
    )
}

fn resolve_project(app: &App, flag: Option<String>) -> Result<String> {
    let name = match flag {
        Some(p) => p,
        None => current_dir_name()?,
    };
    if app.list_projects()?.iter().any(|p| p.name == name) {
        Ok(name)
    } else {
        anyhow::bail!("No project '{name}' in this vault. Run `vltr create -p {name}`.")
    }
}

fn resolve_env(app: &App, project: &str, flag: Option<String>) -> Result<String> {
    match flag {
        Some(e) => Ok(e),
        None => Ok(app.default_environment(project)?.name),
    }
}

fn current_dir_name() -> Result<String> {
    std::env::current_dir()?
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .context("could not derive a project name from the current directory")
}

fn print_project_status(app: &App, name: &str) -> Result<()> {
    println!("Project '{}':", name);
    for (e, count) in app.project_status(name)? {
        let marker = if e.is_default { " (default)" } else { "" };
        println!(
            "• {}{} — {} var{}",
            e.name,
            marker,
            count,
            if count == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

fn write_completions(shell: Shell, output: &mut dyn Write) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, output);
}

fn install_completions(shell: Option<&str>) -> Result<()> {
    let shell = shell
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .and_then(|value| value.rsplit('/').next().map(str::to_owned))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("cannot detect shell; use `vltr completions install --shell <shell>`")
        })?;
    let parsed =
        Shell::from_str(&shell).map_err(|_| anyhow::anyhow!("unsupported shell: {shell}"))?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    let path = match parsed {
        Shell::Bash => home.join(".local/share/bash-completion/completions/vltr"),
        Shell::Zsh => home.join(".zfunc/_vltr"),
        Shell::Fish => home.join(".config/fish/completions/vltr.fish"),
        Shell::Elvish => home.join(".config/elvish/lib/vltr.elv.ts"),
        Shell::PowerShell => home.join(".config/powershell/Completions/vltr.ps1"),
        _ => {
            return Err(anyhow::anyhow!(
                "automatic installation is not supported for {shell}"
            ))
        }
    };
    let parent = path.parent().context("completion path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut contents = Vec::new();
    write_completions(parsed, &mut contents);
    std::fs::write(&path, contents)?;
    println!("Installed {shell} completions at {}", path.display());
    match parsed {
        Shell::Bash => append_profile_line(
            &home.join(".bashrc"),
            "# vaultr completions",
            &format!("source '{}'", path.display()),
        )?,
        Shell::Zsh => append_profile_line(
            &home.join(".zshrc"),
            "# vaultr completions",
            &format!(
                "fpath=({} $fpath)\nautoload -Uz compinit && compinit",
                path.parent().unwrap().display()
            ),
        )?,
        Shell::PowerShell => {
            #[cfg(windows)]
            let profile = home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1");
            #[cfg(not(windows))]
            let profile = home.join(".config/powershell/Microsoft.PowerShell_profile.ps1");
            append_profile_line(
                &profile,
                "# vaultr completions",
                &format!(". '{}'", path.display()),
            )?;
            println!("Updated PowerShell profile at {}", profile.display());
        }
        Shell::Fish | Shell::Elvish => {}
        _ => {}
    }
    Ok(())
}

fn append_profile_line(path: &std::path::Path, marker: &str, line: &str) -> Result<()> {
    if let Ok(contents) = std::fs::read_to_string(path) {
        if contents.contains(marker) {
            return Ok(());
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut profile = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(profile, "\n{marker}\n{line}")?;
    println!("Updated shell profile at {}", path.display());
    Ok(())
}

fn open_and_unlock(db_path: &std::path::Path) -> Result<App> {
    let mut app = App::open(db_path)?;
    if !app.is_initialized()? {
        bail!("Vault not initialized. Run `vltr init` first.");
    }
    if app.try_unlock_from_session()? {
        return Ok(app);
    }
    let password = prompt_password("Master password: ")?;
    app.unlock(password)?;
    warn_if_session_unavailable(&mut app);
    Ok(app)
}

/// Open the vault and require the master password directly (no session unlock).
/// Used by destructive commands (`rm`, `del`).
fn open_and_verify(db_path: &std::path::Path) -> Result<App> {
    let app = App::open(db_path)?;
    if !app.is_initialized()? {
        bail!("Vault not initialized. Run `vltr init` first.");
    }
    let password = prompt_password("Master password: ")?;
    app.verify_password(password)?;
    Ok(app)
}

fn print_session_status(app: &mut App) {
    let save_error = app.take_session_error();
    let store = app.session_store().ok().flatten();
    for line in session_status_lines(store, save_error.as_deref()) {
        eprintln!("{line}");
    }
}

/// What `print_session_status` has to say about the session, given the store
/// that answered and the error left pending by a failed `save_master_key`.
///
/// Split out so the decision is testable without a TTY: which words get printed
/// is the whole content of `print_session_status`, and the bug it now rules out
/// was a branch that returned before the error was ever read.
///
/// The pending error is consulted FIRST, and it does not matter which store
/// answered. `save_master_key` can fail while the PREVIOUS entry is still in
/// place — a keyring that refuses the write, a full data dir — and then
/// `session_store()` answers `Some(..)`, which is the state where a stale key
/// can be hiding. Consulting the error only from the `None` arm is backwards:
/// `None` means there is no session at all, so there is no stale key to explain.
fn session_status_lines(
    store: Option<vltr_core::session::SessionStore>,
    save_error: Option<&str>,
) -> Vec<String> {
    if let Some(reason) = save_error {
        return vec![format!(
            "Warning: the new master key could not be saved to the session store ({reason}); \
             the previous session may be stale, so commands will fail until you run \
             `vltr unlock`."
        )];
    }
    match store {
        Some(vltr_core::session::SessionStore::Keyring) => Vec::new(),
        Some(vltr_core::session::SessionStore::Memory) => {
            vec!["OS keyring is unavailable; using a local session file instead.".into()]
        }
        None => vec![
            "Warning: no session store is available; the password will be requested for \
             future commands."
                .into(),
        ],
    }
}

/// One line `unlock` has to print, carrying the stream it belongs to.
///
/// `unlock` confirmed a healthy store on stdout and warned on stderr, and that
/// split is part of its decision: a user piping `vltr unlock` should get only
/// the confirmation, and the warning must not be mistaken for it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionLine {
    Stdout(String),
    Stderr(String),
}

impl SessionLine {
    fn emit(&self) {
        match self {
            Self::Stdout(text) => println!("{text}"),
            Self::Stderr(text) => eprintln!("{text}"),
        }
    }
}

/// What `unlock` has to say, given the store that answered and the error left
/// pending by a failed `save_master_key`.
///
/// The pending error is consulted FIRST, and it does not matter which store
/// answered. `save_master_key` can fail while the PREVIOUS entry is still in
/// place — a keyring that refuses the write, a full data dir — and then
/// `session_store()` answers `Some(..)`, which is precisely the state where
/// the entry it points at is STALE: the vault is encrypted under the new key
/// and the store still holds the old one.
///
/// Reading the error only from the `None` arm has that backwards. `None` means
/// nothing is stored, so nothing can be stale and there is nothing to warn
/// about; the arm that answers is the one carrying the bad news. Printing the
/// confirmation there did not merely omit a warning, it asserted something
/// false — the user left the command believing a session existed that would
/// open a vault it can no longer open.
///
/// Not reused from `session_status_lines`: its lines are standalone warnings
/// with no "Vault unlocked" confirmation, and the two healthy outcomes this
/// command has to preserve are sentences of their own — taking its output
/// would drop the stdout confirmation entirely.
fn unlock_lines(
    store: Option<vltr_core::session::SessionStore>,
    save_error: Option<&str>,
) -> Vec<SessionLine> {
    if let Some(reason) = save_error {
        return match store {
            // Nothing is stored, so nothing can go stale: the next command
            // simply asks for the password again, which is what this says.
            None => vec![SessionLine::Stderr(format!(
                "Vault unlocked, but no session could be saved ({reason}); the password will be \
                 requested for future commands."
            ))],
            // A store DID answer — about the entry the failed write left
            // behind, not about the key now in use. So the save cannot be
            // claimed, and the stale entry has to be cleared before another
            // unlock can write the right one.
            Some(_) => vec![SessionLine::Stderr(format!(
                "Vault unlocked for this command, but the new master key could not be saved to \
                 the session store ({reason}); a session from an earlier unlock may still be \
                 stored there with the old key, so every other command will fail until you run \
                 `vltr lock` and `vltr unlock` again."
            ))],
        };
    }
    match store {
        Some(vltr_core::session::SessionStore::Keyring) => {
            vec![SessionLine::Stdout(
                "Vault unlocked (session saved in OS keyring).".into(),
            )]
        }
        Some(vltr_core::session::SessionStore::Memory) => vec![SessionLine::Stdout(
            "Vault unlocked (OS keyring unavailable; local session file in use).".into(),
        )],
        None => vec![SessionLine::Stderr(
            "Vault unlocked, but no session could be started; the password will be requested for \
             future commands."
                .into(),
        )],
    }
}

/// What `warn_if_session_unavailable` has to say about the session it just
/// tried to save, given the store that answered and the error left pending by
/// a failed `save_master_key`.
///
/// Split out so the decision is testable without a TTY, exactly as
/// [`session_status_lines`] is for `print_session_status` — and it reads the
/// two inputs in the same order that function does: the pending error FIRST,
/// then the store.
///
/// The order is the whole fix. This warning used to consult the store only to
/// decide whether a store existed at all, which made it diagnose a failed save
/// as "no session store could be saved" — while the state it was describing is
/// the one where a store DID answer, holding the PREVIOUS entry that the
/// failed write left behind. Worse, its second half ("the password will be
/// requested for future commands") is a prediction, and in that state it is
/// false: the next command finds the stale entry and answers "invalid master
/// password" for the rest of its TTL instead of asking. It never lied about
/// the vault, but it sent the user after the wrong diagnosis and the wrong
/// recovery.
///
/// `None` is the only state where nothing is stored and asking again is the
/// truth, so that is the only arm that keeps the old sentence.
fn session_warning_lines(
    store: Option<vltr_core::session::SessionStore>,
    save_error: Option<&str>,
) -> Vec<String> {
    if let Some(reason) = save_error {
        return match store {
            // Nothing is stored, so nothing can be stale: the next command
            // simply asks for the password again, which is what this says.
            None => vec![format!(
                "Warning: the new master key could not be saved to the session store ({reason}); \
                 the password will be requested for future commands."
            )],
            // A store DID answer — about the entry the failed write left
            // behind, not about the key now in use. So the save cannot be
            // claimed, and the stale entry has to be cleared before another
            // command can open this vault.
            Some(_) => vec![format!(
                "Warning: the new master key could not be saved to the session store ({reason}); \
                 a session from an earlier unlock may still be stored there with the old key, so \
                 every other command will fail until you run `vltr lock` and `vltr unlock` again."
            )],
        };
    }
    match store {
        Some(_) => Vec::new(),
        None => vec![
            "Warning: no session store is available; the password will be requested for \
             future commands."
                .into(),
        ],
    }
}

/// Warn about the session `open_and_unlock` / `unlock_for_adoption` just saved,
/// or failed to save.
fn warn_if_session_unavailable(app: &mut App) {
    // Taken before the store is asked, and taken unconditionally: the error is
    // consumed on read, so asking the store first would decide by accident
    // whether anybody gets to hear about a failed save.
    let save_error = app.take_session_error();
    let store = app.session_store().ok().flatten();
    for line in session_warning_lines(store, save_error.as_deref()) {
        eprintln!("{line}");
    }
}

fn project_name(name: Option<String>) -> Result<String> {
    match name.as_deref() {
        Some(value) if value != "." => Ok(value.to_owned()),
        _ => current_dir_name(),
    }
}

fn prompt_password(prompt: &str) -> Result<SecretString> {
    let pass = rpassword::prompt_password(prompt)?;
    Ok(SecretString::new(pass))
}

fn prompt_secret(prompt: &str) -> Result<String> {
    print!("{} ", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

fn mask(value: &str) -> String {
    if value.len() <= 8 {
        "****".to_string()
    } else {
        format!("{}…{}", &value[..4], &value[value.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_requires_the_exact_phrase() {
        assert!(confirmation_matches("RESET IT"));
        for rejected in [
            "",
            "reset it",
            "RESET",
            "RESET  IT",
            " RESET IT",
            "RESET IT ",
            "RESET IT.",
        ] {
            assert!(!confirmation_matches(rejected), "must reject {rejected:?}");
        }
    }

    #[test]
    fn divergence_choice_defaults_to_cancel() {
        assert_eq!(divergence_choice(""), Some(DivergenceChoice::Cancel));
        assert_eq!(divergence_choice("c"), Some(DivergenceChoice::Cancel));
        assert_eq!(divergence_choice("a"), Some(DivergenceChoice::Discard));
        assert_eq!(divergence_choice("keep"), Some(DivergenceChoice::Keep));
        assert_eq!(divergence_choice("maybe"), None, "unknown input re-prompts");
    }

    #[test]
    fn divergence_choice_accepts_the_advertised_letters_and_ignores_case() {
        for input in ["a", "discard", "A", "Discard", "  a  "] {
            assert_eq!(
                divergence_choice(input),
                Some(DivergenceChoice::Discard),
                "must accept {input:?} as discard"
            );
        }
        for input in ["b", "keep", "B", "Keep"] {
            assert_eq!(
                divergence_choice(input),
                Some(DivergenceChoice::Keep),
                "must accept {input:?} as keep"
            );
        }
        for input in ["c", "cancel", "C", "  "] {
            assert_eq!(
                divergence_choice(input),
                Some(DivergenceChoice::Cancel),
                "must accept {input:?} as cancel"
            );
        }
    }

    #[test]
    fn divergence_choice_never_guesses() {
        // Anything unrecognized must re-prompt, never fall through to a
        // default: a guess that resolved to Discard would wipe a vault.
        for input in ["d!", "descartar", "no", "1", "0", "y", "n", "s"] {
            assert_eq!(
                divergence_choice(input),
                None,
                "must re-prompt on {input:?}, not guess a choice"
            );
        }
    }

    #[test]
    fn divergence_choice_rejects_the_undocumented_shorthand() {
        // The prompt says `[a/b/c]`. `d` and `k` used to be accepted anyway, and
        // `d` is a one-keystroke path to the destructive option that the UI
        // never offers. Not a choice now: re-prompting is the safe direction.
        for input in ["d", "D", "  d  ", "descartar"] {
            assert_eq!(
                divergence_choice(input),
                None,
                "{input:?} is not advertised, so it must re-prompt"
            );
        }
        for input in ["k", "K", "  k  "] {
            assert_eq!(
                divergence_choice(input),
                None,
                "{input:?} is not advertised, so it must re-prompt"
            );
        }
    }

    #[test]
    fn key_change_prints_only_the_three_known_values() {
        // The server is untrusted: `vaults.key_change` is free text and it is
        // printed right above the menu, so anything outside the vocabulary must
        // never reach the terminal verbatim.
        for known in [
            models::constants::KEY_CHANGE_INIT,
            models::constants::KEY_CHANGE_REKEY,
            models::constants::KEY_CHANGE_RESET,
        ] {
            assert_eq!(key_change_label(Some(known)), known);
        }
        for hostile in [
            Some(""),
            Some("reset\n  d) keep local"),
            Some("d"),
            Some("keep"),
            Some("RESET"),
            Some("reset "),
            Some("init; rekey"),
            None,
        ] {
            assert_eq!(
                key_change_label(hostile),
                "desconocido",
                "must not print {hostile:?} verbatim"
            );
        }
    }

    #[test]
    fn a_missing_remote_vault_is_not_a_failed_wipe() {
        // Nothing to wipe, so nothing failed: this must not be reported as a
        // failed remote wipe.
        assert!(no_remote_vault(&vltr_core::CoreError::Other(
            "no vault found on the server".into()
        )));
        // Every other failure keeps the warning-and-retry branch.
        assert!(!no_remote_vault(&vltr_core::CoreError::Other(
            "http error: status 500".into()
        )));
        assert!(!no_remote_vault(&vltr_core::CoreError::RemoteKeyChanged));
    }

    /// A failed `save_master_key` must be reported **whatever** store answered.
    ///
    /// The case that matters is the one where the store answers at all:
    /// `save_master_key` fails writing the NEW key while the PREVIOUS entry is
    /// still in place — the keyring refusing a write, the data dir full — so
    /// `session_store()` returns `Some(..)` and the pending error used to be
    /// dropped on the floor by the arm that returns without reading it.
    ///
    /// The result is the worst possible one and it is silent by construction:
    /// the vault is encrypted under the new key, the stored session still holds
    /// the old one, so `vltr status` reports unlocked and every other command
    /// answers "invalid master password" for the rest of the session's TTL.
    ///
    /// This also pins the wording, because "no session store could be saved" is
    /// the wrong diagnosis for that state: something WAS saved, just not the
    /// key that is now in use.
    #[test]
    fn a_failed_session_save_is_reported_whatever_store_answered() {
        use vltr_core::session::SessionStore;
        let reason = "keyring: no such interface";

        for store in [
            Some(SessionStore::Keyring),
            Some(SessionStore::Memory),
            None,
        ] {
            let lines = session_status_lines(store, Some(reason));
            assert_eq!(
                lines.len(),
                1,
                "{store:?}: a failed save must produce exactly one warning, got {lines:?}"
            );
            assert!(
                lines[0].contains(reason),
                "{store:?}: the failure itself must be shown, got {lines:?}"
            );
            assert!(
                lines[0].contains("vltr unlock"),
                "{store:?}: the only recovery has to be named, got {lines:?}"
            );
            assert!(
                !lines[0].contains("no session store could be saved"),
                "{store:?}: a store DID answer — that wording blames the wrong thing, \
                 got {lines:?}"
            );
        }
    }

    /// The counterpart, so the fix above cannot pass by muting everything: a
    /// save that worked still reports the store it landed in, exactly as before.
    #[test]
    fn a_successful_session_save_still_reports_the_store() {
        use vltr_core::session::SessionStore;

        assert!(
            session_status_lines(Some(SessionStore::Keyring), None).is_empty(),
            "the keyring needs no comment"
        );
        assert_eq!(
            session_status_lines(Some(SessionStore::Memory), None),
            vec!["OS keyring is unavailable; using a local session file instead."],
        );
        assert_eq!(
            session_status_lines(None, None),
            vec![
                "Warning: no session store is available; the password will be requested for \
                 future commands."
            ],
        );
    }

    /// `warn_if_session_unavailable` — the warning every unlocked command shows
    /// when it had to ask for the password — must not blame a store that
    /// answered.
    ///
    /// The state is the one bug 2 was about: `save_master_key` fails writing the
    /// NEW key while the PREVIOUS entry is still in place, so `session_store()`
    /// answers `Some(..)`. The old wording said "no session store could be
    /// saved ... the password will be requested for future commands", which is
    /// wrong twice over: a store DID answer, and with a stale entry the next
    /// command does NOT ask — it finds that entry and answers "invalid master
    /// password" for the rest of its TTL.
    #[test]
    fn a_failed_session_save_is_never_blamed_on_a_store_that_answered() {
        use vltr_core::session::SessionStore;
        let reason = "keyring: no such interface";

        for store in [Some(SessionStore::Keyring), Some(SessionStore::Memory)] {
            let lines = session_warning_lines(store, Some(reason));
            let said = lines.join(" | ");
            assert_eq!(lines.len(), 1, "{store:?}: one warning, got {lines:?}");
            assert!(
                said.contains(reason),
                "{store:?}: the failure itself must be shown, got {said:?}"
            );
            assert!(
                !said.contains("no session store could be saved"),
                "{store:?}: a store DID answer — that diagnosis sends the user after the wrong \
                 thing, got {said:?}"
            );
            assert!(
                !said.contains("the password will be requested"),
                "{store:?}: with a stale entry stored, the next command does not ask for a \
                 password — it fails on that entry. Got {said:?}"
            );
            assert!(
                said.contains("vltr lock") && said.contains("vltr unlock"),
                "{store:?}: the stale entry has to be cleared and rewritten, so both steps have \
                 to be named. Got {said:?}"
            );
        }

        // No store at all: nothing is stored, so nothing can be stale and
        // asking for the password again is exactly right.
        let lines = session_warning_lines(None, Some(reason));
        assert_eq!(
            lines,
            vec![format!(
                "Warning: the new master key could not be saved to the session store ({reason}); \
                 the password will be requested for future commands."
            )]
        );
    }

    /// The counterpart, so the fix above cannot pass by warning about
    /// everything: a session that saved fine says nothing, and a vault with no
    /// session at all keeps its pre-existing warning.
    #[test]
    fn a_healthy_session_store_is_not_warned_about() {
        use vltr_core::session::SessionStore;

        assert!(
            session_warning_lines(Some(SessionStore::Keyring), None).is_empty(),
            "a keyring session needs no comment"
        );
        assert!(
            session_warning_lines(Some(SessionStore::Memory), None).is_empty(),
            "the local session file is a working session; this warning never mentioned it"
        );
        assert_eq!(
            session_warning_lines(None, None),
            vec![
                "Warning: no session store is available; the password will be requested for \
                 future commands."
            ],
        );
    }

    /// Everything `unlock` prints, whatever stream each line goes to.
    fn unlock_says(lines: &[SessionLine]) -> String {
        lines
            .iter()
            .map(|line| match line {
                SessionLine::Stdout(text) | SessionLine::Stderr(text) => text.as_str(),
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// `unlock` must not claim a session was saved when the save FAILED.
    ///
    /// This is the case that lies. `save_master_key` fails writing the NEW
    /// master key while the PREVIOUS entry is still in place — a keyring that
    /// refuses the write, a full data dir — so `session_store()` answers
    /// `Some(Keyring)`. The arm that answered used to print "session saved in
    /// OS keyring" without ever reading the pending error, which is available
    /// and is the only thing that knows the truth.
    ///
    /// What the user is left with is the worst combination available: the
    /// vault is encrypted under the new key, the stored session still holds the
    /// old one, and the command they just ran told them it was all fine. Here
    /// the symptom is not a missing warning but a positive statement that is
    /// false — strictly worse than the same bug in `print_session_status`.
    #[test]
    fn unlock_never_claims_a_session_saved_when_the_save_failed() {
        use vltr_core::session::SessionStore;
        let reason = "keyring: no such interface";

        for store in [Some(SessionStore::Keyring), Some(SessionStore::Memory)] {
            let lines = unlock_lines(store, Some(reason));
            let said = unlock_says(&lines);

            assert!(
                !said.contains("saved in OS keyring"),
                "{store:?}: the store answering does not mean the NEW key was saved — \
                 the entry it points at may still be the previous one. Got: {said}"
            );
            assert!(
                !said.contains("session saved"),
                "{store:?}: no wording may assert a save that failed. Got: {said}"
            );
            assert!(
                said.contains(reason),
                "{store:?}: the failure itself has to be shown. Got: {said}"
            );
            assert!(
                said.contains("vltr lock") && said.contains("vltr unlock"),
                "{store:?}: the stale entry has to be cleared and rewritten, so both steps \
                 have to be named. Got: {said}"
            );
            assert_eq!(
                lines,
                vec![SessionLine::Stderr(said.clone())],
                "{store:?}: a failed save is one warning, and on stderr — stdout is what a \
                 user of `vltr unlock` reads as the confirmation. Got: {lines:?}"
            );
        }
    }

    /// The counterpart, so the fix above cannot pass by muting `unlock`: when
    /// the save worked, it still prints exactly the three sentences it printed
    /// before, on the streams it printed them on.
    #[test]
    fn a_successful_unlock_prints_exactly_what_it_printed_before() {
        use vltr_core::session::SessionStore;

        assert_eq!(
            unlock_lines(Some(SessionStore::Keyring), None),
            vec![SessionLine::Stdout(
                "Vault unlocked (session saved in OS keyring).".into()
            )],
        );
        assert_eq!(
            unlock_lines(Some(SessionStore::Memory), None),
            vec![SessionLine::Stdout(
                "Vault unlocked (OS keyring unavailable; local session file in use).".into()
            )],
        );
        assert_eq!(
            unlock_lines(None, None),
            vec![SessionLine::Stderr(
                "Vault unlocked, but no session could be started; the password will be requested \
                 for future commands."
                    .into()
            )],
        );
    }

    /// The fourth pre-existing sentence, kept: no store AND a failed save is not
    /// the stale-entry case — nothing is stored, so nothing can hold an old key
    /// — and this is the wording it always had, asking for the password again.
    #[test]
    fn a_failed_save_with_no_store_is_not_reported_as_a_stale_entry() {
        let lines = unlock_lines(None, Some("data dir is full"));
        assert_eq!(
            lines,
            vec![SessionLine::Stderr(
                "Vault unlocked, but no session could be saved (data dir is full); the password \
                 will be requested for future commands."
                    .into()
            )],
        );
        assert!(
            !unlock_says(&lines).contains("old key"),
            "with nothing stored there is no old key to clear. Got: {}",
            unlock_says(&lines)
        );
    }
}
