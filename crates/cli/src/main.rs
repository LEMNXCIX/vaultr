use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use secrecy::SecretString;
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
    /// Unlock the vault and store a session (OS keyring, memory if unavailable)
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
            match App::session_store()? {
                Some(vltr_core::session::SessionStore::Keyring) => {
                    println!("Vault unlocked (session saved in OS keyring).");
                }
                Some(vltr_core::session::SessionStore::Memory) => {
                    println!("Vault unlocked (OS keyring unavailable; local session file in use).");
                }
                None => match app.take_session_error() {
                    Some(reason) => {
                        eprintln!("Vault unlocked, but no session could be saved ({reason}); the password will be requested for future commands.");
                    }
                    None => {
                        eprintln!("Vault unlocked, but no session could be started; the password will be requested for future commands.");
                    }
                },
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
            let info = vltr_core::session::inspect().ok().flatten();
            if info.is_some() {
                let _ = app.try_unlock_from_session();
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
    match App::session_store().ok().flatten() {
        Some(vltr_core::session::SessionStore::Keyring) => {}
        Some(vltr_core::session::SessionStore::Memory) => {
            eprintln!("OS keyring is unavailable; using a local session file instead.");
        }
        None => warn_if_session_unavailable(app),
    }
}

fn warn_if_session_unavailable(app: &mut App) {
    if let Some(reason) = app.take_session_error() {
        eprintln!("Warning: no session store could be saved ({reason}); the password will be requested for future commands.");
    } else if !App::has_keyring_session().unwrap_or(false) {
        eprintln!(
            "Warning: no session store is available; the password will be requested for future commands."
        );
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
