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
    #[command(hide = true, name = "__session-agent")]
    SessionAgent,
    /// Initialize a new local vault
    Init,
    /// Unlock the vault and store a session (OS keyring, memory if unavailable)
    Unlock,
    /// Clear session (keyring + memory agent)
    Lock,
    /// Project management
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Environment management
    #[command(subcommand)]
    Env(EnvCmd),
    /// Set or update a variable
    Set {
        project: String,
        env: String,
        key: String,
        value: Option<String>,
    },
    /// Get a variable
    Get {
        project: String,
        env: String,
        key: String,
        #[arg(long, short)]
        copy: bool,
    },
    /// Delete a variable
    #[command(visible_alias = "rm")]
    Delete {
        project: String,
        env: String,
        key: String,
    },
    /// List variables
    List { project: String, env: String },
    /// Export as .env
    Export {
        project: String,
        env: String,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Import from .env file
    Import {
        project: String,
        path: PathBuf,
        /// Target environment (defaults to local)
        #[arg(long, short, default_value = "local")]
        env: String,
    },
    /// Search keys across all projects
    Search { query: String },
    /// Write .env file to path (default: ./.env)
    Apply {
        project: String,
        env: String,
        #[arg(long, short, default_value = ".env")]
        path: PathBuf,
    },
    /// Create encrypted backup of the whole vault
    Backup { path: PathBuf },
    /// Restore vault from encrypted backup into a new db path
    Restore {
        backup: PathBuf,
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Show vault status
    Status,
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
enum ProjectCmd {
    Create {
        /// Project name (defaults to the current directory name)
        name: Option<String>,
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        color: Option<String>,
    },
    List,
    Delete {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum EnvCmd {
    List { project: String },
    Create { project: String, name: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    if matches!(cli.command, Commands::SessionAgent) {
        return vltr_core::session::serve_memory_agent().map_err(Into::into);
    }
    let db_path = default_db_path();
    if migrate_legacy_db(&db_path)? {
        println!("Migrated vault to {}", db_path.display());
    }

    match cli.command {
        Commands::SessionAgent => unreachable!("handled before opening the vault"),
        Commands::Init => {
            let app = App::open(&db_path)?;
            if app.is_initialized()? {
                bail!(
                    "vault already initialized at {}. Create a project with `vltr project create <name>` instead",
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
            print_session_status();
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
                    println!(
                        "Vault unlocked (OS keyring unavailable; local in-memory session active)."
                    );
                }
                None => {
                    eprintln!("Vault unlocked, but no session could be started; the password will be requested for future commands.");
                }
            }
        }
        Commands::Lock => {
            let mut app = App::open(&db_path)?;
            app.lock()?;
            println!("Session cleared.");
        }
        Commands::Project(ProjectCmd::Create { name, desc, color }) => {
            let app = open_and_unlock(&db_path)?;
            let name = project_name(name)?;
            let project = app.create_project(&name, desc, color, None)?;
            println!("Created project '{}' (id: {})", project.name, project.id);
            println!("  → default environment 'local' created");
        }
        Commands::Project(ProjectCmd::List) => {
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
        Commands::Project(ProjectCmd::Delete { name }) => {
            let app = open_and_unlock(&db_path)?;
            app.delete_project(&name)?;
            println!("Deleted project '{}'", name);
        }
        Commands::Env(EnvCmd::List { project }) => {
            let app = open_and_unlock(&db_path)?;
            let envs = app.list_environments(&project)?;
            for e in envs {
                let marker = if e.is_default { " (default)" } else { "" };
                println!("• {}{}", e.name, marker);
            }
        }
        Commands::Env(EnvCmd::Create { project, name }) => {
            let app = open_and_unlock(&db_path)?;
            app.create_environment(&project, &name)?;
            println!("Created environment '{}/{}'", project, name);
        }
        Commands::Set {
            project,
            env,
            key,
            value,
        } => {
            let app = open_and_unlock(&db_path)?;
            let value = match value {
                Some(v) => v,
                None => prompt_secret(&format!("Value for {}=", key))?,
            };
            app.set_variable(&project, &env, &key, &value, None)?;
            println!("Set {}={} in {}/{}", key, mask(&value), project, env);
        }
        Commands::Get {
            project,
            env,
            key,
            copy,
        } => {
            let app = open_and_unlock(&db_path)?;
            let var = app.get_variable(&project, &env, &key)?;
            if copy {
                let mut clipboard = arboard::Clipboard::new().context("clipboard")?;
                clipboard.set_text(&var.value)?;
                println!("Copied {} to clipboard", key);
            } else {
                println!("{}", var.value);
            }
        }
        Commands::Delete { project, env, key } => {
            let app = open_and_unlock(&db_path)?;
            app.delete_variable(&project, &env, &key)?;
            println!("Deleted {}/{}/{}", project, env, key);
        }
        Commands::List { project, env } => {
            let app = open_and_unlock(&db_path)?;
            let vars = app.list_variables(&project, &env)?;
            if vars.is_empty() {
                println!("No variables in {}/{}", project, env);
            } else {
                for v in vars {
                    println!("{}={}", v.key, mask(&v.value));
                }
            }
        }
        Commands::Export {
            project,
            env,
            output,
        } => {
            let app = open_and_unlock(&db_path)?;
            let content = app.export_env(&project, &env)?;
            if let Some(path) = output {
                std::fs::write(&path, &content)?;
                println!("Wrote {}", path.display());
            } else {
                print!("{}", content);
            }
        }
        Commands::Import { project, path, env } => {
            let app = open_and_unlock(&db_path)?;
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let n = app.import_env(&project, &env, &content)?;
            println!("Imported {} variables into {}/{}", n, project, env);
        }
        Commands::Search { query } => {
            let app = open_and_unlock(&db_path)?;
            let hits = app.search(&query, None, None)?;
            if hits.is_empty() {
                println!("No matches for '{}'", query);
            } else {
                for h in hits {
                    println!("{}/{}  {}", h.project_name, h.environment_name, h.key);
                }
            }
        }
        Commands::Apply { project, env, path } => {
            let app = open_and_unlock(&db_path)?;
            app.apply_env(&project, &env, &path)?;
            println!("Wrote {}", path.display());
        }
        Commands::Backup { path } => {
            let app = open_and_unlock(&db_path)?;
            app.backup(&path)?;
            println!("Backup written to {}", path.display());
        }
        Commands::Restore { backup, target } => {
            let target = target.unwrap_or_else(|| {
                let mut p = db_path.clone();
                p.set_file_name("vault-restored.db");
                p
            });
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
        Commands::Status => {
            let mut app = App::open(&db_path)?;
            let initialized = app.is_initialized()?;
            let info = vltr_core::session::inspect().ok().flatten();
            if info.is_some() {
                let _ = app.try_unlock_from_session();
            }
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
    warn_if_session_unavailable();
    Ok(app)
}

fn print_session_status() {
    match App::session_store().ok().flatten() {
        Some(vltr_core::session::SessionStore::Keyring) => {}
        Some(vltr_core::session::SessionStore::Memory) => {
            eprintln!("OS keyring is unavailable; using a local in-memory session instead.");
        }
        None => warn_if_session_unavailable(),
    }
}

fn warn_if_session_unavailable() {
    if !App::has_keyring_session().unwrap_or(false) {
        eprintln!(
            "Warning: no session store is available (OS keyring and local agent both failed); the password will be requested for future commands."
        );
    }
}

fn project_name(name: Option<String>) -> Result<String> {
    match name.as_deref() {
        Some(value) if value != "." => Ok(value.to_owned()),
        _ => std::env::current_dir()?
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .context("could not derive a project name from the current directory"),
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
