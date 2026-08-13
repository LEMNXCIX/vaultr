use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use secrecy::SecretString;
use std::io::{self, Write};
use std::path::PathBuf;
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
    /// Unlock the vault and store session in OS keyring
    Unlock,
    /// Clear session (keyring + memory)
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
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    Completions { shell: Shell },
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
    let db_path = default_db_path();
    if migrate_legacy_db(&db_path)? {
        println!("Migrated vault to {}", db_path.display());
    }

    match cli.command {
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
            warn_if_session_unavailable();
        }
        Commands::Unlock => {
            let mut app = App::open(&db_path)?;
            if !app.is_initialized()? {
                bail!("Vault not initialized. Run `vltr init` first.");
            }
            let password = prompt_password("Master password: ")?;
            app.unlock(password)?;
            if App::has_keyring_session().unwrap_or(false) {
                println!("Vault unlocked (session saved in OS keyring).");
            } else {
                eprintln!("Vault unlocked, but the OS keyring is unavailable; the password will be requested for future commands.");
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
            let hits = app.search(&query)?;
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
            let remaining = vltr_core::session::seconds_remaining().ok().flatten();
            let session = remaining.is_some();
            if session {
                let _ = app.try_unlock_from_session();
            }
            println!("Database:    {}", db_path.display());
            println!("Schema:      v{}", app.schema_version().unwrap_or(0));
            println!("Initialized: {}", initialized);
            if let Some(secs) = remaining {
                let mins = secs / 60;
                let rem = secs % 60;
                println!(
                    "Session:     active (~{}m {}s left, refreshes on use)",
                    mins, rem
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
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut io::stdout());
        }
    }

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

fn warn_if_session_unavailable() {
    if !App::has_keyring_session().unwrap_or(false) {
        eprintln!(
            "Warning: OS keyring session is unavailable; install and run a keyring service to avoid entering the password for each command."
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
