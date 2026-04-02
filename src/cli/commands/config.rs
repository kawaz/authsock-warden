//! Config command - manage configuration file

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

use crate::cli::ConfigCommand;
use crate::config::{config_search_paths, find_config_file};

/// Default configuration template
fn default_config() -> &'static str {
    r#"# authsock-warden configuration
# See: https://github.com/kawaz/authsock-warden

# Source groups
# [[sources]]
# name = "default"
# members = ["op://"]

# Socket definitions
# [sockets.default]
# path = "$XDG_RUNTIME_DIR/authsock-warden/default.sock"
# source = "default"
"#
}

/// Execute the config command
pub async fn execute(
    command: Option<ConfigCommand>,
    config_override: Option<PathBuf>,
) -> Result<()> {
    let command = command.unwrap_or(ConfigCommand::Show);

    match command {
        ConfigCommand::Show => show(config_override).await,
        ConfigCommand::Edit => edit(config_override).await,
        ConfigCommand::Path => path(config_override).await,
    }
}

/// Show configuration content
async fn show(config_override: Option<PathBuf>) -> Result<()> {
    let config_path = config_override.or_else(find_config_file);

    if let Some(path) = config_path {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        print!("{}", content);
    } else {
        eprintln!("No configuration file found.");
        eprintln!("Create one with: authsock-warden config edit");
    }

    Ok(())
}

/// Open configuration in editor
async fn edit(config_override: Option<PathBuf>) -> Result<()> {
    let config_path = config_override
        .filter(|p| p.is_file())
        .or_else(find_config_file);

    let path = match config_path {
        Some(p) => p,
        None => {
            // Create default config at first search path
            let default_path = config_search_paths()
                .first()
                .map(|cp| cp.path.clone())
                .context("No config search paths available")?;

            // Create parent directory if needed
            if let Some(parent) = default_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }

            // Write default config
            std::fs::write(&default_path, default_config()).with_context(|| {
                format!("Failed to create config file: {}", default_path.display())
            })?;

            eprintln!("Created: {}", default_path.display());
            default_path
        }
    };

    // Get editor from EDITOR env var or use platform default
    let editor = std::env::var("EDITOR").ok();

    #[cfg(target_os = "macos")]
    let (cmd, args) = match editor {
        Some(e) => (e, vec![path.display().to_string()]),
        None => (
            "open".to_string(),
            vec!["-t".to_string(), path.display().to_string()],
        ),
    };

    #[cfg(target_os = "linux")]
    let (cmd, args) = match editor {
        Some(e) => (e, vec![path.display().to_string()]),
        None => ("xdg-open".to_string(), vec![path.display().to_string()]),
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let (cmd, args) = match editor {
        Some(e) => (e, vec![path.display().to_string()]),
        None => bail!("No EDITOR environment variable set"),
    };

    let status = std::process::Command::new(&cmd)
        .args(&args)
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        bail!("Editor exited with error");
    }

    Ok(())
}

/// Print configuration file path
async fn path(config_override: Option<PathBuf>) -> Result<()> {
    let config_path = config_override.or_else(find_config_file);

    if let Some(path) = config_path {
        println!("{}", path.display());
    } else {
        // Print where it would be created
        let default_path = config_search_paths()
            .first()
            .map(|cp| cp.path.clone())
            .context("No config search paths available")?;
        eprintln!("# Config file does not exist. Would be created at:");
        println!("{}", default_path.display());
    }

    Ok(())
}
