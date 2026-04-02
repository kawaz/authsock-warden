//! Config command implementation

use crate::cli::ConfigCommand;
use std::path::PathBuf;

pub async fn execute(
    command: Option<ConfigCommand>,
    config_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let command = command.unwrap_or(ConfigCommand::Show);
    match command {
        ConfigCommand::Show => {
            let path = resolve_config_path(config_path.as_deref());
            match path {
                Some(p) => {
                    let content = std::fs::read_to_string(&p)?;
                    println!("{}", content);
                }
                None => {
                    println!("No configuration file found.");
                    println!("Create one at: ~/.config/authsock-warden/config.toml");
                }
            }
            Ok(())
        }
        ConfigCommand::Edit => {
            anyhow::bail!("config edit not yet implemented")
        }
        ConfigCommand::Path => {
            let path = resolve_config_path(config_path.as_deref());
            match path {
                Some(p) => println!("{}", p.display()),
                None => println!("No configuration file found."),
            }
            Ok(())
        }
    }
}

/// Resolve the config file path: use explicit path if given, otherwise search standard locations
fn resolve_config_path(explicit: Option<&std::path::Path>) -> Option<PathBuf> {
    match explicit {
        Some(p) if p.exists() => Some(p.to_path_buf()),
        Some(_) => None,
        None => crate::config::find_config_file(),
    }
}
