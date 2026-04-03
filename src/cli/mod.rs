//! CLI module for authsock-warden

pub mod args;
pub mod commands;
pub mod exit_code;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use args::{CompletionArgs, LogArgs, RegisterArgs, RunArgs, UnregisterArgs};
pub use internal::InternalCommand;

/// SSH agent proxy with key filtering, process-aware access control, and 1Password integration
#[derive(Parser, Debug)]
#[command(name = "authsock-warden")]
#[command(author, about, long_about = None)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct Cli {
    /// Print help
    #[arg(long, action = clap::ArgAction::Help, global = true)]
    help: Option<bool>,

    /// Print version
    #[arg(short = 'V', long)]
    pub version: bool,

    /// Configuration file path
    #[arg(long, global = true, env = "AUTHSOCK_WARDEN_CONFIG")]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Suppress non-essential output
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the proxy in the foreground
    Run(RunArgs),

    /// Manage configuration file
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },

    /// Manage OS service (launchd/systemd)
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },

    /// View service logs
    Log(LogArgs),

    /// Generate shell completions
    Completion(CompletionArgs),

    /// Show managed keys and their status
    Keys,

    /// Refresh key timers (re-authenticate)
    Refresh,

    /// Show warden status (key states, timers)
    Status,

    #[command(hide = true)]
    Version,

    /// Internal commands (not for direct use)
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        command: InternalCommand,
    },
}

mod internal {
    use super::*;

    #[derive(Subcommand, Debug, Clone)]
    pub enum InternalCommand {
        /// Check Full Disk Access status
        FdaCheck {
            /// Path to write result ("ok" or "denied"). If omitted, prints to stdout.
            #[arg(long)]
            result_file: Option<PathBuf>,
            /// Run the TCC check directly (skip .app re-launch). Used internally.
            #[arg(long)]
            raw: bool,
        },
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommand {
    /// Show current configuration
    Show,
    /// Open configuration in editor
    Edit,
    /// Print configuration file path
    Path,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceCommand {
    /// Register as an OS service (launchd/systemd)
    Register(RegisterArgs),
    /// Unregister the OS service
    Unregister(UnregisterArgs),
    /// Reload the OS service configuration
    Reload(UnregisterArgs),
    /// Show OS service status
    Status(UnregisterArgs),
}
