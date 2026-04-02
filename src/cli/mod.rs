//! CLI module for authsock-warden

pub mod args;
pub mod commands;
pub mod exit_code;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use args::{CompletionArgs, LogArgs, RegisterArgs, RunArgs, UnregisterArgs};

/// SSH agent proxy with key filtering, process-aware access control, and 1Password integration
#[derive(Parser, Debug)]
#[command(name = "authsock-warden")]
#[command(author, about, long_about = None)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct Cli {
    #[arg(long, action = clap::ArgAction::Help, global = true)]
    help: Option<bool>,

    #[arg(short = 'V', long)]
    pub version: bool,

    #[arg(long, global = true, env = "AUTHSOCK_WARDEN_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

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
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommand {
    Show,
    Edit,
    Path,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceCommand {
    Register(RegisterArgs),
    Unregister(UnregisterArgs),
    Reload(UnregisterArgs),
    Status(UnregisterArgs),
}
