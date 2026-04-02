//! Argument structures for CLI commands

use clap::Args;
use clap_complete::Shell;

/// Arguments for the `run` command
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Print configuration as TOML and exit
    #[arg(long)]
    pub print_config: bool,

    /// Foreground mode (always true for `run`)
    #[arg(long, hide = true, default_value = "true")]
    pub foreground: bool,
}

/// Arguments for the `register` command
#[derive(Args, Debug, Clone)]
pub struct RegisterArgs {
    /// Service name
    #[arg(long, default_value = "authsock-warden")]
    pub name: String,

    /// Path to the executable for the service
    #[arg(long, value_name = "PATH")]
    pub executable: Option<std::path::PathBuf>,

    /// Force registration with non-recommended path
    #[arg(long)]
    pub force: bool,
}

/// Arguments for the `unregister` command
#[derive(Args, Debug, Clone)]
pub struct UnregisterArgs {
    /// Service name
    #[arg(long, default_value = "authsock-warden")]
    pub name: String,
}

/// Arguments for the `log` command
#[derive(Args, Debug, Clone)]
pub struct LogArgs {
    /// Show logs from the last duration
    #[arg(long)]
    pub since: Option<String>,

    /// Follow log output
    #[arg(long)]
    pub follow: bool,
}

/// Arguments for the `completion` command
#[derive(Args, Debug, Clone)]
pub struct CompletionArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: Shell,
}
