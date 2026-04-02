//! Argument structures for CLI commands

use clap::Args;
use clap_complete::Shell;

/// Arguments for the `run` command
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Upstream SSH agent socket path
    ///
    /// Defaults to SSH_AUTH_SOCK environment variable.
    #[arg(long)]
    pub upstream: Option<std::path::PathBuf>,

    /// Socket path to listen on
    ///
    /// Format: --socket PATH [FILTERS...]
    ///
    /// Arguments after PATH until the next option are filters for this socket.
    /// If no --socket is specified, a default socket is created.
    ///
    /// Examples:
    ///   --socket /tmp/warden.sock
    ///   --socket /tmp/work.sock comment=*@work* type=ed25519
    #[arg(long, num_args = 1..)]
    pub socket: Vec<String>,

    /// Print configuration as TOML and exit
    #[arg(long)]
    pub print_config: bool,

    /// Foreground mode (always true for `run`)
    #[arg(long, hide = true, default_value = "true")]
    pub foreground: bool,
}

impl RunArgs {
    /// Parse --socket args into (path, filters) pairs
    pub fn parse_sockets(&self) -> Vec<(String, Vec<String>)> {
        if self.socket.is_empty() {
            return vec![];
        }

        let mut result = Vec::new();
        let mut current_path: Option<String> = None;
        let mut current_filters: Vec<String> = Vec::new();

        for arg in &self.socket {
            // If it looks like a filter (contains '='), add to current socket
            if arg.contains('=') || arg.starts_with("not-") {
                current_filters.push(arg.clone());
            } else {
                // New socket path — save previous if any
                if let Some(path) = current_path.take() {
                    result.push((path, std::mem::take(&mut current_filters)));
                }
                current_path = Some(arg.clone());
            }
        }

        // Save last socket
        if let Some(path) = current_path {
            result.push((path, current_filters));
        }

        result
    }
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
