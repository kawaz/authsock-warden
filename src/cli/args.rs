//! Argument structures for CLI commands

use clap::Args;
use clap_complete::Shell;

/// Arguments for the `run` command
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Key source group definition
    ///
    /// Format: --source [NAME=]MEMBER[,MEMBER...]
    ///
    /// Each --source starts a new group. Subsequent --socket
    /// definitions belong to that group until the next --source.
    ///
    /// Member types:
    ///
    ///   op://            All 1Password SSH keys
    ///   op://vault       Keys in a specific vault
    ///   op://vault/item  A specific key
    ///   agent:PATH       Proxy to SSH agent socket
    ///   file:PATH        Load private key from file
    ///   PATH             Auto-detect (socket/file)
    ///
    /// If omitted, $SSH_AUTH_SOCK is used as default source.
    #[arg(long, num_args = 1, action = clap::ArgAction::Append, verbatim_doc_comment)]
    pub source: Vec<String>,

    /// Socket path to listen on
    ///
    /// Format: --socket PATH [FILTERS...]
    ///
    /// Arguments after PATH until the next --source or --socket are filters.
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

/// Parsed source group from CLI arguments
#[derive(Debug, Clone)]
pub struct CliSourceGroup {
    pub name: String,
    pub members: Vec<String>,
    pub sockets: Vec<CliSocket>,
}

/// Parsed socket from CLI arguments
#[derive(Debug, Clone)]
pub struct CliSocket {
    pub path: String,
    pub filters: Vec<String>,
}

impl RunArgs {
    /// Parse CLI arguments into source groups with their sockets.
    ///
    /// --source starts a new group, --socket adds to the current group.
    /// If no --source, an implicit group from $SSH_AUTH_SOCK is created.
    pub fn parse_groups(&self) -> Vec<CliSourceGroup> {
        // Use raw args to get proper grouping (--source ... --socket ... --source ...)
        let raw_args: Vec<String> = std::env::args().collect();
        parse_groups_from_raw(&raw_args)
    }
}

/// Parse a source argument: [NAME=]MEMBER[,MEMBER...]
fn parse_source_arg(arg: &str) -> (String, Vec<String>) {
    let (name, members_str) = if let Some((n, rest)) = arg.split_once('=') {
        // Check if this is actually a named source (name=members)
        // vs a member with = in it (like a filter)
        // Source names don't contain : or / so this is safe
        if !n.contains(':') && !n.contains('/') {
            (n.to_string(), rest)
        } else {
            ("default".to_string(), arg)
        }
    } else {
        ("default".to_string(), arg)
    };
    let members: Vec<String> = members_str.split(',').map(|s| s.to_string()).collect();
    (name, members)
}

/// Helper: push socket to group if both exist
fn push_socket(socket: Option<CliSocket>, group: &mut Option<CliSourceGroup>) {
    if let Some(sock) = socket
        && let Some(ref mut g) = *group
    {
        g.sockets.push(sock);
    }
}

/// Helper: finalize and push group to list if non-empty
fn finalize_group(group: Option<CliSourceGroup>, groups: &mut Vec<CliSourceGroup>) {
    if let Some(g) = group
        && !g.sockets.is_empty()
    {
        groups.push(g);
    }
}

/// Parse groups from raw command line args
fn parse_groups_from_raw(args: &[String]) -> Vec<CliSourceGroup> {
    let mut groups: Vec<CliSourceGroup> = Vec::new();
    let mut current_group: Option<CliSourceGroup> = None;
    let mut current_socket: Option<CliSocket> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--source" || arg.starts_with("--source=") {
            push_socket(current_socket.take(), &mut current_group);
            finalize_group(current_group.take(), &mut groups);

            let value = if arg == "--source" {
                iter.next().map(|s| s.as_str())
            } else {
                arg.strip_prefix("--source=")
            };

            if let Some(value) = value {
                let (name, members) = parse_source_arg(value);
                current_group = Some(CliSourceGroup {
                    name,
                    members,
                    sockets: Vec::new(),
                });
            }
        } else if arg == "--socket" || arg.starts_with("--socket=") {
            push_socket(current_socket.take(), &mut current_group);

            let path = if arg == "--socket" {
                iter.next().map(|s| s.as_str())
            } else {
                arg.strip_prefix("--socket=")
            };

            if let Some(path) = path {
                // If no source group yet, create implicit from $SSH_AUTH_SOCK
                if current_group.is_none()
                    && let Ok(ssh_auth_sock) = std::env::var("SSH_AUTH_SOCK")
                {
                    current_group = Some(CliSourceGroup {
                        name: "default".to_string(),
                        members: vec![ssh_auth_sock],
                        sockets: Vec::new(),
                    });
                }

                current_socket = Some(CliSocket {
                    path: path.to_string(),
                    filters: Vec::new(),
                });
            }
        } else if let Some(ref mut sock) = current_socket {
            // Skip known global options
            if arg.starts_with("--config")
                || arg.starts_with("--verbose")
                || arg.starts_with("--quiet")
                || arg.starts_with("--print-config")
                || arg.starts_with("--foreground")
                || arg == "-v"
                || arg == "-V"
                || arg == "--help"
                || arg == "--version"
            {
                if arg == "--config" {
                    iter.next(); // skip value
                }
                continue;
            }

            // Filter arguments (don't start with --)
            if !arg.starts_with("--") {
                sock.filters.push(arg.clone());
            }
        }
    }

    push_socket(current_socket, &mut current_group);
    finalize_group(current_group, &mut groups);

    groups
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_arg_named() {
        let (name, members) = parse_source_arg("work=op://,file:~/.ssh/id_work");
        assert_eq!(name, "work");
        assert_eq!(members, vec!["op://", "file:~/.ssh/id_work"]);
    }

    #[test]
    fn test_parse_source_arg_unnamed() {
        let (name, members) = parse_source_arg("op://emerada,~/.ssh/agent.sock");
        assert_eq!(name, "default");
        assert_eq!(members, vec!["op://emerada", "~/.ssh/agent.sock"]);
    }

    #[test]
    fn test_parse_source_arg_single() {
        let (name, members) = parse_source_arg("op://");
        assert_eq!(name, "default");
        assert_eq!(members, vec!["op://"]);
    }

    #[test]
    fn test_parse_groups_basic() {
        let args: Vec<String> = vec![
            "authsock-warden",
            "run",
            "--source",
            "op://,/tmp/agent.sock",
            "--socket",
            "/tmp/work.sock",
            "comment=*@work*",
            "--socket",
            "/tmp/all.sock",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let groups = parse_groups_from_raw(&args);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "default");
        assert_eq!(groups[0].members, vec!["op://", "/tmp/agent.sock"]);
        assert_eq!(groups[0].sockets.len(), 2);
        assert_eq!(groups[0].sockets[0].path, "/tmp/work.sock");
        assert_eq!(groups[0].sockets[0].filters, vec!["comment=*@work*"]);
        assert_eq!(groups[0].sockets[1].path, "/tmp/all.sock");
        assert!(groups[0].sockets[1].filters.is_empty());
    }

    #[test]
    fn test_parse_groups_named() {
        let args: Vec<String> = vec![
            "authsock-warden",
            "run",
            "--source",
            "work=op://emerada",
            "--socket",
            "/tmp/work.sock",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let groups = parse_groups_from_raw(&args);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "work");
        assert_eq!(groups[0].members, vec!["op://emerada"]);
    }

    #[test]
    fn test_parse_groups_multiple() {
        let args: Vec<String> = vec![
            "authsock-warden",
            "run",
            "--source",
            "work=op://emerada",
            "--socket",
            "/tmp/work.sock",
            "--source",
            "personal=file:~/.ssh/id_ed25519",
            "--socket",
            "/tmp/personal.sock",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let groups = parse_groups_from_raw(&args);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "work");
        assert_eq!(groups[1].name, "personal");
    }

    #[test]
    fn test_parse_groups_empty() {
        let args: Vec<String> = vec!["authsock-warden", "run"]
            .into_iter()
            .map(String::from)
            .collect();

        let groups = parse_groups_from_raw(&args);
        assert!(groups.is_empty());
    }
}
