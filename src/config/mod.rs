//! Configuration module for authsock-warden
//!
//! This module handles loading and parsing of configuration files,
//! including environment variable expansion and path resolution.

mod file;

use crate::utils::path::expand_path;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub use file::{ConfigFile, ConfigPath, config_search_paths, find_config_file, load_config};

/// Main configuration structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Policy settings (idle check, etc.)
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Authentication settings
    #[serde(default)]
    pub auth: AuthConfig,

    /// 1Password account (URL or UUID) for op CLI
    /// Required when multiple accounts are configured.
    /// Sets OP_ACCOUNT environment variable for all op CLI calls.
    pub op_account: Option<String>,

    /// Key source group definitions
    #[serde(default)]
    pub sources: Vec<SourceConfig>,

    /// Socket definitions
    #[serde(default)]
    pub sockets: HashMap<String, SocketConfig>,

    /// Per-key policy definitions
    #[serde(default)]
    pub keys: Vec<KeyConfig>,

    /// GitHub API settings
    #[serde(default)]
    pub github: GithubConfig,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Interval for idle checks (e.g., "30s", "5m")
    pub idle_check_interval: Option<String>,

    /// Command to run for idle checks
    pub idle_check_command: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication method (currently only "command")
    #[serde(default = "default_auth_method")]
    pub method: String,

    /// Command to run for authentication
    pub command: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: default_auth_method(),
            command: None,
        }
    }
}

/// Source group configuration (DR-010)
///
/// A source group bundles multiple key sources (agents, files, op CLI)
/// under a single name. Members are specified as URI-like strings:
///   - `op://` — all 1Password SSH keys
///   - `op://VAULT` — SSH keys from a specific vault
///   - `op://VAULT/ITEM` — a specific key
///   - `agent:PATH` — SSH agent socket (proxy mode)
///   - `file:PATH` — private key file
///   - `PATH` (no prefix) — auto-detect based on file type at startup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// Name of this source group
    pub name: String,
    /// Member definitions (e.g., "op://", "agent:/path", "file:/path", "/path")
    pub members: Vec<String>,
}

impl SourceConfig {
    /// Get the name of this source group
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parse members into typed SourceMember variants
    pub fn parse_members(&self) -> crate::error::Result<Vec<SourceMember>> {
        self.members
            .iter()
            .map(|m| SourceMember::parse(m))
            .collect()
    }
}

/// Parsed source member type
#[derive(Debug, Clone)]
pub enum SourceMember {
    /// 1Password via op CLI (warden signs locally)
    Op {
        /// Optional vault filter
        vault: Option<String>,
        /// Optional item filter
        item: Option<String>,
    },
    /// SSH agent socket (proxy mode, upstream signs)
    Agent {
        /// Path to the agent socket
        socket: String,
    },
    /// Private key file (warden signs locally)
    File {
        /// Path to the private key file
        path: String,
    },
    /// Bare path — type not yet determined. Resolved at startup via `resolve()`.
    Unresolved {
        /// The raw path string
        path: String,
    },
}

impl SourceMember {
    /// Parse a member string into a typed SourceMember.
    ///
    /// Bare paths (no prefix) are stored as `Unresolved` and must be
    /// resolved at startup via `resolve()` which checks the file type.
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        // op:// scheme
        if let Some(rest) = s.strip_prefix("op://") {
            let (vault, item) = match rest.split_once('/') {
                Some((v, i)) if !v.is_empty() && !i.is_empty() => {
                    (Some(v.to_string()), Some(i.to_string()))
                }
                _ if !rest.is_empty() => (Some(rest.to_string()), None),
                _ => (None, None),
            };
            return Ok(SourceMember::Op { vault, item });
        }
        // Explicit agent: prefix
        if let Some(path) = s.strip_prefix("agent:") {
            return Ok(SourceMember::Agent {
                socket: path.to_string(),
            });
        }
        // Explicit file: prefix
        if let Some(path) = s.strip_prefix("file:") {
            return Ok(SourceMember::File {
                path: path.to_string(),
            });
        }
        // No prefix: defer type detection to runtime
        Ok(SourceMember::Unresolved {
            path: s.to_string(),
        })
    }

    /// Resolve an `Unresolved` member by checking the file type at the given path.
    ///
    /// - Unix socket → `Agent`
    /// - Regular file → `File`
    /// - Path not found or other → error (fail-closed per DR-010)
    ///
    /// Already-resolved members are returned as-is.
    pub fn resolve(&self) -> crate::error::Result<Self> {
        let SourceMember::Unresolved { path } = self else {
            return Ok(self.clone());
        };

        let expanded = crate::utils::path::expand_path(path)?;
        let metadata = std::fs::metadata(&expanded).map_err(|e| {
            crate::error::Error::Config(format!(
                "Cannot access source member '{}': {}. Use agent: or file: prefix to specify type explicitly.",
                path, e
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_socket() {
                tracing::info!(path = %expanded, "Auto-detected source member as agent socket");
                return Ok(SourceMember::Agent {
                    socket: path.clone(),
                });
            }
        }

        if metadata.is_file() {
            tracing::info!(path = %expanded, "Auto-detected source member as key file");
            return Ok(SourceMember::File { path: path.clone() });
        }

        Err(crate::error::Error::Config(format!(
            "'{}' is neither a socket nor a regular file. Use agent: or file: prefix.",
            path
        )))
    }

    /// Check if this member is unresolved
    pub fn is_unresolved(&self) -> bool {
        matches!(self, SourceMember::Unresolved { .. })
    }

    /// Description for logging
    pub fn description(&self) -> String {
        match self {
            SourceMember::Op { vault, item } => {
                let mut desc = "op://".to_string();
                if let Some(v) = vault {
                    desc.push_str(v);
                    if let Some(i) = item {
                        desc.push('/');
                        desc.push_str(i);
                    }
                }
                desc
            }
            SourceMember::Agent { socket } => format!("agent:{}", socket),
            SourceMember::File { path } => format!("file:{}", path),
            SourceMember::Unresolved { path } => format!("unresolved:{}", path),
        }
    }
}

/// Configuration for a single socket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketConfig {
    /// Path to the socket file
    /// Supports environment variable and tilde expansion
    pub path: String,

    /// Single source group reference (DR-010)
    pub source: Option<String>,

    /// Filter rules for this socket
    /// Mixed format: strings are single OR terms, arrays are AND groups
    /// e.g., ["f1", "f2", ["f3", "f4"]] means f1 || f2 || (f3 && f4)
    #[serde(
        default,
        deserialize_with = "deserialize_filters",
        serialize_with = "serialize_filters"
    )]
    pub filters: Vec<Vec<String>>,

    /// Timeout for keys accessed through this socket (e.g., "1h")
    pub timeout: Option<String>,

    /// List of allowed process names
    #[serde(default)]
    pub allowed_processes: Vec<String>,
}

/// Per-key policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Public key in SSH authorized_keys format
    pub public_key: String,

    /// Timeout before the key is locked or forgotten (e.g., "4h")
    pub timeout: Option<String>,

    /// Action on timeout: "lock" or "forget"
    #[serde(default = "default_on_timeout")]
    pub on_timeout: String,

    /// Duration after which a locked key is forgotten (e.g., "24h")
    pub forget_after: Option<String>,

    /// List of allowed process names
    #[serde(default)]
    pub allowed_processes: Vec<String>,
}

/// GitHub API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// Cache TTL for GitHub API responses
    /// Format: "1h", "30m", "1d", etc.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: String,

    /// Timeout for GitHub API requests
    /// Format: "10s", "30s", etc.
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

// --- Default value functions ---

fn default_auth_method() -> String {
    "command".to_string()
}

fn default_on_timeout() -> String {
    "lock".to_string()
}

fn default_cache_ttl() -> String {
    "1h".to_string()
}

fn default_timeout() -> String {
    "10s".to_string()
}

// --- Default trait implementations ---

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            cache_ttl: default_cache_ttl(),
            timeout: default_timeout(),
        }
    }
}

// --- Custom filter serialization/deserialization ---

/// Custom deserializer for filters:
/// - `"f1"` -> single filter (OR term)
/// - `["f1", "f2"]` -> AND group
/// - `["f1", ["f2", "f3"]]` -> f1 || (f2 && f3)
fn deserialize_filters<'de, D>(deserializer: D) -> Result<Vec<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct FiltersVisitor;

    impl<'de> Visitor<'de> for FiltersVisitor {
        type Value = Vec<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of strings or arrays of strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();

            while let Some(value) = seq.next_element::<toml::Value>()? {
                match value {
                    toml::Value::String(s) => {
                        // Single string -> single-element AND group (OR term)
                        result.push(vec![s]);
                    }
                    toml::Value::Array(arr) => {
                        // Array -> AND group
                        let group: Vec<String> = arr
                            .into_iter()
                            .map(|v| {
                                v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                                    de::Error::custom("expected string in filter group")
                                })
                            })
                            .collect::<Result<_, _>>()?;
                        result.push(group);
                    }
                    _ => {
                        return Err(de::Error::custom("expected string or array of strings"));
                    }
                }
            }

            Ok(result)
        }
    }

    deserializer.deserialize_seq(FiltersVisitor)
}

/// Custom serializer for filters:
/// - Single-element group -> string (e.g., `["f1"]` -> `"f1"`)
/// - Multi-element group -> array (e.g., `["f1", "f2"]` -> `["f1", "f2"]`)
fn serialize_filters<S>(filters: &Vec<Vec<String>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(filters.len()))?;
    for group in filters {
        if group.len() == 1 {
            // Single filter -> serialize as string
            seq.serialize_element(&group[0])?;
        } else {
            // Multiple filters -> serialize as array
            seq.serialize_element(group)?;
        }
    }
    seq.end()
}

// --- Expanded configuration types ---

/// Configuration with all paths expanded and durations parsed
#[derive(Debug, Clone)]
pub struct ExpandedConfig {
    /// Policy settings with parsed durations
    pub policy: ExpandedPolicyConfig,

    /// Authentication settings
    pub auth: AuthConfig,

    /// Key source group definitions with parsed members
    pub sources: Vec<ExpandedSourceGroup>,

    /// Socket definitions with expanded paths
    pub sockets: HashMap<String, ExpandedSocketConfig>,

    /// Per-key policies with parsed durations
    pub keys: Vec<ExpandedKeyConfig>,

    /// GitHub API settings with parsed durations
    pub github: ExpandedGithubConfig,
}

/// Policy configuration with parsed durations
#[derive(Debug, Clone)]
pub struct ExpandedPolicyConfig {
    /// Parsed idle check interval
    pub idle_check_interval: Option<std::time::Duration>,

    /// Command to run for idle checks
    pub idle_check_command: Option<String>,
}

/// Expanded source group with parsed members
#[derive(Debug, Clone)]
pub struct ExpandedSourceGroup {
    /// Name of this source group
    pub name: String,
    /// Parsed member definitions
    pub members: Vec<SourceMember>,
}

/// Socket configuration with expanded paths and parsed durations
#[derive(Debug, Clone)]
pub struct ExpandedSocketConfig {
    /// Resolved socket path
    pub path: PathBuf,

    /// Single source group reference
    pub source: Option<String>,

    /// Filter rules for this socket (outer: OR, inner: AND)
    pub filters: Vec<Vec<String>>,

    /// Parsed timeout duration
    pub timeout: Option<std::time::Duration>,

    /// List of allowed process names
    pub allowed_processes: Vec<String>,
}

/// Per-key policy with parsed durations
#[derive(Debug, Clone)]
pub struct ExpandedKeyConfig {
    /// Public key in SSH authorized_keys format
    pub public_key: String,

    /// Parsed timeout duration
    pub timeout: Option<std::time::Duration>,

    /// Action on timeout: "lock" or "forget"
    pub on_timeout: String,

    /// Parsed forget_after duration
    pub forget_after: Option<std::time::Duration>,

    /// List of allowed process names
    pub allowed_processes: Vec<String>,
}

/// GitHub configuration with parsed durations
#[derive(Debug, Clone)]
pub struct ExpandedGithubConfig {
    /// Cache TTL as Duration
    pub cache_ttl: std::time::Duration,

    /// Timeout as Duration
    pub timeout: std::time::Duration,
}

impl Config {
    /// Expand environment variables and tilde in all paths, parse durations
    pub fn expand_paths(&self) -> crate::error::Result<ExpandedConfig> {
        // Expand policy
        let policy = ExpandedPolicyConfig {
            idle_check_interval: self
                .policy
                .idle_check_interval
                .as_ref()
                .map(|s| parse_duration(s))
                .transpose()?,
            idle_check_command: self.policy.idle_check_command.clone(),
        };

        // Expand sources: parse members
        let mut sources = Vec::new();
        for source in &self.sources {
            let members = source.parse_members()?;
            sources.push(ExpandedSourceGroup {
                name: source.name.clone(),
                members,
            });
        }

        // Expand sockets
        let mut sockets = HashMap::new();
        for (name, socket) in &self.sockets {
            sockets.insert(
                name.clone(),
                ExpandedSocketConfig {
                    path: PathBuf::from(expand_path(&socket.path)?),
                    source: socket.source.clone(),
                    filters: socket.filters.clone(),
                    timeout: socket
                        .timeout
                        .as_ref()
                        .map(|s| parse_duration(s))
                        .transpose()?,
                    allowed_processes: socket.allowed_processes.clone(),
                },
            );
        }

        // Expand keys
        let mut keys = Vec::new();
        for key in &self.keys {
            keys.push(ExpandedKeyConfig {
                public_key: key.public_key.clone(),
                timeout: key
                    .timeout
                    .as_ref()
                    .map(|s| parse_duration(s))
                    .transpose()?,
                on_timeout: key.on_timeout.clone(),
                forget_after: key
                    .forget_after
                    .as_ref()
                    .map(|s| parse_duration(s))
                    .transpose()?,
                allowed_processes: key.allowed_processes.clone(),
            });
        }

        Ok(ExpandedConfig {
            policy,
            auth: self.auth.clone(),
            sources,
            sockets,
            keys,
            github: ExpandedGithubConfig {
                cache_ttl: parse_duration(&self.github.cache_ttl)?,
                timeout: parse_duration(&self.github.timeout)?,
            },
        })
    }
}

/// Parse a duration string like "1h", "30m", "10s", "1d"
pub fn parse_duration(s: &str) -> crate::error::Result<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(crate::error::Error::Config(
            "Empty duration string".to_string(),
        ));
    }

    // Find the position where the numeric part ends
    let (num_str, unit) = s
        .char_indices()
        .find(|(_, c)| c.is_alphabetic())
        .map(|(i, _)| (&s[..i], &s[i..]))
        .unwrap_or((s, "s")); // Default to seconds if no unit

    let num: u64 = num_str.trim().parse().map_err(|e| {
        crate::error::Error::Config(format!("Invalid duration number '{}': {}", num_str, e))
    })?;

    let seconds = match unit.to_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => num,
        "m" | "min" | "mins" | "minute" | "minutes" => num * 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => num * 60 * 60,
        "d" | "day" | "days" => num * 60 * 60 * 24,
        "w" | "week" | "weeks" => num * 60 * 60 * 24 * 7,
        "" => num, // Assume seconds if no unit
        _ => {
            return Err(crate::error::Error::Config(format!(
                "Unknown duration unit '{}' in '{}'",
                unit, s
            )));
        }
    };

    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let toml_str = "";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.sources.is_empty());
        assert!(config.sockets.is_empty());
        assert!(config.keys.is_empty());
        assert_eq!(config.auth.method, "command");
        assert_eq!(config.github.cache_ttl, "1h");
        assert_eq!(config.github.timeout, "10s");
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.sources.is_empty());
        assert!(config.sockets.is_empty());
        assert!(config.keys.is_empty());
        assert_eq!(config.auth.method, "command");
        assert!(config.auth.command.is_none());
        assert!(config.policy.idle_check_interval.is_none());
        assert!(config.policy.idle_check_command.is_none());
        assert_eq!(config.github.cache_ttl, "1h");
        assert_eq!(config.github.timeout, "10s");
    }

    // --- SourceMember::parse tests ---

    #[test]
    fn test_source_member_parse_op_all() {
        let member = SourceMember::parse("op://").unwrap();
        match member {
            SourceMember::Op { vault, item } => {
                assert!(vault.is_none());
                assert!(item.is_none());
            }
            _ => panic!("Expected Op variant"),
        }
    }

    #[test]
    fn test_source_member_parse_op_vault() {
        let member = SourceMember::parse("op://emerada").unwrap();
        match member {
            SourceMember::Op { vault, item } => {
                assert_eq!(vault.as_deref(), Some("emerada"));
                assert!(item.is_none());
            }
            _ => panic!("Expected Op variant"),
        }
    }

    #[test]
    fn test_source_member_parse_op_vault_item() {
        let member = SourceMember::parse("op://Private/kawaz-mbp-key").unwrap();
        match member {
            SourceMember::Op { vault, item } => {
                assert_eq!(vault.as_deref(), Some("Private"));
                assert_eq!(item.as_deref(), Some("kawaz-mbp-key"));
            }
            _ => panic!("Expected Op variant"),
        }
    }

    #[test]
    fn test_source_member_parse_agent_explicit() {
        let member = SourceMember::parse("agent:~/.ssh/agent.sock").unwrap();
        match member {
            SourceMember::Agent { socket } => {
                assert_eq!(socket, "~/.ssh/agent.sock");
            }
            _ => panic!("Expected Agent variant"),
        }
    }

    #[test]
    fn test_source_member_parse_file_explicit() {
        let member = SourceMember::parse("file:~/.ssh/id_work").unwrap();
        match member {
            SourceMember::File { path } => {
                assert_eq!(path, "~/.ssh/id_work");
            }
            _ => panic!("Expected File variant"),
        }
    }

    #[test]
    fn test_source_member_parse_bare_path() {
        // Bare path is Unresolved (auto-detection deferred to runtime)
        let member = SourceMember::parse("/tmp/agent.sock").unwrap();
        assert!(member.is_unresolved());
        match &member {
            SourceMember::Unresolved { path } => {
                assert_eq!(path, "/tmp/agent.sock");
            }
            _ => panic!("Expected Unresolved variant for bare path"),
        }
    }

    #[test]
    fn test_source_member_description() {
        assert_eq!(
            SourceMember::Op {
                vault: None,
                item: None
            }
            .description(),
            "op://"
        );
        assert_eq!(
            SourceMember::Op {
                vault: Some("emerada".to_string()),
                item: None
            }
            .description(),
            "op://emerada"
        );
        assert_eq!(
            SourceMember::Op {
                vault: Some("Private".to_string()),
                item: Some("key".to_string())
            }
            .description(),
            "op://Private/key"
        );
        assert_eq!(
            SourceMember::Agent {
                socket: "/tmp/a.sock".to_string()
            }
            .description(),
            "agent:/tmp/a.sock"
        );
        assert_eq!(
            SourceMember::File {
                path: "~/.ssh/id".to_string()
            }
            .description(),
            "file:~/.ssh/id"
        );
    }

    // --- SourceConfig TOML parse tests ---

    #[test]
    fn test_parse_source_group() {
        let toml_str = r#"
[[sources]]
name = "work"
members = ["op://emerada", "agent:~/Library/agent.sock", "file:~/.ssh/id_work"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.sources[0].name(), "work");
        assert_eq!(config.sources[0].members.len(), 3);
        assert_eq!(config.sources[0].members[0], "op://emerada");
        assert_eq!(config.sources[0].members[1], "agent:~/Library/agent.sock");
        assert_eq!(config.sources[0].members[2], "file:~/.ssh/id_work");
    }

    #[test]
    fn test_parse_source_group_parse_members() {
        let toml_str = r#"
[[sources]]
name = "work"
members = ["op://", "agent:/tmp/agent.sock", "file:~/.ssh/id_work", "/tmp/bare.sock"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let members = config.sources[0].parse_members().unwrap();
        assert_eq!(members.len(), 4);
        assert!(matches!(
            &members[0],
            SourceMember::Op {
                vault: None,
                item: None
            }
        ));
        assert!(
            matches!(&members[1], SourceMember::Agent { socket } if socket == "/tmp/agent.sock")
        );
        assert!(matches!(&members[2], SourceMember::File { path } if path == "~/.ssh/id_work"));
        assert!(
            matches!(&members[3], SourceMember::Unresolved { path } if path == "/tmp/bare.sock")
        );
    }

    #[test]
    fn test_parse_multiple_source_groups() {
        let toml_str = r#"
[[sources]]
name = "work"
members = ["op://emerada"]

[[sources]]
name = "personal"
members = ["file:~/.ssh/id_personal"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.sources.len(), 2);
        assert_eq!(config.sources[0].name(), "work");
        assert_eq!(config.sources[1].name(), "personal");
    }

    // --- SocketConfig tests ---

    #[test]
    fn test_parse_socket_with_source() {
        let toml_str = r#"
[sockets.work]
path = "$XDG_RUNTIME_DIR/authsock-warden/work.sock"
source = "work"
filters = ["comment=~@work"]
timeout = "1h"
allowed_processes = ["git"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let work = config.sockets.get("work").unwrap();
        assert_eq!(work.path, "$XDG_RUNTIME_DIR/authsock-warden/work.sock");
        assert_eq!(work.source.as_deref(), Some("work"));
        assert_eq!(work.filters, vec![vec!["comment=~@work".to_string()]]);
        assert_eq!(work.timeout.as_deref(), Some("1h"));
        assert_eq!(work.allowed_processes, vec!["git"]);
    }

    #[test]
    fn test_parse_socket_without_source() {
        let toml_str = r#"
[sockets.all]
path = "/tmp/all.sock"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let all = config.sockets.get("all").unwrap();
        assert_eq!(all.path, "/tmp/all.sock");
        assert!(all.source.is_none());
        assert!(all.filters.is_empty());
        assert!(all.timeout.is_none());
        assert!(all.allowed_processes.is_empty());
    }

    #[test]
    fn test_parse_sockets_with_mixed_filters() {
        let toml_str = r#"
[sockets.test]
path = "/tmp/test.sock"
filters = ["f1", "f2", ["f3", "f4"]]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let socket = config.sockets.get("test").unwrap();
        assert_eq!(
            socket.filters,
            vec![
                vec!["f1".to_string()],
                vec!["f2".to_string()],
                vec!["f3".to_string(), "f4".to_string()],
            ]
        );
    }

    #[test]
    fn test_parse_keys() {
        let toml_str = r#"
[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
on_timeout = "lock"
forget_after = "24h"
allowed_processes = ["ssh", "git", "jj"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.keys.len(), 1);

        let key = &config.keys[0];
        assert_eq!(key.public_key, "ssh-ed25519 AAAA...");
        assert_eq!(key.timeout.as_deref(), Some("4h"));
        assert_eq!(key.on_timeout, "lock");
        assert_eq!(key.forget_after.as_deref(), Some("24h"));
        assert_eq!(key.allowed_processes, vec!["ssh", "git", "jj"]);
    }

    #[test]
    fn test_parse_keys_defaults() {
        let toml_str = r#"
[[keys]]
public_key = "ssh-ed25519 AAAA..."
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let key = &config.keys[0];
        assert_eq!(key.on_timeout, "lock"); // default
        assert!(key.timeout.is_none());
        assert!(key.forget_after.is_none());
        assert!(key.allowed_processes.is_empty());
    }

    #[test]
    fn test_parse_policy_and_auth() {
        let toml_str = r#"
[policy]
idle_check_interval = "30s"
idle_check_command = "/path/to/cmux-check.sh"

[auth]
method = "command"
command = "/path/to/notify-and-verify.sh"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy.idle_check_interval.as_deref(), Some("30s"));
        assert_eq!(
            config.policy.idle_check_command.as_deref(),
            Some("/path/to/cmux-check.sh")
        );
        assert_eq!(config.auth.method, "command");
        assert_eq!(
            config.auth.command.as_deref(),
            Some("/path/to/notify-and-verify.sh")
        );
    }

    #[test]
    fn test_parse_github() {
        let toml_str = r#"
[github]
cache_ttl = "2h"
timeout = "30s"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.github.cache_ttl, "2h");
        assert_eq!(config.github.timeout, "30s");
    }

    #[test]
    fn test_parse_op_account() {
        let toml_str = r#"
op_account = "kawaz.1password.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.op_account.as_deref(), Some("kawaz.1password.com"));
    }

    #[test]
    fn test_parse_op_account_none() {
        let toml_str = "";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.op_account.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
op_account = "kawaz.1password.com"

[policy]
idle_check_interval = "30s"
idle_check_command = "/path/to/cmux-check.sh"

[auth]
method = "command"
command = "/path/to/notify-and-verify.sh"

[[sources]]
name = "work"
members = ["op://emerada", "agent:~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock", "file:~/.ssh/id_work"]

[[sources]]
name = "personal"
members = ["file:~/.ssh/id_personal"]

[sockets.work]
path = "$XDG_RUNTIME_DIR/authsock-warden/work.sock"
source = "work"
filters = ["comment=~@work"]
timeout = "1h"
allowed_processes = ["git"]

[sockets.all]
path = "$XDG_RUNTIME_DIR/authsock-warden/all.sock"
source = "personal"

[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
on_timeout = "lock"
forget_after = "24h"
allowed_processes = ["ssh", "git", "jj"]

[github]
cache_ttl = "1h"
timeout = "10s"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.op_account.as_deref(), Some("kawaz.1password.com"));
        assert_eq!(config.sources.len(), 2);
        assert_eq!(config.sockets.len(), 2);
        assert_eq!(config.keys.len(), 1);
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(
            parse_duration("10s").unwrap(),
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            parse_duration("30sec").unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("5").unwrap(),
            std::time::Duration::from_secs(5)
        );
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(
            parse_duration("5m").unwrap(),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            parse_duration("2min").unwrap(),
            std::time::Duration::from_secs(120)
        );
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(
            parse_duration("1h").unwrap(),
            std::time::Duration::from_secs(3600)
        );
        assert_eq!(
            parse_duration("2hours").unwrap(),
            std::time::Duration::from_secs(7200)
        );
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(
            parse_duration("1d").unwrap(),
            std::time::Duration::from_secs(86400)
        );
        assert_eq!(
            parse_duration("7days").unwrap(),
            std::time::Duration::from_secs(604800)
        );
    }

    #[test]
    fn test_parse_duration_weeks() {
        assert_eq!(
            parse_duration("1w").unwrap(),
            std::time::Duration::from_secs(604800)
        );
        assert_eq!(
            parse_duration("2weeks").unwrap(),
            std::time::Duration::from_secs(1209600)
        );
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn test_filters_serialize_deserialize_roundtrip() {
        let toml_str = r#"
path = "/tmp/test.sock"
filters = ["f1", "f2", ["f3", "f4"]]
"#;
        // Deserialize
        let config: SocketConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.filters,
            vec![
                vec!["f1".to_string()],
                vec!["f2".to_string()],
                vec!["f3".to_string(), "f4".to_string()],
            ]
        );

        // Serialize back
        let serialized = toml::to_string(&config).unwrap();

        // Deserialize again
        let config2: SocketConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.filters, config2.filters);
    }

    #[test]
    fn test_filters_empty_serialization() {
        let config = SocketConfig {
            path: "/tmp/test.sock".to_string(),
            source: None,
            filters: vec![],
            timeout: None,
            allowed_processes: vec![],
        };

        let serialized = toml::to_string(&config).unwrap();
        let config2: SocketConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.filters, config2.filters);
    }

    #[test]
    fn test_source_config_name() {
        let source = SourceConfig {
            name: "test-group".to_string(),
            members: vec!["op://".to_string()],
        };
        assert_eq!(source.name(), "test-group");
    }

    #[test]
    fn test_deny_unknown_fields() {
        let toml_str = r#"
unknown_field = "value"
"#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "Should reject unknown fields in Config");
    }

    #[test]
    fn test_deny_unknown_fields_in_policy() {
        let toml_str = r#"
[policy]
unknown = "value"
"#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(
            result.is_err(),
            "Should reject unknown fields in PolicyConfig"
        );
    }

    #[test]
    fn test_deny_unknown_fields_in_socket() {
        let toml_str = r#"
[sockets.test]
path = "/tmp/test.sock"
unknown = "value"
"#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(
            result.is_err(),
            "Should reject unknown fields in SocketConfig"
        );
    }

    #[test]
    fn test_deny_unknown_fields_in_key() {
        let toml_str = r#"
[[keys]]
public_key = "ssh-ed25519 AAAA..."
unknown = "value"
"#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "Should reject unknown fields in KeyConfig");
    }

    #[test]
    fn test_expand_paths_parses_durations() {
        let toml_str = r#"
[policy]
idle_check_interval = "30s"

[sockets.work]
path = "/tmp/work.sock"
timeout = "1h"

[[keys]]
public_key = "ssh-ed25519 AAAA..."
timeout = "4h"
forget_after = "24h"

[github]
cache_ttl = "2h"
timeout = "30s"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let expanded = config.expand_paths().unwrap();

        assert_eq!(
            expanded.policy.idle_check_interval,
            Some(std::time::Duration::from_secs(30))
        );

        let work = expanded.sockets.get("work").unwrap();
        assert_eq!(work.timeout, Some(std::time::Duration::from_secs(3600)));

        assert_eq!(
            expanded.keys[0].timeout,
            Some(std::time::Duration::from_secs(14400))
        );
        assert_eq!(
            expanded.keys[0].forget_after,
            Some(std::time::Duration::from_secs(86400))
        );

        assert_eq!(
            expanded.github.cache_ttl,
            std::time::Duration::from_secs(7200)
        );
        assert_eq!(expanded.github.timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_expand_paths_parses_source_members() {
        let toml_str = r#"
[[sources]]
name = "work"
members = ["op://emerada", "agent:/tmp/agent.sock", "file:~/.ssh/id_work"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let expanded = config.expand_paths().unwrap();

        assert_eq!(expanded.sources.len(), 1);
        assert_eq!(expanded.sources[0].name, "work");
        assert_eq!(expanded.sources[0].members.len(), 3);
        assert!(matches!(
            &expanded.sources[0].members[0],
            SourceMember::Op {
                vault: Some(v),
                item: None
            } if v == "emerada"
        ));
        assert!(matches!(
            &expanded.sources[0].members[1],
            SourceMember::Agent { socket } if socket == "/tmp/agent.sock"
        ));
        assert!(matches!(
            &expanded.sources[0].members[2],
            SourceMember::File { path } if path == "~/.ssh/id_work"
        ));
    }
}
