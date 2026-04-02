//! Run command implementation
//!
//! Starts the authsock-warden proxy in the foreground.

use crate::agent::{OpSourceConfig, Proxy, Server, Upstream, WardProxy};
use crate::cli::args::RunArgs;
use crate::config::{self, Config, SourceConfig, SourceMember};
use crate::filter::FilterEvaluator;
use crate::utils::path::expand_path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info};

pub async fn execute(args: RunArgs, config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // Load config from file, then overlay CLI args
    let mut config = load_config(config_path.as_deref())?;
    apply_cli_args(&mut config, &args);

    if args.print_config {
        let toml_str = toml::to_string_pretty(&config)?;
        println!("{}", toml_str);
        return Ok(());
    }

    if config.sockets.is_empty() {
        anyhow::bail!(
            "No sockets defined.\n\n\
             Quick start:\n  \
               authsock-warden run --socket /tmp/authsock-warden.sock\n  \
               authsock-warden run --source op:// --socket /tmp/authsock-warden.sock\n\n\
             Or create a config file:\n  \
               authsock-warden config edit\n\n\
             See 'authsock-warden run --help' for more options."
        );
    }

    // Set up shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build and run proxies for each socket
    let mut tasks = Vec::new();

    for (socket_name, socket_config) in &config.sockets {
        let socket_path = expand_path(&socket_config.path)?;

        // Collect op sources from the source group
        let op_sources = collect_op_sources(socket_config, &config);

        // Build filter evaluator
        let filter = build_filter_evaluator(&socket_config.filters)?;

        // Bind server
        let mut server = Server::new(&socket_path);
        server.bind().await?;

        // Spawn server task
        let rx = shutdown_rx.clone();
        let name = socket_name.clone();

        if op_sources.is_empty() {
            // No op sources — use classic Proxy (agent-only)
            let upstream = resolve_upstream(socket_config, &config)?;

            info!(
                socket = %socket_name,
                path = %socket_path,
                upstream = %upstream.socket_path().display(),
                filters = ?filter.descriptions(),
                "Starting proxy"
            );

            let proxy =
                Arc::new(Proxy::new(upstream, filter).with_socket_path(socket_path.clone()));

            let task = tokio::spawn(async move {
                let proxy = proxy;
                if let Err(e) = server
                    .run(
                        move |stream| {
                            let proxy = Arc::clone(&proxy);
                            async move { proxy.handle_client(stream).await }
                        },
                        rx,
                    )
                    .await
                {
                    error!(socket = %name, error = %e, "Server error");
                }
            });
            tasks.push(task);
        } else {
            // Op sources present — use WardProxy (multi-backend)
            let upstream = resolve_upstream_optional(socket_config, &config)?;

            info!(
                socket = %socket_name,
                path = %socket_path,
                upstream = upstream.as_ref().map(|u| u.socket_path().display().to_string()).unwrap_or_else(|| "(none)".to_string()),
                op_sources = op_sources.len(),
                filters = ?filter.descriptions(),
                "Starting WardProxy"
            );

            let proxy = Arc::new(
                WardProxy::new(upstream, filter, op_sources).with_socket_path(socket_path.clone()),
            );

            let task = tokio::spawn(async move {
                let proxy = proxy;
                if let Err(e) = server
                    .run(
                        move |stream| {
                            let proxy = Arc::clone(&proxy);
                            async move { proxy.handle_client(stream).await }
                        },
                        rx,
                    )
                    .await
                {
                    error!(socket = %name, error = %e, "Server error");
                }
            });
            tasks.push(task);
        }
    }

    info!(
        sockets = config.sockets.len(),
        "authsock-warden running. Press Ctrl+C to stop."
    );

    // Wait for shutdown signal
    wait_for_shutdown().await;
    info!("Shutting down...");

    // Send shutdown signal
    let _ = shutdown_tx.send(true);

    // Wait for all tasks to complete
    for task in tasks {
        let _ = task.await;
    }

    info!("Shutdown complete.");
    Ok(())
}

fn load_config(config_path: Option<&std::path::Path>) -> anyhow::Result<Config> {
    if let Some(path) = config_path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    } else if let Some(path) = config::find_config_file() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&content)?;
        info!(path = %path.display(), "Loaded configuration");
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

fn resolve_upstream(
    socket_config: &crate::config::SocketConfig,
    config: &Config,
) -> anyhow::Result<Upstream> {
    if let Some(ref source_name) = socket_config.source {
        // Source explicitly specified — only use agent members
        if let Some(source) = config.sources.iter().find(|s| s.name() == source_name)
            && let Ok(members) = source.parse_members()
        {
            for member in &members {
                let resolved = member.resolve().unwrap_or_else(|_| member.clone());
                if let SourceMember::Agent { socket } = &resolved {
                    let expanded = expand_path(socket)?;
                    return Ok(Upstream::new(expanded));
                }
            }
        }
        anyhow::bail!(
            "Source '{}' has no agent member. Add an agent member or use WardProxy for op-only sources.",
            source_name
        );
    }

    // No source specified — fallback to $SSH_AUTH_SOCK
    Ok(Upstream::from_env()?)
}

/// Resolve upstream as optional (returns None if no agent member found and no SSH_AUTH_SOCK).
///
/// Used by WardProxy which can operate without an upstream agent
/// (e.g., when only op:// sources are configured).
fn resolve_upstream_optional(
    socket_config: &crate::config::SocketConfig,
    config: &Config,
) -> anyhow::Result<Option<Upstream>> {
    if let Some(ref source_name) = socket_config.source {
        // Source is explicitly specified — only use agent members from it
        if let Some(source) = config.sources.iter().find(|s| s.name() == source_name)
            && let Ok(members) = source.parse_members()
        {
            for member in &members {
                let resolved = member.resolve().unwrap_or_else(|_| member.clone());
                if let SourceMember::Agent { socket } = &resolved {
                    let expanded = expand_path(socket)?;
                    return Ok(Some(Upstream::new(expanded)));
                }
            }
        }
        // Source specified but no agent member — no upstream (op-only is valid)
        return Ok(None);
    }

    // No source specified — fallback to $SSH_AUTH_SOCK
    match Upstream::from_env() {
        Ok(upstream) => Ok(Some(upstream)),
        Err(_) => Ok(None),
    }
}

/// Collect op:// source configurations from the socket's source group.
fn collect_op_sources(
    socket_config: &crate::config::SocketConfig,
    config: &Config,
) -> Vec<OpSourceConfig> {
    let Some(ref source_name) = socket_config.source else {
        return vec![];
    };

    let Some(source) = config.sources.iter().find(|s| s.name() == source_name) else {
        return vec![];
    };

    let Ok(members) = source.parse_members() else {
        return vec![];
    };

    members
        .into_iter()
        .filter_map(|member| {
            if let SourceMember::Op { vault, item } = member {
                Some(OpSourceConfig { vault, item })
            } else {
                None
            }
        })
        .collect()
}

/// Apply CLI arguments on top of config (CLI takes precedence)
fn apply_cli_args(config: &mut Config, args: &RunArgs) {
    use crate::cli::args::CliSourceGroup;

    let groups = args.parse_groups();
    if groups.is_empty() {
        return;
    }

    for group in groups {
        let CliSourceGroup {
            name,
            members,
            sockets,
        } = group;

        // Add source group
        let existing = config.sources.iter().position(|s| s.name() == name);
        let source = SourceConfig {
            name: name.clone(),
            members,
        };
        if let Some(idx) = existing {
            config.sources[idx] = source;
        } else {
            config.sources.push(source);
        }

        // Add sockets referencing this source group
        for (i, cli_socket) in sockets.into_iter().enumerate() {
            let socket_name = if i == 0 && name == "default" {
                "default".to_string()
            } else {
                format!("{}-{}", name, i)
            };

            let filter_groups: Vec<Vec<String>> =
                cli_socket.filters.into_iter().map(|f| vec![f]).collect();

            let socket_config = crate::config::SocketConfig {
                path: cli_socket.path,
                source: Some(name.clone()),
                filters: filter_groups,
                timeout: None,
                allowed_processes: vec![],
            };

            config.sockets.insert(socket_name, socket_config);
        }
    }
}

fn build_filter_evaluator(filters: &[Vec<String>]) -> anyhow::Result<FilterEvaluator> {
    if filters.is_empty() {
        Ok(FilterEvaluator::default())
    } else {
        FilterEvaluator::parse(filters).map_err(|e| anyhow::anyhow!("Filter error: {}", e))
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => { info!("Received SIGINT"); }
            _ = sigterm.recv() => { info!("Received SIGTERM"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        info!("Received SIGINT");
    }
}
