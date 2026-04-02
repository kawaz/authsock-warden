//! Run command implementation
//!
//! Starts the authsock-warden proxy in the foreground.

use crate::agent::{Proxy, Server, Upstream};
use crate::cli::args::RunArgs;
use crate::config::{self, Config, SourceConfig};
use crate::filter::FilterEvaluator;
use crate::utils::path::expand_path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};

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
            "No sockets defined. Use --socket PATH or add [sockets.NAME] to config file."
        );
    }

    // Set up shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build and run proxies for each socket
    let mut tasks = Vec::new();

    for (socket_name, socket_config) in &config.sockets {
        let socket_path = expand_path(&socket_config.path)?;

        // Resolve upstream for this socket
        let upstream = resolve_upstream(socket_config, &config)?;

        // Build filter evaluator
        let filter = build_filter_evaluator(&socket_config.filters)?;

        info!(
            socket = %socket_name,
            path = %socket_path,
            upstream = %upstream.socket_path().display(),
            filters = ?filter.descriptions(),
            "Starting proxy"
        );

        // Create proxy
        let proxy = Arc::new(Proxy::new(upstream, filter).with_socket_path(socket_path.clone()));

        // Bind server
        let mut server = Server::new(&socket_path);
        server.bind().await?;

        // Spawn server task
        let rx = shutdown_rx.clone();
        let name = socket_name.clone();
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
    // 1. Socket-level upstream override (backward compatibility)
    if let Some(ref upstream_path) = socket_config.upstream {
        let expanded = expand_path(upstream_path)?;
        return Ok(Upstream::new(expanded));
    }

    // 2. Find first agent source referenced by this socket
    if !socket_config.sources.is_empty() {
        for source_name in &socket_config.sources {
            if let Some(SourceConfig::Agent { socket, .. }) =
                config.sources.iter().find(|s| s.name() == source_name)
            {
                let expanded = expand_path(socket)?;
                return Ok(Upstream::new(expanded));
            }
        }
        warn!("No agent-type source found for socket. Using SSH_AUTH_SOCK fallback.");
    }

    // 3. Fallback to SSH_AUTH_SOCK
    Ok(Upstream::from_env()?)
}

/// Apply CLI arguments on top of config (CLI takes precedence)
fn apply_cli_args(config: &mut Config, args: &RunArgs) {
    // --upstream overrides the upstream for all sockets
    if let Some(ref upstream) = args.upstream {
        // Add or replace default agent source
        let upstream_str = upstream.display().to_string();
        let has_cli_source = config.sources.iter().any(|s| s.name() == "_cli");
        if !has_cli_source {
            config.sources.push(SourceConfig::Agent {
                name: "_cli".to_string(),
                socket: upstream_str,
            });
        }
    }

    // --socket adds sockets from CLI
    let cli_sockets = args.parse_sockets();
    for (i, (path, filters)) in cli_sockets.into_iter().enumerate() {
        let name = if i == 0 {
            "default".to_string()
        } else {
            format!("cli-{}", i)
        };

        let filter_groups: Vec<Vec<String>> = filters.into_iter().map(|f| vec![f]).collect();

        let mut socket_config = crate::config::SocketConfig {
            path,
            sources: vec![],
            filters: filter_groups,
            timeout: None,
            allowed_processes: vec![],
            upstream: None,
        };

        // If --upstream was given, point this socket to it
        if args.upstream.is_some() {
            socket_config.sources = vec!["_cli".to_string()];
        }

        config.sockets.insert(name, socket_config);
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
