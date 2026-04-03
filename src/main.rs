//! authsock-warden - SSH agent proxy with key filtering, process-aware access control,
//! and 1Password integration

use clap::{CommandFactory, Parser};
use clap_complete::env::CompleteEnv;
use tracing::error;
use tracing_subscriber::EnvFilter;

use authsock_warden::cli::exit_code::ExitCode;
use authsock_warden::cli::{Cli, Commands, ServiceCommand};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();

    if cli.version {
        authsock_warden::cli::commands::version::print_version(cli.verbose);
        return ExitCode::Success.into();
    }

    init_logging(cli.verbose, cli.quiet);

    let result = run(cli).await;

    match result {
        Ok(()) => ExitCode::Success.into(),
        Err((code, err)) => {
            error!("{err:#}");
            code.into()
        }
    }
}

async fn run(cli: Cli) -> Result<(), (ExitCode, anyhow::Error)> {
    let Some(command) = cli.command else {
        Cli::command().print_help().ok();
        return Ok(());
    };

    match command {
        Commands::Run(args) => authsock_warden::cli::commands::run::execute(args, cli.config)
            .await
            .map_err(|e| (classify_error(&e), e))?,
        Commands::Config { command } => {
            authsock_warden::cli::commands::config::execute(command, cli.config)
                .await
                .map_err(|e| (ExitCode::ConfigError, e))?
        }
        Commands::Service { command } => match command {
            ServiceCommand::Register(args) => {
                authsock_warden::cli::commands::service::register(args, cli.config)
                    .await
                    .map_err(|e| (ExitCode::GeneralError, e))?
            }
            ServiceCommand::Unregister(args) => {
                authsock_warden::cli::commands::service::unregister(args)
                    .await
                    .map_err(|e| (ExitCode::GeneralError, e))?
            }
            ServiceCommand::Reload(args) => authsock_warden::cli::commands::service::reload(args)
                .await
                .map_err(|e| (ExitCode::GeneralError, e))?,
            ServiceCommand::Status(args) => authsock_warden::cli::commands::service::status(args)
                .await
                .map_err(|e| (ExitCode::GeneralError, e))?,
        },
        Commands::Log(args) => authsock_warden::cli::commands::log::execute(args)
            .await
            .map_err(|e| (ExitCode::GeneralError, e))?,
        Commands::Completion(args) => authsock_warden::cli::commands::completion::execute(args)
            .await
            .map_err(|e| (ExitCode::GeneralError, e))?,
        Commands::Keys => {
            println!("keys command not yet implemented");
        }
        Commands::Refresh => {
            println!("refresh command not yet implemented");
        }
        Commands::Status => {
            println!("status command not yet implemented");
        }
        Commands::Version => {
            authsock_warden::cli::commands::version::print_version(cli.verbose);
        }
    }

    Ok(())
}

fn classify_error(err: &anyhow::Error) -> ExitCode {
    // Classify by downcasting to concrete error types rather than string matching
    use authsock_warden::error::Error;
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<Error>() {
            return match e {
                Error::Config(_) | Error::TomlParse(_) => ExitCode::ConfigError,
                Error::UpstreamNotAvailable(_) => ExitCode::UpstreamError,
                Error::Socket(_) => ExitCode::SocketError,
                _ => continue,
            };
        }
    }
    ExitCode::GeneralError
}

fn init_logging(verbose: bool, quiet: bool) {
    let filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else if quiet {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
