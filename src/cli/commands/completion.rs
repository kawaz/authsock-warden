//! Completion command implementation

use crate::cli::Cli;
use crate::cli::args::CompletionArgs;
use clap::CommandFactory;
use clap_complete::generate;

pub async fn execute(args: CompletionArgs) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    generate(
        args.shell,
        &mut cmd,
        "authsock-warden",
        &mut std::io::stdout(),
    );
    Ok(())
}
