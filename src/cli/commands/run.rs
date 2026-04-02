//! Run command implementation

use crate::cli::args::RunArgs;
use std::path::PathBuf;

pub async fn execute(_args: RunArgs, _config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // TODO: Phase 1 implementation
    // 1. Load config
    // 2. Create upstream connections from sources
    // 3. Create filter evaluators for each socket
    // 4. Bind sockets and start proxy
    anyhow::bail!("run command not yet implemented")
}
