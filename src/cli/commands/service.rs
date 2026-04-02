//! Service command implementation

use crate::cli::args::{RegisterArgs, UnregisterArgs};
use std::path::PathBuf;

pub async fn register(_args: RegisterArgs, _config_path: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("service register not yet implemented")
}

pub async fn unregister(_args: UnregisterArgs) -> anyhow::Result<()> {
    anyhow::bail!("service unregister not yet implemented")
}

pub async fn reload(_args: UnregisterArgs) -> anyhow::Result<()> {
    anyhow::bail!("service reload not yet implemented")
}

pub async fn status(_args: UnregisterArgs) -> anyhow::Result<()> {
    anyhow::bail!("service status not yet implemented")
}
