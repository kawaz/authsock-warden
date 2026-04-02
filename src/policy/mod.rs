//! Policy engine for process-aware access control
//!
//! This module provides:
//! - Process identification from Unix domain socket connections
//! - Process tree walking (child → parent → ... → init/launchd)
//! - Policy evaluation combining filters and process rules

pub mod engine;
pub mod process;

pub use engine::PolicyEngine;
pub use process::{ProcessChain, ProcessInfo};
