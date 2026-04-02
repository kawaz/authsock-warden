//! Key store module for managing SSH key lifecycle
//!
//! Provides secure key storage with 4-state lifecycle:
//! Not Loaded → Active → Locked → Forgotten

pub mod cache;
pub mod op;
pub mod registry;
pub mod secret;
pub mod signer;
pub mod timer;

pub use registry::{KeyRegistry, KeyState, ManagedKey};
