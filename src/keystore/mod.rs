//! Key store module for managing SSH key lifecycle
//!
//! Provides secure key storage with 4-state lifecycle:
//! Not Loaded → Active → Locked → Forgotten

pub mod registry;
pub mod secret;
pub mod timer;

pub use registry::{KeyRegistry, KeyState, ManagedKey};
