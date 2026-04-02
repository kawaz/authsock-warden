//! Security hardening module
//!
//! Provides defense-in-depth protections for the warden process:
//! - Anti-debug: ptrace denial, DYLD injection detection
//! - Memory: mlock for secret data

pub mod anti_debug;
pub mod memory;
