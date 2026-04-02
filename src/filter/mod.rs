//! SSH key filtering module
//!
//! Provides filter rules for controlling which SSH keys are visible
//! on each socket. Supports filtering by comment, fingerprint, key type,
//! public key, key file, and GitHub user keys.

pub mod evaluator;
pub mod rule;

// Filter matchers
pub mod comment;
pub mod fingerprint;
pub mod github;
pub mod keyfile;
pub mod keytype;
pub mod pubkey;

pub use evaluator::FilterEvaluator;
pub use rule::FilterRule;
