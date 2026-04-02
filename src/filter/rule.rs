//! Filter rule definitions
//!
//! Stub implementation - will be fully ported from authsock-filter.

use crate::protocol::Identity;

/// A single filter rule
#[derive(Debug, Clone)]
pub enum FilterRule {
    /// Placeholder - full implementation will follow
    AcceptAll,
}

impl FilterRule {
    /// Check if an identity matches this rule
    pub fn matches(&self, _identity: &Identity) -> bool {
        match self {
            FilterRule::AcceptAll => true,
        }
    }
}
