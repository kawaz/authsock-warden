//! Filter evaluation engine
//!
//! Stub implementation - will be fully ported from authsock-filter.

use crate::protocol::Identity;

/// A group of filters combined with AND logic
#[derive(Debug, Clone, Default)]
pub struct FilterGroup {
    pub rules: Vec<super::FilterRule>,
}

/// Evaluates filter groups with OR logic between groups
#[derive(Debug, Clone, Default)]
pub struct FilterEvaluator {
    pub groups: Vec<FilterGroup>,
}

impl FilterEvaluator {
    /// Check if an identity matches the filter rules.
    /// Empty filter (no groups) matches everything.
    pub fn matches(&self, identity: &Identity) -> bool {
        if self.groups.is_empty() {
            return true;
        }
        self.groups
            .iter()
            .any(|group| group.rules.iter().all(|rule| rule.matches(identity)))
    }
}
