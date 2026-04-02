//! Comment matching filter

use crate::error::{Error, Result};
use crate::protocol::Identity;
use globset::{Glob, GlobMatcher};
use regex::Regex;

#[derive(Debug, Clone)]
enum MatchType {
    Exact(String),
    Glob(GlobMatcher),
    Regex(Regex),
}

/// Matcher for SSH key comments
#[derive(Debug, Clone)]
pub struct CommentMatcher {
    pattern: String,
    match_type: MatchType,
}

impl CommentMatcher {
    /// Create a new comment matcher
    ///
    /// Pattern syntax:
    /// - `~regex` - regular expression
    /// - `*glob*` - glob pattern (if contains * or ?)
    /// - `exact` - exact match
    pub fn new(pattern: &str) -> Result<Self> {
        let match_type = if let Some(regex_pattern) = pattern.strip_prefix('~') {
            let regex = Regex::new(regex_pattern).map_err(|e| {
                Error::Filter(format!("Invalid regex pattern '{}': {}", regex_pattern, e))
            })?;
            MatchType::Regex(regex)
        } else if pattern.contains('*') || pattern.contains('?') {
            let glob = Glob::new(pattern)
                .map_err(|e| Error::Filter(format!("Invalid glob pattern '{}': {}", pattern, e)))?;
            MatchType::Glob(glob.compile_matcher())
        } else {
            MatchType::Exact(pattern.to_string())
        };

        Ok(Self {
            pattern: pattern.to_string(),
            match_type,
        })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn matches(&self, identity: &Identity) -> bool {
        match &self.match_type {
            MatchType::Exact(s) => identity.comment == *s,
            MatchType::Glob(g) => g.is_match(&identity.comment),
            MatchType::Regex(r) => r.is_match(&identity.comment),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_identity(comment: &str) -> Identity {
        Identity::new(Bytes::new(), comment.to_string())
    }

    #[test]
    fn test_exact_match() {
        let matcher = CommentMatcher::new("user@host").unwrap();
        assert!(matcher.matches(&make_identity("user@host")));
        assert!(!matcher.matches(&make_identity("other@host")));
    }

    #[test]
    fn test_glob_match() {
        let matcher = CommentMatcher::new("*@work.example.com").unwrap();
        assert!(matcher.matches(&make_identity("user@work.example.com")));
        assert!(!matcher.matches(&make_identity("user@home.example.com")));
    }

    #[test]
    fn test_regex_match() {
        let matcher = CommentMatcher::new("~@work\\.example\\.com$").unwrap();
        assert!(matcher.matches(&make_identity("user@work.example.com")));
        assert!(!matcher.matches(&make_identity("user@work.example.com.evil")));
    }

    #[test]
    fn test_invalid_regex() {
        let result = CommentMatcher::new("~[invalid");
        assert!(result.is_err());
    }
}
