//! Filter rule definitions and parsing

use crate::error::{Error, Result};
use crate::filter::{
    CommentMatcher, FingerprintMatcher, GitHubKeysMatcher, KeyTypeMatcher, KeyfileMatcher,
    PubkeyMatcher,
};
use crate::protocol::Identity;

/// A filter that can match against an SSH key identity
#[derive(Debug, Clone)]
pub enum Filter {
    Fingerprint(FingerprintMatcher),
    Pubkey(PubkeyMatcher),
    Keyfile(KeyfileMatcher),
    Comment(CommentMatcher),
    KeyType(KeyTypeMatcher),
    GitHub(GitHubKeysMatcher),
}

impl Filter {
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            Filter::Fingerprint(m) => m.matches(identity),
            Filter::Pubkey(m) => m.matches(identity),
            Filter::Keyfile(m) => m.matches(identity),
            Filter::Comment(m) => m.matches(identity),
            Filter::KeyType(m) => m.matches(identity),
            Filter::GitHub(m) => m.matches(identity),
        }
    }

    pub fn description(&self) -> String {
        match self {
            Filter::Fingerprint(m) => format!("fingerprint={}", m.pattern()),
            Filter::Pubkey(_) => "pubkey=<key>".to_string(),
            Filter::Keyfile(m) => format!("keyfile={}", m.path()),
            Filter::Comment(m) => format!("comment={}", m.pattern()),
            Filter::KeyType(m) => format!("type={}", m.key_type()),
            Filter::GitHub(m) => format!("github={}", m.username()),
        }
    }
}

/// A filter rule with optional negation
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub filter: Filter,
    pub negated: bool,
}

impl FilterRule {
    pub fn new(filter: Filter, negated: bool) -> Self {
        Self { filter, negated }
    }

    pub fn matches(&self, identity: &Identity) -> bool {
        let result = self.filter.matches(identity);
        if self.negated { !result } else { result }
    }

    pub fn parse(s: &str) -> Result<Self> {
        let (negated, s) = if let Some(rest) = s.strip_prefix("not-") {
            (true, rest)
        } else {
            (false, s)
        };

        let filter = Self::parse_filter(s)?;
        Ok(Self { filter, negated })
    }

    fn parse_filter(s: &str) -> Result<Filter> {
        if let Some(filter) = Self::try_auto_detect(s) {
            return Ok(filter);
        }

        if let Some(rest) = s.strip_prefix("fingerprint=") {
            return Ok(Filter::Fingerprint(FingerprintMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("pubkey=") {
            return Ok(Filter::Pubkey(PubkeyMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("keyfile=") {
            return Ok(Filter::Keyfile(KeyfileMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("comment=") {
            return Ok(Filter::Comment(CommentMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("type=") {
            return Ok(Filter::KeyType(KeyTypeMatcher::new(rest)));
        }
        if let Some(rest) = s.strip_prefix("github=") {
            return Ok(Filter::GitHub(GitHubKeysMatcher::new(rest)));
        }

        Err(Error::Filter(format!("Unknown filter format: {}", s)))
    }

    fn try_auto_detect(s: &str) -> Option<Filter> {
        if s.starts_with("SHA256:") {
            return FingerprintMatcher::new(s).ok().map(Filter::Fingerprint);
        }
        if s.starts_with("MD5:") {
            return FingerprintMatcher::new(s).ok().map(Filter::Fingerprint);
        }
        if s.starts_with("ssh-")
            || s.starts_with("ecdsa-sha2-")
            || s.starts_with("sk-ssh-")
            || s.starts_with("sk-ecdsa-")
        {
            return PubkeyMatcher::new(s).ok().map(Filter::Pubkey);
        }
        None
    }

    pub fn description(&self) -> String {
        if self.negated {
            format!("-{}", self.filter.description())
        } else {
            self.filter.description()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fingerprint() {
        let rule = FilterRule::parse("SHA256:abc123").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Fingerprint(_)));
    }

    #[test]
    fn test_parse_explicit_fingerprint() {
        let rule = FilterRule::parse("fingerprint=SHA256:abc123").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Fingerprint(_)));
    }

    #[test]
    fn test_parse_negated() {
        let rule = FilterRule::parse("not-type=dsa").unwrap();
        assert!(rule.negated);
        assert!(matches!(rule.filter, Filter::KeyType(_)));
    }

    #[test]
    fn test_parse_comment() {
        let rule = FilterRule::parse("comment=~@work").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Comment(_)));
    }

    #[test]
    fn test_parse_github() {
        let rule = FilterRule::parse("github=kawaz").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::GitHub(_)));
    }

    #[test]
    fn test_parse_pubkey_auto() {
        let rule = FilterRule::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test",
        )
        .unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Pubkey(_)));
    }
}
