//! Public key matching filter

use crate::error::{Error, Result};
use crate::protocol::Identity;
use bytes::Bytes;
use ssh_key::PublicKey;

/// Matcher for SSH public keys
#[derive(Debug, Clone)]
pub struct PubkeyMatcher {
    key_blob: Bytes,
}

impl PubkeyMatcher {
    /// Create from OpenSSH format key string (comment is ignored)
    pub fn new(key_str: &str) -> Result<Self> {
        let key = PublicKey::from_openssh(key_str)
            .map_err(|e| Error::Filter(format!("Invalid public key: {}", e)))?;

        let key_blob = key
            .to_bytes()
            .map_err(|e| Error::Filter(format!("Failed to encode key: {}", e)))?;

        Ok(Self {
            key_blob: Bytes::from(key_blob),
        })
    }

    pub fn from_blob(key_blob: Bytes) -> Self {
        Self { key_blob }
    }

    pub fn matches(&self, identity: &Identity) -> bool {
        identity.key_blob == self.key_blob
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com";
        let matcher = PubkeyMatcher::new(key);
        assert!(matcher.is_ok());
    }

    #[test]
    fn test_parse_with_comment_ignored() {
        let key1 =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl different comment";

        let m1 = PubkeyMatcher::new(key1).unwrap();
        let m2 = PubkeyMatcher::new(key2).unwrap();

        assert_eq!(m1.key_blob, m2.key_blob);
    }

    #[test]
    fn test_invalid_key() {
        let result = PubkeyMatcher::new("not a valid key");
        assert!(result.is_err());
    }
}
