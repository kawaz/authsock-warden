//! Public key cache for op:// source
//!
//! Caches the mapping of fingerprint → (public_key, item_id, title, vault)
//! in ~/.cache/authsock-warden/op_map.json to avoid repeated op item get calls.
//!
//! This data is not sensitive (public keys and fingerprints only).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};

const CACHE_VERSION: u32 = 1;
const CACHE_FILENAME: &str = "op_map.json";
const APP_NAME: &str = "authsock-warden";

/// A single cached key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedKey {
    pub item_id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub title: String,
    pub vault: String,
}

/// The cache file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpKeyCache {
    pub version: u32,
    pub keys: Vec<CachedKey>,
}

impl OpKeyCache {
    pub fn new() -> Self {
        Self {
            version: CACHE_VERSION,
            keys: Vec::new(),
        }
    }

    /// Build a fingerprint → CachedKey lookup map
    pub fn by_fingerprint(&self) -> HashMap<&str, &CachedKey> {
        self.keys
            .iter()
            .map(|k| (k.fingerprint.as_str(), k))
            .collect()
    }

    /// Load cache from disk. Returns empty cache on any error.
    pub fn load() -> Self {
        let Some(path) = cache_path() else {
            return Self::new();
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<OpKeyCache>(&content) {
                Ok(cache) if cache.version == CACHE_VERSION => {
                    debug!(keys = cache.keys.len(), "Loaded op key cache");
                    cache
                }
                Ok(_) => {
                    debug!("Op key cache version mismatch, starting fresh");
                    Self::new()
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse op key cache, starting fresh");
                    Self::new()
                }
            },
            Err(_) => Self::new(),
        }
    }

    /// Save cache to disk. Errors are logged but not propagated.
    pub fn save(&self) {
        let Some(path) = cache_path() else {
            return;
        };

        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(error = %e, "Failed to create cache directory");
            return;
        }

        match serde_json::to_string_pretty(self) {
            Ok(content) => {
                if let Err(e) = std::fs::write(&path, &content) {
                    warn!(error = %e, "Failed to write op key cache");
                } else {
                    // Set permissions to 0600 (owner read/write only)
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    }
                    debug!(keys = self.keys.len(), path = %path.display(), "Saved op key cache");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize op key cache");
            }
        }
    }
}

impl Default for OpKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the cache file path
fn cache_path() -> Option<PathBuf> {
    // XDG_CACHE_HOME or ~/.cache
    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))?;

    Some(cache_dir.join(APP_NAME).join(CACHE_FILENAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_cache() {
        let cache = OpKeyCache::new();
        assert_eq!(cache.version, CACHE_VERSION);
        assert!(cache.keys.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let mut cache = OpKeyCache::new();
        cache.keys.push(CachedKey {
            item_id: "abc123".to_string(),
            fingerprint: "SHA256:xyz".to_string(),
            public_key: "ssh-ed25519 AAAA...".to_string(),
            title: "test key".to_string(),
            vault: "Private".to_string(),
        });

        let json = serde_json::to_string(&cache).unwrap();
        let loaded: OpKeyCache = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].item_id, "abc123");
    }

    #[test]
    fn test_by_fingerprint() {
        let mut cache = OpKeyCache::new();
        cache.keys.push(CachedKey {
            item_id: "abc".to_string(),
            fingerprint: "SHA256:aaa".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            title: "key1".to_string(),
            vault: "Private".to_string(),
        });
        cache.keys.push(CachedKey {
            item_id: "def".to_string(),
            fingerprint: "SHA256:bbb".to_string(),
            public_key: "ssh-ed25519 BBBB".to_string(),
            title: "key2".to_string(),
            vault: "Work".to_string(),
        });

        let map = cache.by_fingerprint();
        assert_eq!(map.len(), 2);
        assert_eq!(map["SHA256:aaa"].item_id, "abc");
        assert_eq!(map["SHA256:bbb"].item_id, "def");
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op_map.json");

        let mut cache = OpKeyCache::new();
        cache.keys.push(CachedKey {
            item_id: "test".to_string(),
            fingerprint: "SHA256:test".to_string(),
            public_key: "ssh-ed25519 TEST".to_string(),
            title: "test".to_string(),
            vault: "Private".to_string(),
        });

        // Save manually to test path
        let content = serde_json::to_string_pretty(&cache).unwrap();
        std::fs::write(&path, &content).unwrap();

        // Load
        let loaded: OpKeyCache =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].item_id, "test");
    }

    #[test]
    fn test_load_invalid_json() {
        // Should not panic on invalid input
        let result = serde_json::from_str::<OpKeyCache>("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_mismatch() {
        let json = r#"{"version": 999, "keys": []}"#;
        let cache: OpKeyCache = serde_json::from_str(json).unwrap();
        assert_ne!(cache.version, CACHE_VERSION);
    }
}
