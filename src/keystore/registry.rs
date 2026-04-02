//! Key registry for managing SSH key lifecycle

use crate::keystore::secret::SecretKeyData;
use crate::keystore::timer::KeyTimer;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// State of a managed key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Key is known but not loaded into memory
    NotLoaded,
    /// Key is in memory and available for signing
    Active,
    /// Key is in memory but signing is locked (needs re-auth)
    Locked,
    /// Key has been zeroized from memory
    Forgotten,
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::NotLoaded => write!(f, "NotLoaded"),
            KeyState::Active => write!(f, "Active"),
            KeyState::Locked => write!(f, "Locked"),
            KeyState::Forgotten => write!(f, "Forgotten"),
        }
    }
}

/// Metadata about how to retrieve a key
#[derive(Debug, Clone)]
pub enum KeySource {
    /// Key from 1Password (item ID for retrieval)
    OnePassword { item_id: String },
    /// Key from a file
    File { path: std::path::PathBuf },
}

/// A managed key with lifecycle state
pub struct ManagedKey {
    /// Raw public key blob (wire format)
    pub key_blob: Bytes,
    /// Human-readable comment
    pub comment: String,
    /// Source information for key retrieval
    pub source: KeySource,
    /// Current state
    pub state: KeyState,
    /// Timer for timeout/forget management
    pub timer: Option<KeyTimer>,
    /// Secret key data (only present in Active/Locked states)
    secret: Option<SecretKeyData>,
}

impl ManagedKey {
    pub fn new(key_blob: Bytes, comment: String, source: KeySource) -> Self {
        Self {
            key_blob,
            comment,
            source,
            state: KeyState::NotLoaded,
            timer: None,
            secret: None,
        }
    }

    /// Load a secret key (transition to Active)
    pub fn load_secret(
        &mut self,
        secret: SecretKeyData,
        timeout: Option<Duration>,
        forget_after: Option<Duration>,
    ) {
        self.secret = Some(secret);
        self.state = KeyState::Active;
        self.timer = Some(KeyTimer::new(timeout, forget_after));
    }

    /// Get the secret key (only if Active)
    pub fn secret(&self) -> Option<&SecretKeyData> {
        if self.state == KeyState::Active {
            self.secret.as_ref()
        } else {
            None
        }
    }

    /// Lock the key (Active → Locked)
    pub fn lock(&mut self) {
        if self.state == KeyState::Active {
            self.state = KeyState::Locked;
            debug!(comment = %self.comment, "Key locked");
        }
    }

    /// Unlock the key (Locked → Active, requires re-auth)
    pub fn unlock(&mut self) {
        if self.state == KeyState::Locked {
            self.state = KeyState::Active;
            if let Some(ref mut timer) = self.timer {
                timer.touch();
            }
            debug!(comment = %self.comment, "Key unlocked");
        }
    }

    /// Forget the key (any state → Forgotten, zeroizes secret)
    pub fn forget(&mut self) {
        if let Some(secret) = self.secret.take() {
            secret.forget();
        }
        self.state = KeyState::Forgotten;
        self.timer = None;
        info!(comment = %self.comment, "Key forgotten");
    }

    /// Refresh timers (re-auth required)
    pub fn refresh(&mut self) {
        if let Some(ref mut timer) = self.timer {
            timer.refresh();
        }
        if self.state == KeyState::Locked {
            self.state = KeyState::Active;
        }
        debug!(comment = %self.comment, "Key refreshed");
    }

    /// Check and update state based on timers
    pub fn check_timers(&mut self, on_timeout: &str) {
        let Some(ref timer) = self.timer else {
            return;
        };

        if self.state == KeyState::Active && timer.is_timed_out() {
            match on_timeout {
                "lock" => self.lock(),
                "forget" => self.forget(),
                _ => self.lock(), // default to lock
            }
        }

        // forget_after applies regardless of lock/forget setting
        if (self.state == KeyState::Active || self.state == KeyState::Locked)
            && self.timer.as_ref().is_some_and(|t| t.should_forget())
        {
            self.forget();
        }
    }

    /// Touch the timer (on signing)
    pub fn touch(&mut self) {
        if let Some(ref mut timer) = self.timer {
            timer.touch();
        }
    }
}

impl std::fmt::Debug for ManagedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedKey")
            .field("comment", &self.comment)
            .field("state", &self.state)
            .field("has_secret", &self.secret.is_some())
            .finish()
    }
}

/// Registry of all managed keys
pub struct KeyRegistry {
    /// Map from public key blob (wire format) to managed key
    keys: Arc<RwLock<HashMap<Bytes, ManagedKey>>>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a key (initially in NotLoaded state)
    pub async fn register(&self, key_blob: Bytes, comment: String, source: KeySource) {
        let mut keys = self.keys.write().await;
        keys.insert(key_blob.clone(), ManagedKey::new(key_blob, comment, source));
    }

    /// Get the state of a key
    pub async fn get_state(&self, key_blob: &Bytes) -> Option<KeyState> {
        let keys = self.keys.read().await;
        keys.get(key_blob).map(|k| k.state)
    }

    /// Load a secret for a key (transition to Active)
    pub async fn load_secret(
        &self,
        key_blob: &Bytes,
        secret: SecretKeyData,
        timeout: Option<Duration>,
        forget_after: Option<Duration>,
    ) -> bool {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(key_blob) {
            key.load_secret(secret, timeout, forget_after);
            true
        } else {
            false
        }
    }

    /// Lock a key
    pub async fn lock_key(&self, key_blob: &Bytes) {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(key_blob) {
            key.lock();
        }
    }

    /// Forget a key (zeroize secret)
    pub async fn forget_key(&self, key_blob: &Bytes) {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(key_blob) {
            key.forget();
        }
    }

    /// Forget all keys
    pub async fn forget_all(&self) {
        let mut keys = self.keys.write().await;
        for key in keys.values_mut() {
            key.forget();
        }
    }

    /// Refresh a key's timers
    pub async fn refresh_key(&self, key_blob: &Bytes) {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(key_blob) {
            key.refresh();
        }
    }

    /// Refresh all keys' timers
    pub async fn refresh_all(&self) {
        let mut keys = self.keys.write().await;
        for key in keys.values_mut() {
            key.refresh();
        }
    }

    /// Check all key timers and update states
    pub async fn check_all_timers(&self, default_on_timeout: &str) {
        let mut keys = self.keys.write().await;
        for key in keys.values_mut() {
            key.check_timers(default_on_timeout);
        }
    }

    /// Get a summary of all keys for status display
    pub async fn status_summary(&self) -> Vec<KeyStatusInfo> {
        let keys = self.keys.read().await;
        keys.values()
            .map(|k| KeyStatusInfo {
                comment: k.comment.clone(),
                state: k.state,
                time_until_timeout: k.timer.as_ref().and_then(|t| t.time_until_timeout()),
                time_until_forget: k.timer.as_ref().and_then(|t| t.time_until_forget()),
            })
            .collect()
    }

    /// Get the number of registered keys
    pub async fn len(&self) -> usize {
        self.keys.read().await.len()
    }

    /// Check if registry is empty
    pub async fn is_empty(&self) -> bool {
        self.keys.read().await.is_empty()
    }
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Status info for display
#[derive(Debug, Clone)]
pub struct KeyStatusInfo {
    pub comment: String,
    pub state: KeyState,
    pub time_until_timeout: Option<Duration>,
    pub time_until_forget: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_blob(id: u8) -> Bytes {
        Bytes::from(vec![id; 32])
    }

    fn test_source() -> KeySource {
        KeySource::File {
            path: std::path::PathBuf::from("/tmp/test_key"),
        }
    }

    // --- ManagedKey unit tests ---

    #[test]
    fn new_managed_key_is_not_loaded() {
        let key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        assert_eq!(key.state, KeyState::NotLoaded);
        assert!(key.secret().is_none());
        assert!(key.timer.is_none());
    }

    #[test]
    fn load_secret_transitions_to_active() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        let secret = SecretKeyData::new(vec![0xAA; 16]);
        key.load_secret(secret, Some(Duration::from_secs(60)), None);
        assert_eq!(key.state, KeyState::Active);
        assert!(key.secret().is_some());
        assert!(key.timer.is_some());
    }

    #[test]
    fn secret_returns_none_when_not_active() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        // NotLoaded
        assert!(key.secret().is_none());

        // Load then lock
        key.load_secret(
            SecretKeyData::new(vec![1]),
            Some(Duration::from_secs(60)),
            None,
        );
        key.lock();
        assert_eq!(key.state, KeyState::Locked);
        assert!(key.secret().is_none());
    }

    #[test]
    fn lock_transitions_active_to_locked() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![1]), None, None);
        assert_eq!(key.state, KeyState::Active);
        key.lock();
        assert_eq!(key.state, KeyState::Locked);
    }

    #[test]
    fn lock_is_noop_when_not_active() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        // NotLoaded -> lock should be noop
        key.lock();
        assert_eq!(key.state, KeyState::NotLoaded);
    }

    #[test]
    fn unlock_transitions_locked_to_active() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(
            SecretKeyData::new(vec![1]),
            Some(Duration::from_secs(60)),
            None,
        );
        key.lock();
        assert_eq!(key.state, KeyState::Locked);
        key.unlock();
        assert_eq!(key.state, KeyState::Active);
    }

    #[test]
    fn unlock_is_noop_when_not_locked() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![1]), None, None);
        // Active -> unlock should be noop
        key.unlock();
        assert_eq!(key.state, KeyState::Active);
    }

    #[test]
    fn forget_transitions_to_forgotten_and_clears_secret() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![0xBB; 32]), None, None);
        assert!(key.secret.is_some());
        key.forget();
        assert_eq!(key.state, KeyState::Forgotten);
        assert!(key.secret.is_none());
        assert!(key.timer.is_none());
    }

    #[test]
    fn forget_from_not_loaded() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.forget();
        assert_eq!(key.state, KeyState::Forgotten);
    }

    #[test]
    fn refresh_resets_timers_and_unlocks() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(
            SecretKeyData::new(vec![1]),
            Some(Duration::from_millis(1)),
            None,
        );
        key.lock();
        assert_eq!(key.state, KeyState::Locked);
        key.refresh();
        assert_eq!(key.state, KeyState::Active);
    }

    #[test]
    fn check_timers_locks_on_timeout() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![1]), Some(Duration::ZERO), None);
        key.check_timers("lock");
        assert_eq!(key.state, KeyState::Locked);
    }

    #[test]
    fn check_timers_forgets_on_timeout_when_configured() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![1]), Some(Duration::ZERO), None);
        key.check_timers("forget");
        assert_eq!(key.state, KeyState::Forgotten);
    }

    #[test]
    fn check_timers_forgets_after_forget_duration() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        key.load_secret(
            SecretKeyData::new(vec![1]),
            None,                 // no lock timeout
            Some(Duration::ZERO), // immediate forget
        );
        key.check_timers("lock");
        assert_eq!(key.state, KeyState::Forgotten);
    }

    #[test]
    fn check_timers_noop_without_timer() {
        let mut key = ManagedKey::new(test_blob(1), "test".into(), test_source());
        // No timer set (NotLoaded)
        key.check_timers("lock");
        assert_eq!(key.state, KeyState::NotLoaded);
    }

    #[test]
    fn debug_does_not_contain_secret() {
        let mut key = ManagedKey::new(test_blob(1), "test_key".into(), test_source());
        key.load_secret(SecretKeyData::new(vec![0xDE, 0xAD]), None, None);
        let debug_output = format!("{:?}", key);
        assert!(debug_output.contains("test_key"));
        assert!(debug_output.contains("has_secret"));
        // Should not contain raw secret data
        assert!(!debug_output.contains("222")); // 0xDE
        assert!(!debug_output.contains("173")); // 0xAD
    }

    #[test]
    fn key_state_display() {
        assert_eq!(format!("{}", KeyState::NotLoaded), "NotLoaded");
        assert_eq!(format!("{}", KeyState::Active), "Active");
        assert_eq!(format!("{}", KeyState::Locked), "Locked");
        assert_eq!(format!("{}", KeyState::Forgotten), "Forgotten");
    }

    // --- KeyRegistry async tests ---

    #[tokio::test]
    async fn registry_register_and_get_state() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::NotLoaded));
    }

    #[tokio::test]
    async fn registry_get_state_unknown_key() {
        let registry = KeyRegistry::new();
        assert_eq!(registry.get_state(&test_blob(99)).await, None);
    }

    #[tokio::test]
    async fn registry_load_secret() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        let result = registry
            .load_secret(
                &blob,
                SecretKeyData::new(vec![1]),
                Some(Duration::from_secs(60)),
                None,
            )
            .await;
        assert!(result);
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Active));
    }

    #[tokio::test]
    async fn registry_load_secret_unknown_key_returns_false() {
        let registry = KeyRegistry::new();
        let result = registry
            .load_secret(&test_blob(99), SecretKeyData::new(vec![1]), None, None)
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn registry_lock_key() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        registry
            .load_secret(&blob, SecretKeyData::new(vec![1]), None, None)
            .await;
        registry.lock_key(&blob).await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Locked));
    }

    #[tokio::test]
    async fn registry_forget_key() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        registry
            .load_secret(&blob, SecretKeyData::new(vec![1]), None, None)
            .await;
        registry.forget_key(&blob).await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Forgotten));
    }

    #[tokio::test]
    async fn registry_forget_all() {
        let registry = KeyRegistry::new();
        let blob1 = test_blob(1);
        let blob2 = test_blob(2);
        registry
            .register(blob1.clone(), "key1".into(), test_source())
            .await;
        registry
            .register(blob2.clone(), "key2".into(), test_source())
            .await;
        registry
            .load_secret(&blob1, SecretKeyData::new(vec![1]), None, None)
            .await;
        registry
            .load_secret(&blob2, SecretKeyData::new(vec![2]), None, None)
            .await;
        registry.forget_all().await;
        assert_eq!(registry.get_state(&blob1).await, Some(KeyState::Forgotten));
        assert_eq!(registry.get_state(&blob2).await, Some(KeyState::Forgotten));
    }

    #[tokio::test]
    async fn registry_refresh_key() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        registry
            .load_secret(
                &blob,
                SecretKeyData::new(vec![1]),
                Some(Duration::from_millis(1)),
                None,
            )
            .await;
        // Lock it first
        registry.lock_key(&blob).await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Locked));
        // Refresh should unlock
        registry.refresh_key(&blob).await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Active));
    }

    #[tokio::test]
    async fn registry_refresh_all() {
        let registry = KeyRegistry::new();
        let blob1 = test_blob(1);
        let blob2 = test_blob(2);
        registry
            .register(blob1.clone(), "key1".into(), test_source())
            .await;
        registry
            .register(blob2.clone(), "key2".into(), test_source())
            .await;
        registry
            .load_secret(&blob1, SecretKeyData::new(vec![1]), None, None)
            .await;
        registry
            .load_secret(&blob2, SecretKeyData::new(vec![2]), None, None)
            .await;
        registry.lock_key(&blob1).await;
        registry.lock_key(&blob2).await;
        registry.refresh_all().await;
        assert_eq!(registry.get_state(&blob1).await, Some(KeyState::Active));
        assert_eq!(registry.get_state(&blob2).await, Some(KeyState::Active));
    }

    #[tokio::test]
    async fn registry_check_all_timers() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "test".into(), test_source())
            .await;
        registry
            .load_secret(
                &blob,
                SecretKeyData::new(vec![1]),
                Some(Duration::ZERO),
                None,
            )
            .await;
        registry.check_all_timers("lock").await;
        assert_eq!(registry.get_state(&blob).await, Some(KeyState::Locked));
    }

    #[tokio::test]
    async fn registry_len_and_is_empty() {
        let registry = KeyRegistry::new();
        assert!(registry.is_empty().await);
        assert_eq!(registry.len().await, 0);

        registry
            .register(test_blob(1), "test".into(), test_source())
            .await;
        assert!(!registry.is_empty().await);
        assert_eq!(registry.len().await, 1);
    }

    #[tokio::test]
    async fn registry_status_summary() {
        let registry = KeyRegistry::new();
        let blob = test_blob(1);
        registry
            .register(blob.clone(), "my_key".into(), test_source())
            .await;
        registry
            .load_secret(
                &blob,
                SecretKeyData::new(vec![1]),
                Some(Duration::from_secs(300)),
                Some(Duration::from_secs(3600)),
            )
            .await;

        let summary = registry.status_summary().await;
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].comment, "my_key");
        assert_eq!(summary[0].state, KeyState::Active);
        assert!(summary[0].time_until_timeout.is_some());
        assert!(summary[0].time_until_forget.is_some());
    }

    #[tokio::test]
    async fn registry_default_impl() {
        let registry = KeyRegistry::default();
        assert!(registry.is_empty().await);
    }
}
