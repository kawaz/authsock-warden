//! GitHub user keys matching filter

use crate::error::Result;
use crate::filter::PubkeyMatcher;
use crate::protocol::Identity;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Matcher for GitHub user's public keys
#[derive(Debug, Clone)]
pub struct GitHubKeysMatcher {
    username: String,
    matchers: Arc<RwLock<Vec<PubkeyMatcher>>>,
    cache_time: Arc<RwLock<Option<Instant>>>,
    cache_ttl: Duration,
    fetching: Arc<AtomicBool>,
}

impl GitHubKeysMatcher {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            matchers: Arc::new(RwLock::new(Vec::new())),
            cache_time: Arc::new(RwLock::new(None)),
            cache_ttl: DEFAULT_CACHE_TTL,
            fetching: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_cache_ttl(username: &str, cache_ttl: Duration) -> Self {
        Self {
            username: username.to_string(),
            matchers: Arc::new(RwLock::new(Vec::new())),
            cache_time: Arc::new(RwLock::new(None)),
            cache_ttl,
            fetching: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub async fn fetch_keys(&self) -> Result<()> {
        if self
            .fetching
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            tracing::debug!(
                "Skipping fetch for GitHub user {}: already in progress",
                self.username
            );
            return Ok(());
        }

        let _guard = scopeguard::guard((), |_| {
            self.fetching.store(false, Ordering::Relaxed);
        });

        let url = format!("https://github.com/{}.keys", self.username);

        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(crate::error::Error::Other(format!(
                "GitHub API request failed with status: {}",
                response.status()
            )));
        }
        let text = response.text().await?;

        let mut new_matchers = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match PubkeyMatcher::new(line) {
                Ok(m) => new_matchers.push(m),
                Err(e) => {
                    tracing::warn!("Skipping invalid key from GitHub {}: {}", self.username, e);
                }
            }
        }

        let key_count = new_matchers.len();
        *self.matchers.write().await = new_matchers;
        *self.cache_time.write().await = Some(Instant::now());

        tracing::info!(
            "Fetched {} keys for GitHub user {}",
            key_count,
            self.username
        );

        Ok(())
    }

    pub fn is_cache_valid(&self) -> bool {
        if let Ok(cache_time) = self.cache_time.try_read()
            && let Some(time) = *cache_time
        {
            return time.elapsed() < self.cache_ttl;
        }
        false
    }

    pub fn matches(&self, identity: &Identity) -> bool {
        if let Ok(matchers) = self.matchers.try_read() {
            matchers.iter().any(|m| m.matches(identity))
        } else {
            false
        }
    }

    pub async fn ensure_loaded(&self) -> Result<()> {
        if !self.is_cache_valid() {
            self.fetch_keys().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let matcher = GitHubKeysMatcher::new("kawaz");
        assert_eq!(matcher.username(), "kawaz");
        assert!(!matcher.is_cache_valid());
    }

    #[test]
    fn test_with_cache_ttl() {
        let matcher = GitHubKeysMatcher::with_cache_ttl("kawaz", Duration::from_secs(60));
        assert_eq!(matcher.username(), "kawaz");
        assert_eq!(matcher.cache_ttl, Duration::from_secs(60));
    }
}
