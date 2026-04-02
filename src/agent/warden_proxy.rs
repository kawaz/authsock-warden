//! WardProxy: SSH Agent proxy with multi-backend key aggregation
//!
//! Unlike the basic `Proxy` which only forwards to an upstream agent,
//! `WardProxy` aggregates keys from multiple sources:
//! - Agent upstream (proxy mode)
//! - 1Password via op CLI (local signing)
//!
//! Op keys are lazily discovered on the first REQUEST_IDENTITIES,
//! and private keys are fetched on-demand at sign time (triggering TouchID).

use crate::error::{Error, Result};
use crate::filter::FilterEvaluator;
use crate::keystore::{op, signer};
use crate::protocol::{AgentCodec, AgentMessage, Identity, MessageType};
use bytes::Bytes;
use ssh_key::PublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use super::Upstream;

/// Configuration for a single op:// source member
#[derive(Debug, Clone)]
pub struct OpSourceConfig {
    /// Optional vault filter (from `op://VAULT` or `op://VAULT/ITEM`)
    pub vault: Option<String>,
    /// Optional item filter (from `op://VAULT/ITEM`)
    pub item: Option<String>,
}

/// State of op key discovery (lazy initialization)
enum OpState {
    /// Not yet initialized — will be initialized on first request
    Uninitialized,
    /// Keys discovered successfully
    Ready {
        /// Op-managed keys indexed by wire-format key_blob
        keys: HashMap<Bytes, OpManagedKey>,
    },
    /// Initialization failed
    Failed(String),
}

/// A key managed by 1Password
struct OpManagedKey {
    /// 1Password item ID (used to fetch private key)
    item_id: String,
    /// Human-readable title (used as identity comment)
    title: String,
}

/// Which backend handles signing for a given key
#[derive(Debug, Clone)]
enum SigningBackend {
    /// Forward to upstream agent
    Agent,
    /// Sign locally with op-managed key
    Op { item_id: String },
}

/// SSH Agent proxy with multi-backend key aggregation.
///
/// Handles REQUEST_IDENTITIES by collecting keys from all configured
/// backends (agent upstream + op CLI), then applies filters.
/// Handles SIGN_REQUEST by routing to the appropriate backend.
pub struct WardProxy {
    /// Socket path for identification
    socket_path: String,
    /// Connection counter for client IDs
    connection_counter: AtomicU64,
    /// Filter evaluator for key filtering
    filter: Arc<FilterEvaluator>,
    /// Op source configurations (one per `op://` member)
    op_sources: Vec<OpSourceConfig>,
    /// Agent upstream (if any agent member exists in the source group)
    upstream: Option<Arc<Upstream>>,
    /// Op key state: lazily initialized on first REQUEST_IDENTITIES
    op_state: Arc<RwLock<OpState>>,
    /// Maps key_blob to which backend handles signing
    key_backend_map: Arc<RwLock<HashMap<Bytes, SigningBackend>>>,
    /// Socket-level cache for allowed keys (shared across all connections)
    allowed_keys_cache: Arc<RwLock<HashSet<Bytes>>>,
}

impl WardProxy {
    /// Create a new WardProxy.
    ///
    /// - `upstream`: agent upstream, if any agent member is in the source group
    /// - `filter`: filter evaluator for key filtering
    /// - `op_sources`: op:// source configurations
    pub fn new(
        upstream: Option<Upstream>,
        filter: FilterEvaluator,
        op_sources: Vec<OpSourceConfig>,
    ) -> Self {
        Self {
            socket_path: String::new(),
            connection_counter: AtomicU64::new(0),
            filter: Arc::new(filter),
            op_sources,
            upstream: upstream.map(Arc::new),
            op_state: Arc::new(RwLock::new(OpState::Uninitialized)),
            key_backend_map: Arc::new(RwLock::new(HashMap::new())),
            allowed_keys_cache: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Set the socket path for identification
    pub fn with_socket_path(mut self, path: impl Into<String>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Handle a client connection
    pub async fn handle_client(&self, mut client_stream: tokio::net::UnixStream) -> Result<()> {
        let client_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);
        debug!(
            socket = %self.socket_path,
            client_id = client_id,
            "Client connected (WardProxy)"
        );

        let result = self.handle_client_inner(&mut client_stream).await;

        debug!(
            socket = %self.socket_path,
            client_id = client_id,
            "Client disconnected (WardProxy)"
        );

        result
    }

    async fn handle_client_inner(&self, client_stream: &mut tokio::net::UnixStream) -> Result<()> {
        let (mut client_reader, mut client_writer) = client_stream.split();

        loop {
            let request = match AgentCodec::read(&mut client_reader).await? {
                Some(msg) => msg,
                None => {
                    trace!("Client disconnected");
                    break;
                }
            };

            trace!(msg_type = ?request.msg_type, "Received request from client (WardProxy)");

            let response = self.process_request(request).await?;

            AgentCodec::write(&mut client_writer, &response).await?;
        }

        Ok(())
    }

    async fn process_request(&self, request: AgentMessage) -> Result<AgentMessage> {
        match request.msg_type {
            MessageType::RequestIdentities => self.handle_request_identities(request).await,
            MessageType::SignRequest => self.handle_sign_request(request).await,
            _ => self.forward_to_upstream(request).await,
        }
    }

    // ---- REQUEST_IDENTITIES ----

    /// Handle SSH_AGENTC_REQUEST_IDENTITIES (11)
    ///
    /// Collects identities from all backends (op + agent), merges them
    /// (op keys take precedence for the key_backend_map), applies filters,
    /// and returns the combined list.
    async fn handle_request_identities(&self, request: AgentMessage) -> Result<AgentMessage> {
        debug!("Handling REQUEST_IDENTITIES (WardProxy)");

        // Ensure op keys are discovered (lazy init on first call)
        self.ensure_op_initialized().await;

        // Refresh op keys from 1Password agent socket (fast, no TouchID)
        if !self.op_sources.is_empty() {
            self.refresh_op_keys_from_agent().await;
        }

        let mut all_identities: Vec<Identity> = Vec::new();
        let mut new_backend_map: HashMap<Bytes, SigningBackend> = HashMap::new();

        // 1. Collect op identities
        {
            let state = self.op_state.read().await;
            if let OpState::Ready { keys } = &*state {
                for (key_blob, managed) in keys {
                    all_identities.push(Identity::new(key_blob.clone(), managed.title.clone()));
                    new_backend_map.insert(
                        key_blob.clone(),
                        SigningBackend::Op {
                            item_id: managed.item_id.clone(),
                        },
                    );
                }
                debug!(count = keys.len(), "Collected op identities");
            }
        }

        // 2. Collect agent identities (if upstream exists)
        if let Some(upstream) = &self.upstream {
            match self.request_upstream_identities(upstream, &request).await {
                Ok(agent_identities) => {
                    debug!(count = agent_identities.len(), "Collected agent identities");
                    for id in agent_identities {
                        // Op takes precedence: only add to backend map if not already present
                        new_backend_map
                            .entry(id.key_blob.clone())
                            .or_insert(SigningBackend::Agent);
                        all_identities.push(id);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to get identities from upstream agent");
                }
            }
        }

        // 3. Deduplicate by key_blob (op first, agent second)
        let mut seen = HashSet::new();
        all_identities.retain(|id| seen.insert(id.key_blob.clone()));

        let original_count = all_identities.len();

        // 4. Apply filters
        let filtered: Vec<Identity> = all_identities
            .into_iter()
            .filter(|id| self.filter.matches(id))
            .collect();

        let filtered_count = filtered.len();
        info!(
            original = original_count,
            filtered = filtered_count,
            "Filtered identities (WardProxy)"
        );

        // 5. Update caches
        {
            let mut cache = self.allowed_keys_cache.write().await;
            cache.clear();
            for identity in &filtered {
                cache.insert(identity.key_blob.clone());
            }
        }
        {
            let mut map = self.key_backend_map.write().await;
            *map = new_backend_map;
        }

        Ok(AgentMessage::build_identities_answer(&filtered))
    }

    /// Forward REQUEST_IDENTITIES to upstream and parse the response
    async fn request_upstream_identities(
        &self,
        upstream: &Upstream,
        request: &AgentMessage,
    ) -> Result<Vec<Identity>> {
        let mut conn = upstream.connect().await?;
        let response = conn.send_receive(request).await?;

        if response.msg_type != MessageType::IdentitiesAnswer {
            warn!(
                msg_type = ?response.msg_type,
                "Unexpected response type for REQUEST_IDENTITIES from upstream"
            );
            return Ok(Vec::new());
        }

        response.parse_identities()
    }

    // ---- SIGN_REQUEST ----

    /// Handle SSH_AGENTC_SIGN_REQUEST (13)
    ///
    /// Routes signing to the appropriate backend based on key_backend_map.
    async fn handle_sign_request(&self, request: AgentMessage) -> Result<AgentMessage> {
        let key_blob = match request.parse_sign_request_key() {
            Ok(blob) => blob,
            Err(e) => {
                warn!(error = %e, "Failed to parse sign request");
                return Ok(AgentMessage::failure());
            }
        };

        let identity = Identity::new(key_blob.clone(), String::new());

        // Check allowed keys cache, then filter directly
        let is_allowed = {
            let cache = self.allowed_keys_cache.read().await;
            cache.contains(key_blob.as_ref())
        } || self.filter.matches(&identity);

        if !is_allowed {
            warn!("Sign request denied: key not allowed by filter (WardProxy)");
            return Ok(AgentMessage::failure());
        }

        // Look up which backend should handle this key
        let backend = {
            let map = self.key_backend_map.read().await;
            map.get(&key_blob).cloned()
        };

        match backend {
            Some(SigningBackend::Agent) => self.forward_to_upstream(request).await,
            Some(SigningBackend::Op { item_id }) => {
                self.sign_with_op(&item_id, &request.payload).await
            }
            None => {
                // Key not in our backend map — try upstream as fallback
                if self.upstream.is_some() {
                    self.forward_to_upstream(request).await
                } else {
                    warn!("Sign request for unknown key and no upstream available");
                    Ok(AgentMessage::failure())
                }
            }
        }
    }

    /// Sign data locally using an op-managed key.
    ///
    /// Fetches the private key from 1Password (triggering TouchID),
    /// parses it, and signs the data.
    async fn sign_with_op(
        &self,
        item_id: &str,
        sign_request_payload: &Bytes,
    ) -> Result<AgentMessage> {
        let item_id = item_id.to_string();
        let payload = sign_request_payload.clone();

        debug!(item_id = %item_id, "Signing with op-managed key (fetching private key)");

        // Fetch private key via op CLI (blocking — may trigger TouchID)
        let pem = tokio::task::spawn_blocking(move || op::get_private_key(&item_id))
            .await
            .map_err(|e| Error::KeyStore(format!("spawn_blocking failed: {}", e)))??;

        // Parse and sign
        let private_key = signer::parse_private_key(&pem)?;
        signer::sign_with_key(&private_key, &payload)
    }

    // ---- Op lazy initialization ----

    /// Ensure op keys are discovered. Called once on first REQUEST_IDENTITIES.
    async fn ensure_op_initialized(&self) {
        // Fast path: already initialized
        {
            let state = self.op_state.read().await;
            match &*state {
                OpState::Uninitialized => {} // fall through to slow path
                OpState::Ready { .. } => return,
                OpState::Failed(err) => {
                    debug!(error = %err, "Op key discovery previously failed, skipping");
                    return;
                }
            }
        }

        // Slow path: discover keys
        let mut state = self.op_state.write().await;
        // Double-check after acquiring write lock
        if !matches!(&*state, OpState::Uninitialized) {
            return;
        }

        if self.op_sources.is_empty() {
            // No op sources configured — skip initialization
            *state = OpState::Ready {
                keys: HashMap::new(),
            };
            return;
        }

        info!("Initializing op key discovery (lazy)");

        match self.discover_op_keys().await {
            Ok(keys) => {
                info!(count = keys.len(), "Op key discovery complete");
                *state = OpState::Ready { keys };
            }
            Err(e) => {
                warn!(error = %e, "Op key discovery failed");
                *state = OpState::Failed(e.to_string());
            }
        }
    }

    /// Discover all SSH keys from configured op sources.
    ///
    /// For each op source, calls `op item list` then `op item get` for
    /// each discovered key to obtain the public key blob.
    async fn discover_op_keys(&self) -> Result<HashMap<Bytes, OpManagedKey>> {
        use crate::keystore::cache::{CachedKey, OpKeyCache};

        let mut keys = HashMap::new();
        let mut cache = OpKeyCache::load();
        let cache_map = cache
            .by_fingerprint()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<HashMap<String, CachedKey>>();
        let mut new_cache_keys: Vec<CachedKey> = Vec::new();

        for source in &self.op_sources {
            let vault = source.vault.clone();
            let item = source.item.clone();

            // Step 1: op item list → fingerprint → itemid map
            let key_infos = tokio::task::spawn_blocking(move || {
                op::list_ssh_keys(vault.as_deref(), item.as_deref())
            })
            .await
            .map_err(|e| Error::KeyStore(format!("spawn_blocking failed: {}", e)))??;

            let mut fp_to_info: HashMap<String, (String, String, String)> = HashMap::new();
            for info in &key_infos {
                fp_to_info.insert(
                    info.fingerprint.clone(),
                    (
                        info.item_id.clone(),
                        info.title.clone(),
                        info.vault_name.clone(),
                    ),
                );
            }

            info!(
                count = key_infos.len(),
                "op item list returned SSH keys, resolving public keys..."
            );

            let mut resolved_fps: HashSet<String> = HashSet::new();

            // Step 2: Try disk cache for instant resolution
            for (fp, (item_id, title, vault_name)) in &fp_to_info {
                if let Some(cached) = cache_map.get(fp.as_str())
                    && let Ok(pub_key) = PublicKey::from_openssh(&cached.public_key)
                    && let Ok(blob) = pub_key.to_bytes()
                {
                    let key_blob = Bytes::from(blob);
                    resolved_fps.insert(fp.clone());
                    debug!(title = %title, "Resolved via cache");
                    keys.insert(
                        key_blob,
                        OpManagedKey {
                            item_id: item_id.clone(),
                            title: title.clone(),
                        },
                    );
                    new_cache_keys.push(CachedKey {
                        item_id: item_id.clone(),
                        fingerprint: fp.clone(),
                        public_key: cached.public_key.clone(),
                        title: title.clone(),
                        vault: vault_name.clone(),
                    });
                }
            }

            if resolved_fps.len() == fp_to_info.len() {
                debug!("All keys resolved from cache");
                continue;
            }

            // Step 3: Try 1Password agent socket for remaining keys
            let remaining_fp_to_info: HashMap<String, (String, String)> = fp_to_info
                .iter()
                .filter(|(fp, _)| !resolved_fps.contains(fp.as_str()))
                .map(|(fp, (id, title, _))| (fp.clone(), (id.clone(), title.clone())))
                .collect();

            let agent_resolved = self.resolve_keys_via_agent(&remaining_fp_to_info).await;

            if let Ok(ref agent_keys) = agent_resolved {
                for (fp, (key_blob, item_id, title)) in agent_keys {
                    resolved_fps.insert(fp.clone());
                    debug!(title = %title, "Resolved via 1Password agent");
                    keys.insert(
                        key_blob.clone(),
                        OpManagedKey {
                            item_id: item_id.clone(),
                            title: title.clone(),
                        },
                    );
                    // Reconstruct public key string for cache
                    if let Ok(pub_key) = PublicKey::from_bytes(key_blob) {
                        let vault_name = fp_to_info
                            .get(fp)
                            .map(|(_, _, v)| v.as_str())
                            .unwrap_or("Unknown");
                        new_cache_keys.push(CachedKey {
                            item_id: item_id.clone(),
                            fingerprint: fp.clone(),
                            public_key: pub_key.to_openssh().unwrap_or_default(),
                            title: title.clone(),
                            vault: vault_name.to_string(),
                        });
                    }
                }
            }

            // Step 4: Fetch still-remaining keys via op item get (parallel)
            let remaining: Vec<_> = key_infos
                .iter()
                .filter(|info| !resolved_fps.contains(&info.fingerprint))
                .collect();

            if !remaining.is_empty() {
                info!(
                    count = remaining.len(),
                    "Fetching remaining keys via op item get..."
                );

                let mut fetch_tasks = Vec::new();
                for info in &remaining {
                    let item_id = info.item_id.clone();
                    let title = info.title.clone();
                    let task = tokio::task::spawn_blocking(move || {
                        let pub_key_str = op::get_public_key(&item_id)?;
                        Ok::<_, Error>((item_id, title, pub_key_str))
                    });
                    fetch_tasks.push(task);
                }

                for (task, info) in fetch_tasks.into_iter().zip(remaining.iter()) {
                    let (item_id, title, pub_key_str) = task
                        .await
                        .map_err(|e| Error::KeyStore(format!("spawn_blocking failed: {}", e)))??;

                    let pub_key = PublicKey::from_openssh(&pub_key_str).map_err(|e| {
                        Error::KeyStore(format!(
                            "Failed to parse public key for '{}': {}",
                            title, e
                        ))
                    })?;

                    let key_blob = Bytes::from(pub_key.to_bytes().map_err(|e| {
                        Error::KeyStore(format!(
                            "Failed to encode public key for '{}': {}",
                            title, e
                        ))
                    })?);

                    debug!(title = %title, item_id = %item_id, "Resolved via op item get");
                    keys.insert(
                        key_blob,
                        OpManagedKey {
                            item_id: item_id.clone(),
                            title: title.clone(),
                        },
                    );

                    new_cache_keys.push(CachedKey {
                        item_id,
                        fingerprint: info.fingerprint.clone(),
                        public_key: pub_key_str,
                        title,
                        vault: info.vault_name.clone(),
                    });
                }
            }
        }

        // Save updated cache
        cache.keys = new_cache_keys;
        cache.save();

        info!(count = keys.len(), "Op key discovery complete");
        Ok(keys)
    }

    /// Refresh op keys by querying the 1Password agent socket.
    ///
    /// Called on every REQUEST_IDENTITIES (after initial discovery).
    /// Detects newly added keys in the agent and adds them to op_state.
    /// This is fast (no op CLI, no TouchID).
    async fn refresh_op_keys_from_agent(&self) {
        use crate::keystore::cache::{CachedKey, OpKeyCache};
        use ssh_key::HashAlg;

        let state_is_ready = {
            let state = self.op_state.read().await;
            matches!(&*state, OpState::Ready { .. })
        };
        if !state_is_ready {
            return;
        }

        let Some(agent_path) = onepassword_agent_socket() else {
            return;
        };

        let upstream = Upstream::new(&agent_path);
        let mut conn = match upstream.connect().await {
            Ok(conn) => conn,
            Err(_) => return,
        };

        let request = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let response = match conn.send_receive(&request).await {
            Ok(resp) => resp,
            Err(_) => return,
        };

        if response.msg_type != MessageType::IdentitiesAnswer {
            return;
        }

        let identities = response.parse_identities().unwrap_or_default();

        // Check for new keys not in op_state
        let mut new_keys = Vec::new();
        {
            let state = self.op_state.read().await;
            if let OpState::Ready { keys } = &*state {
                for identity in &identities {
                    if !keys.contains_key(&identity.key_blob) {
                        new_keys.push(identity.clone());
                    }
                }
            }
        }

        if new_keys.is_empty() {
            return;
        }

        debug!(
            count = new_keys.len(),
            "Detected new keys from 1Password agent"
        );

        // Try to match new keys against cache by fingerprint
        let cache = OpKeyCache::load();
        let cache_map = cache
            .by_fingerprint()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<std::collections::HashMap<String, CachedKey>>();

        let mut added = 0;
        let mut updated_cache = false;

        {
            let mut state = self.op_state.write().await;
            if let OpState::Ready { keys } = &mut *state {
                for identity in &new_keys {
                    if let Some(pub_key) = &identity.public_key {
                        let fp = pub_key.fingerprint(HashAlg::Sha256).to_string();
                        if let Some(cached) = cache_map.get(&fp) {
                            keys.insert(
                                identity.key_blob.clone(),
                                OpManagedKey {
                                    item_id: cached.item_id.clone(),
                                    title: cached.title.clone(),
                                },
                            );
                            added += 1;
                            debug!(title = %cached.title, "Added new key from agent (cache hit)");
                        } else {
                            // New key not in cache — would need op item list to get itemid
                            // Skip for now, will be picked up on next full discovery
                            debug!(fingerprint = %fp, "New key from agent not in cache, skipping");
                            updated_cache = true;
                        }
                    }
                }
            }
        }

        if added > 0 {
            info!(added = added, "Refreshed op keys from 1Password agent");
        }
        let _ = updated_cache; // TODO: trigger op item list on next suitable occasion
    }

    /// Try to resolve public keys via 1Password agent socket (fast path).
    ///
    /// Returns map of fingerprint → (key_blob, item_id, title) for keys
    /// that were found in the agent and matched the fingerprint map.
    async fn resolve_keys_via_agent(
        &self,
        fp_to_info: &HashMap<String, (String, String)>,
    ) -> Result<HashMap<String, (Bytes, String, String)>> {
        use ssh_key::HashAlg;

        let agent_socket = onepassword_agent_socket();
        let Some(agent_path) = agent_socket else {
            debug!("1Password agent socket not found, skipping fast path");
            return Ok(HashMap::new());
        };

        // Connect to 1Password agent and send REQUEST_IDENTITIES
        let upstream = Upstream::new(&agent_path);
        let mut conn = match upstream.connect().await {
            Ok(conn) => conn,
            Err(e) => {
                debug!(error = %e, "Cannot connect to 1Password agent, skipping fast path");
                return Ok(HashMap::new());
            }
        };

        let request = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let response = match conn.send_receive(&request).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!(error = %e, "1Password agent request failed, skipping fast path");
                return Ok(HashMap::new());
            }
        };

        if response.msg_type != MessageType::IdentitiesAnswer {
            return Ok(HashMap::new());
        }

        let identities = response.parse_identities().unwrap_or_default();
        let mut result = HashMap::new();

        for identity in identities {
            if let Some(pub_key) = &identity.public_key {
                let fp = pub_key.fingerprint(HashAlg::Sha256);
                let fp_str = fp.to_string();

                if let Some((item_id, title)) = fp_to_info.get(&fp_str) {
                    result.insert(
                        fp_str,
                        (identity.key_blob.clone(), item_id.clone(), title.clone()),
                    );
                }
            }
        }

        debug!(
            resolved = result.len(),
            total = fp_to_info.len(),
            "Resolved keys via 1Password agent"
        );

        Ok(result)
    }

    // ---- Upstream forwarding ----

    /// Forward a request to the upstream agent.
    /// Returns failure if no upstream is configured.
    async fn forward_to_upstream(&self, request: AgentMessage) -> Result<AgentMessage> {
        match &self.upstream {
            Some(upstream) => {
                let mut conn = upstream.connect().await?;
                conn.send_receive(&request).await
            }
            None => {
                debug!("No upstream agent configured, returning failure");
                Ok(AgentMessage::failure())
            }
        }
    }
}

/// Get the platform-specific 1Password SSH agent socket path.
///
/// Returns None if the socket doesn't exist.
fn onepassword_agent_socket() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;

    #[cfg(target_os = "macos")]
    let path = home.join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock");

    #[cfg(target_os = "linux")]
    let path = home.join(".1password/agent.sock");

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let path = {
        let _ = home;
        return None;
    };

    if path.exists() { Some(path) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warden_proxy_creation_no_backends() {
        let proxy = WardProxy::new(None, FilterEvaluator::default(), vec![]);
        assert_eq!(proxy.socket_path, "");
        assert!(proxy.upstream.is_none());
        assert!(proxy.op_sources.is_empty());
    }

    #[test]
    fn test_warden_proxy_with_socket_path() {
        let proxy = WardProxy::new(None, FilterEvaluator::default(), vec![])
            .with_socket_path("/tmp/ward.sock");
        assert_eq!(proxy.socket_path, "/tmp/ward.sock");
    }

    #[test]
    fn test_warden_proxy_with_upstream() {
        let upstream = Upstream::new("/tmp/agent.sock");
        let proxy = WardProxy::new(Some(upstream), FilterEvaluator::default(), vec![]);
        assert!(proxy.upstream.is_some());
    }

    #[test]
    fn test_warden_proxy_with_op_sources() {
        let sources = vec![
            OpSourceConfig {
                vault: None,
                item: None,
            },
            OpSourceConfig {
                vault: Some("Private".to_string()),
                item: None,
            },
            OpSourceConfig {
                vault: Some("Work".to_string()),
                item: Some("deploy-key".to_string()),
            },
        ];
        let proxy = WardProxy::new(None, FilterEvaluator::default(), sources);
        assert_eq!(proxy.op_sources.len(), 3);
        assert!(proxy.op_sources[0].vault.is_none());
        assert_eq!(proxy.op_sources[1].vault.as_deref(), Some("Private"));
        assert_eq!(proxy.op_sources[2].item.as_deref(), Some("deploy-key"));
    }

    #[test]
    fn test_signing_backend_variants() {
        let agent = SigningBackend::Agent;
        let op = SigningBackend::Op {
            item_id: "abc123".to_string(),
        };
        // Verify Debug trait works
        assert!(format!("{:?}", agent).contains("Agent"));
        assert!(format!("{:?}", op).contains("abc123"));
    }

    #[test]
    fn test_op_source_config_construction() {
        // Corresponds to op:// (no filter)
        let cfg = OpSourceConfig {
            vault: None,
            item: None,
        };
        assert!(cfg.vault.is_none());
        assert!(cfg.item.is_none());
    }

    #[tokio::test]
    async fn test_op_state_lazy_init_no_sources() {
        let proxy = WardProxy::new(None, FilterEvaluator::default(), vec![]);
        proxy.ensure_op_initialized().await;

        let state = proxy.op_state.read().await;
        match &*state {
            OpState::Ready { keys } => assert!(keys.is_empty()),
            _ => panic!("Expected OpState::Ready with empty keys"),
        }
    }

    #[tokio::test]
    async fn test_forward_to_upstream_no_upstream() {
        let proxy = WardProxy::new(None, FilterEvaluator::default(), vec![]);
        let request = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let response = proxy.forward_to_upstream(request).await.unwrap();
        assert_eq!(response.msg_type, MessageType::Failure);
    }
}
