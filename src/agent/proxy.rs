//! SSH Agent proxy core logic
//!
//! This module implements the core proxy functionality that filters
//! SSH agent requests between a client and the upstream agent.

use crate::error::Result;
use crate::filter::FilterEvaluator;
use crate::policy::process::{ProcessChain, get_peer_pid};
use crate::protocol::{AgentCodec, AgentMessage, Identity, MessageType};
use bytes::Bytes;
use std::collections::HashSet;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use super::Upstream;

/// SSH Agent proxy that filters requests
pub struct Proxy {
    /// Upstream agent connection manager
    upstream: Arc<Upstream>,
    /// Filter evaluator for key filtering
    filter: Arc<FilterEvaluator>,
    /// Socket path for identification
    socket_path: String,
    /// Connection counter for client IDs
    connection_counter: AtomicU64,
    /// Socket-level cache for allowed keys (shared across all connections)
    allowed_keys_cache: Arc<RwLock<HashSet<Bytes>>>,
}

impl Proxy {
    /// Create a new proxy
    pub fn new(upstream: Upstream, filter: FilterEvaluator) -> Self {
        Self {
            upstream: Arc::new(upstream),
            filter: Arc::new(filter),
            socket_path: String::new(),
            connection_counter: AtomicU64::new(0),
            allowed_keys_cache: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a new proxy with Arc-wrapped components
    pub fn new_shared(upstream: Arc<Upstream>, filter: Arc<FilterEvaluator>) -> Self {
        Self {
            upstream,
            filter,
            socket_path: String::new(),
            connection_counter: AtomicU64::new(0),
            allowed_keys_cache: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Set the socket path for identification
    pub fn with_socket_path(mut self, path: impl Into<String>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Get a reference to the upstream
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Get a reference to the filter
    pub fn filter(&self) -> &FilterEvaluator {
        &self.filter
    }

    /// Handle a client connection
    pub async fn handle_client(&self, mut client_stream: UnixStream) -> Result<()> {
        let client_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);
        let process_chain = get_peer_pid(client_stream.as_raw_fd()).map(ProcessChain::from_pid);
        debug!(
            socket = %self.socket_path,
            client_id = client_id,
            "Client connected"
        );

        let result = self
            .handle_client_inner(&mut client_stream, process_chain.as_ref())
            .await;

        debug!(
            socket = %self.socket_path,
            client_id = client_id,
            "Client disconnected"
        );

        result
    }

    async fn handle_client_inner(
        &self,
        client_stream: &mut UnixStream,
        process_chain: Option<&ProcessChain>,
    ) -> Result<()> {
        let (mut client_reader, mut client_writer) = client_stream.split();

        loop {
            let request = match AgentCodec::read(&mut client_reader).await? {
                Some(msg) => msg,
                None => {
                    trace!("Client disconnected");
                    break;
                }
            };

            trace!(msg_type = ?request.msg_type, "Received request from client");

            let response = self.process_request(request, process_chain).await?;

            AgentCodec::write(&mut client_writer, &response).await?;
        }

        Ok(())
    }

    async fn process_request(
        &self,
        request: AgentMessage,
        process_chain: Option<&ProcessChain>,
    ) -> Result<AgentMessage> {
        match request.msg_type {
            MessageType::RequestIdentities => {
                self.handle_request_identities(request, process_chain).await
            }
            MessageType::SignRequest => self.handle_sign_request(request, process_chain).await,
            _ => self.forward_to_upstream(request).await,
        }
    }

    /// Handle SSH_AGENTC_REQUEST_IDENTITIES (11)
    ///
    /// Forwards the request to upstream, then filters the response
    /// to only include keys that match the filter rules.
    async fn handle_request_identities(
        &self,
        request: AgentMessage,
        process_chain: Option<&ProcessChain>,
    ) -> Result<AgentMessage> {
        info!("REQUEST_IDENTITIES received");

        let response = self.forward_to_upstream(request).await?;

        if response.msg_type != MessageType::IdentitiesAnswer {
            warn!(msg_type = ?response.msg_type, "Unexpected response type for REQUEST_IDENTITIES");
            return Ok(response);
        }

        let identities = match response.parse_identities() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(error = %e, "Failed to parse identities from upstream");
                return Ok(AgentMessage::failure());
            }
        };

        let original_count = identities.len();
        debug!(count = original_count, "Received identities from upstream");

        let filtered: Vec<Identity> = identities
            .into_iter()
            .filter(|id| self.filter.matches(id))
            .collect();

        let filtered_count = filtered.len();

        for identity in &filtered {
            info!(
                key = %describe_key(identity),
                comment = %identity.comment,
                "REQUEST_IDENTITIES exposing key"
            );
        }

        info!(
            original = original_count,
            filtered = filtered_count,
            "REQUEST_IDENTITIES response"
        );

        if let Some(chain) = process_chain {
            if let Ok(json) = serde_json::to_string(&serde_json::json!({
                "event": "REQUEST_IDENTITIES",
                "socket": &self.socket_path,
                "original": original_count,
                "filtered": filtered_count,
                "keys": filtered.iter().map(|id| {
                    serde_json::json!({
                        "key": describe_key(id),
                        "comment": &id.comment,
                    })
                }).collect::<Vec<_>>(),
                "process_chain": chain,
            })) {
                info!(target: "authsock_warden::audit", "{}", json);
            }
        }

        // Update socket-level shared allowed keys cache
        {
            let mut cache = self.allowed_keys_cache.write().await;
            cache.clear();
            for identity in &filtered {
                cache.insert(identity.key_blob.clone());
            }
        }

        Ok(AgentMessage::build_identities_answer(&filtered))
    }

    /// Handle SSH_AGENTC_SIGN_REQUEST (13)
    ///
    /// Only allows signing with keys that are in the allowed set
    /// (i.e., keys that passed the filter in a previous REQUEST_IDENTITIES),
    /// or keys that match the filter directly.
    async fn handle_sign_request(
        &self,
        request: AgentMessage,
        process_chain: Option<&ProcessChain>,
    ) -> Result<AgentMessage> {
        let key_blob = match request.parse_sign_request_key() {
            Ok(blob) => blob,
            Err(e) => {
                warn!(error = %e, "Failed to parse sign request");
                return Ok(AgentMessage::failure());
            }
        };

        let identity = Identity::new(key_blob.clone(), String::new());
        let key_desc = describe_key(&identity);

        info!(key = %key_desc, "SIGN_REQUEST received");

        // Check cache first, then filter directly
        let is_allowed = {
            let cache = self.allowed_keys_cache.read().await;
            cache.contains(key_blob.as_ref())
        } || self.filter.matches(&identity);

        if !is_allowed {
            info!(key = %key_desc, "SIGN_REQUEST denied by filter");
            if let Some(chain) = process_chain {
                if let Ok(json) = serde_json::to_string(&serde_json::json!({
                    "event": "SIGN_REQUEST",
                    "socket": &self.socket_path,
                    "key": &key_desc,
                    "result": "denied",
                    "backend": "agent",
                    "process_chain": chain,
                })) {
                    info!(target: "authsock_warden::audit", "{}", json);
                }
            }
            return Ok(AgentMessage::failure());
        }

        info!(key = %key_desc, backend = "agent", "Signing with upstream agent");

        let result = self.forward_to_upstream(request).await;

        let result_str = match &result {
            Ok(resp) if resp.msg_type == MessageType::SignResponse => {
                info!(key = %key_desc, "SIGN_REQUEST success");
                "success"
            }
            Ok(resp) => {
                info!(key = %key_desc, response = ?resp.msg_type, "SIGN_REQUEST failed");
                "failed"
            }
            Err(e) => {
                info!(key = %key_desc, error = %e, "SIGN_REQUEST error");
                "error"
            }
        };

        if let Some(chain) = process_chain {
            if let Ok(json) = serde_json::to_string(&serde_json::json!({
                "event": "SIGN_REQUEST",
                "socket": &self.socket_path,
                "key": &key_desc,
                "result": result_str,
                "backend": "agent",
                "process_chain": chain,
            })) {
                info!(target: "authsock_warden::audit", "{}", json);
            }
        }

        result
    }

    async fn forward_to_upstream(&self, request: AgentMessage) -> Result<AgentMessage> {
        let mut conn = self.upstream.connect().await?;
        conn.send_receive(&request).await
    }
}

/// Build a short human-readable description of a key for log output.
///
/// Format: `<key_type> <fingerprint_prefix> (<comment>)` or similar,
/// depending on available information. Never includes private key material.
fn describe_key(identity: &Identity) -> String {
    let key_type = identity.key_type().unwrap_or_else(|| "unknown".into());
    let fp = identity
        .fingerprint()
        .map(|f| {
            let s = f.to_string();
            // Show first 12 chars of the fingerprint hash (after "SHA256:" prefix)
            if let Some(hash) = s.strip_prefix("SHA256:") {
                format!("SHA256:{}...", &hash[..hash.len().min(12)])
            } else {
                s
            }
        })
        .unwrap_or_else(|| "unknown-fp".into());
    if identity.comment.is_empty() {
        format!("{} {}", key_type, fp)
    } else {
        format!("{} {} ({})", key_type, fp, identity.comment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let upstream = Upstream::new("/tmp/test.sock");
        let filter = FilterEvaluator::default();
        let proxy = Proxy::new(upstream, filter);
        assert_eq!(proxy.socket_path, "");
    }

    #[test]
    fn test_proxy_with_socket_path() {
        let upstream = Upstream::new("/tmp/test.sock");
        let filter = FilterEvaluator::default();
        let proxy = Proxy::new(upstream, filter).with_socket_path("/tmp/my.sock");
        assert_eq!(proxy.socket_path, "/tmp/my.sock");
    }
}
