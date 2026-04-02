//! Policy engine for combining filter and process-based access control

use crate::config::KeyConfig;
use crate::filter::FilterEvaluator;
use crate::policy::process::{ProcessChain, get_peer_pid};
use crate::protocol::Identity;
use std::os::unix::io::RawFd;
use tracing::{debug, trace, warn};

/// Decision from the policy engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the operation
    Allow,
    /// Deny the operation with a reason
    Deny(String),
}

/// Policy engine that combines filter rules and process-based access control
pub struct PolicyEngine {
    /// Filter evaluator for key visibility
    filter: FilterEvaluator,
    /// Per-key policy configurations
    key_policies: Vec<KeyConfig>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(filter: FilterEvaluator, key_policies: Vec<KeyConfig>) -> Self {
        Self {
            filter,
            key_policies,
        }
    }

    /// Create a policy engine with only filter rules (no process policies)
    pub fn filter_only(filter: FilterEvaluator) -> Self {
        Self {
            filter,
            key_policies: Vec::new(),
        }
    }

    /// Check if an identity should be visible (for REQUEST_IDENTITIES)
    ///
    /// Applies filter rules and optionally process-based restrictions.
    pub fn check_identity_visible(
        &self,
        identity: &Identity,
        client_fd: Option<RawFd>,
        socket_allowed_processes: &[String],
    ) -> bool {
        // First check filter
        if !self.filter.matches(identity) {
            return false;
        }

        // Check socket-level process restriction
        if !socket_allowed_processes.is_empty()
            && let Some(chain) = self.get_process_chain(client_fd)
            && !chain.matches_any(socket_allowed_processes)
        {
            trace!(
                processes = ?chain.process_names(),
                "Identity hidden: socket process restriction"
            );
            return false;
        }

        // Check key-level process restriction
        if let Some(key_policy) = self.find_key_policy(identity)
            && !key_policy.allowed_processes.is_empty()
            && let Some(chain) = self.get_process_chain(client_fd)
        {
            let effective = self.effective_allowed_processes(
                &key_policy.allowed_processes,
                socket_allowed_processes,
            );
            if !chain.matches_any(&effective) {
                trace!(
                    processes = ?chain.process_names(),
                    "Identity hidden: key process restriction"
                );
                return false;
            }
        }

        true
    }

    /// Check if a sign request should be allowed
    pub fn check_sign_request(
        &self,
        identity: &Identity,
        client_fd: Option<RawFd>,
        socket_allowed_processes: &[String],
    ) -> PolicyDecision {
        // Filter check
        if !self.filter.matches(identity) {
            return PolicyDecision::Deny("key not allowed by filter".to_string());
        }

        // Process check (socket-level)
        if !socket_allowed_processes.is_empty() {
            match self.get_process_chain(client_fd) {
                Some(chain) => {
                    if !chain.matches_any(socket_allowed_processes) {
                        let names = chain.process_names().join(" → ");
                        return PolicyDecision::Deny(format!(
                            "process chain [{}] not in socket allowed list",
                            names
                        ));
                    }
                }
                None => {
                    debug!("Could not determine client process, allowing by default");
                }
            }
        }

        // Process check (key-level, intersected with socket-level)
        if let Some(key_policy) = self.find_key_policy(identity)
            && !key_policy.allowed_processes.is_empty()
        {
            match self.get_process_chain(client_fd) {
                Some(chain) => {
                    let effective = self.effective_allowed_processes(
                        &key_policy.allowed_processes,
                        socket_allowed_processes,
                    );
                    if !chain.matches_any(&effective) {
                        let names = chain.process_names().join(" → ");
                        return PolicyDecision::Deny(format!(
                            "process chain [{}] not in key allowed list",
                            names
                        ));
                    }
                }
                None => {
                    debug!("Could not determine client process for key policy check");
                }
            }
        }

        PolicyDecision::Allow
    }

    /// Get the filter evaluator
    pub fn filter(&self) -> &FilterEvaluator {
        &self.filter
    }

    /// Compute effective allowed processes: key ∩ socket (most restrictive wins)
    fn effective_allowed_processes(
        &self,
        key_processes: &[String],
        socket_processes: &[String],
    ) -> Vec<String> {
        if socket_processes.is_empty() {
            return key_processes.to_vec();
        }
        if key_processes.is_empty() {
            return socket_processes.to_vec();
        }
        // Intersection
        key_processes
            .iter()
            .filter(|p| socket_processes.contains(p))
            .cloned()
            .collect()
    }

    /// Find the key policy for an identity (by public key string match)
    fn find_key_policy(&self, identity: &Identity) -> Option<&KeyConfig> {
        let openssh = identity.to_openssh()?;
        self.key_policies.iter().find(|kp| {
            // Compare by stripping comments from both sides
            let kp_key = kp
                .public_key
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            let id_key = openssh
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            kp_key == id_key
        })
    }

    fn get_process_chain(&self, client_fd: Option<RawFd>) -> Option<ProcessChain> {
        let fd = client_fd?;
        let pid = get_peer_pid(fd);
        if pid.is_none() {
            warn!("Failed to get peer PID from socket fd {}", fd);
        }
        pid.map(ProcessChain::from_pid)
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
    fn test_policy_engine_filter_only() {
        let filter = FilterEvaluator::default(); // matches all
        let engine = PolicyEngine::filter_only(filter);

        let decision = engine.check_sign_request(&make_identity("any"), None, &[]);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_engine_with_filter() {
        let filter = FilterEvaluator::parse(&[vec!["comment=*@work*".to_string()]]).unwrap();
        let engine = PolicyEngine::filter_only(filter);

        let decision = engine.check_sign_request(&make_identity("user@work"), None, &[]);
        assert_eq!(decision, PolicyDecision::Allow);

        let decision = engine.check_sign_request(&make_identity("user@home"), None, &[]);
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_effective_allowed_processes_intersection() {
        let engine = PolicyEngine::filter_only(FilterEvaluator::default());

        // Both non-empty: intersection
        let effective = engine.effective_allowed_processes(
            &["ssh".to_string(), "git".to_string(), "jj".to_string()],
            &["git".to_string(), "svn".to_string()],
        );
        assert_eq!(effective, vec!["git"]);

        // Socket empty: key wins
        let effective =
            engine.effective_allowed_processes(&["ssh".to_string(), "git".to_string()], &[]);
        assert_eq!(effective, vec!["ssh", "git"]);

        // Key empty: socket wins
        let effective = engine.effective_allowed_processes(&[], &["git".to_string()]);
        assert_eq!(effective, vec!["git"]);
    }

    #[test]
    fn test_identity_visible_no_restrictions() {
        let filter = FilterEvaluator::default();
        let engine = PolicyEngine::filter_only(filter);

        assert!(engine.check_identity_visible(&make_identity("any"), None, &[]));
    }

    #[test]
    fn test_identity_visible_filter_blocks() {
        let filter = FilterEvaluator::parse(&[vec!["comment=*@work*".to_string()]]).unwrap();
        let engine = PolicyEngine::filter_only(filter);

        assert!(engine.check_identity_visible(&make_identity("user@work"), None, &[]));
        assert!(!engine.check_identity_visible(&make_identity("user@home"), None, &[]));
    }
}
