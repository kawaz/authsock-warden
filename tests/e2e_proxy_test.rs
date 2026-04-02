//! E2E integration tests for the agent proxy mode.
//!
//! These tests verify the full pipeline:
//! mock SSH agent <-> Proxy <-> test client
//!
//! A mock SSH agent is implemented as a simple tokio UnixListener that
//! responds to the SSH agent protocol (REQUEST_IDENTITIES, SIGN_REQUEST).

use authsock_warden::agent::{Proxy, Upstream};
use authsock_warden::filter::FilterEvaluator;
use authsock_warden::protocol::{AgentCodec, AgentMessage, Identity, MessageType};
use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::{UnixListener, UnixStream};

/// Build a list of test identities with distinct key blobs and comments.
fn test_identities() -> Vec<Identity> {
    // Use valid-looking (but fake) key blobs that are distinguishable.
    // These are not real SSH keys, but they have enough structure for
    // the protocol round-trip.
    vec![
        Identity::new(
            Bytes::from_static(b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x01"),
            "work@laptop".to_string(),
        ),
        Identity::new(
            Bytes::from_static(b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x02"),
            "personal@desktop".to_string(),
        ),
        Identity::new(
            Bytes::from_static(b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x03"),
            "deploy@ci".to_string(),
        ),
    ]
}

/// Run a mock SSH agent that handles REQUEST_IDENTITIES and SIGN_REQUEST.
///
/// - REQUEST_IDENTITIES: returns the provided identities
/// - SIGN_REQUEST: returns a fixed SUCCESS-style sign response
/// - Other messages: returns FAILURE
async fn mock_agent(listener: UnixListener, identities: Vec<Identity>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };

        let identities = identities.clone();
        tokio::spawn(async move {
            handle_mock_connection(stream, &identities).await;
        });
    }
}

async fn handle_mock_connection(stream: UnixStream, identities: &[Identity]) {
    let (mut reader, mut writer) = stream.into_split();

    loop {
        let request = match AgentCodec::read(&mut reader).await {
            Ok(Some(msg)) => msg,
            _ => break,
        };

        let response = match request.msg_type {
            MessageType::RequestIdentities => AgentMessage::build_identities_answer(identities),
            MessageType::SignRequest => {
                // Build a fake SSH_AGENT_SIGN_RESPONSE (type 14).
                // Real format: string signature_blob
                // We return a minimal valid response with a dummy signature.
                let mut payload = BytesMut::new();
                let fake_sig = b"fake-signature-data";
                payload.put_u32(fake_sig.len() as u32);
                payload.put_slice(fake_sig);
                AgentMessage::new(MessageType::SignResponse, payload.freeze())
            }
            _ => AgentMessage::failure(),
        };

        if AgentCodec::write(&mut writer, &response).await.is_err() {
            break;
        }
    }
}

/// Build a raw SIGN_REQUEST message for a given key blob.
fn build_sign_request(key_blob: &Bytes) -> AgentMessage {
    let mut payload = BytesMut::new();
    // key blob (string)
    payload.put_u32(key_blob.len() as u32);
    payload.put_slice(key_blob);
    // data to sign (string) — dummy data
    let data = b"data-to-sign";
    payload.put_u32(data.len() as u32);
    payload.put_slice(data);
    // flags (uint32)
    payload.put_u32(0);

    AgentMessage::new(MessageType::SignRequest, payload.freeze())
}

/// Helper: start mock agent, create Proxy, return (proxy, mock_agent_task).
///
/// The proxy is configured with the given filter.
/// The mock agent serves the identities from `test_identities()`.
async fn setup_proxy(filter: FilterEvaluator) -> (Arc<Proxy>, tokio::task::JoinHandle<()>) {
    let dir = tempdir().unwrap();
    // Leak the tempdir so it lives for the entire test (cleaned up on process exit).
    let dir = Box::leak(Box::new(dir));
    let mock_sock = dir.path().join("mock_agent.sock");

    let listener = UnixListener::bind(&mock_sock).unwrap();
    let identities = test_identities();
    let mock_task = tokio::spawn(async move {
        mock_agent(listener, identities).await;
    });

    let upstream = Upstream::new(&mock_sock);
    let proxy = Arc::new(Proxy::new(upstream, filter).with_socket_path("test-proxy"));

    (proxy, mock_task)
}

/// Helper: send a REQUEST_IDENTITIES through the proxy and return parsed identities.
async fn request_identities_via_proxy(proxy: &Arc<Proxy>) -> Vec<Identity> {
    let dir = tempdir().unwrap();
    let warden_sock = dir.path().join("warden.sock");

    let listener = UnixListener::bind(&warden_sock).unwrap();

    let proxy_clone = Arc::clone(proxy);
    let accept_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        proxy_clone.handle_client(stream).await.ok();
    });

    let mut client = UnixStream::connect(&warden_sock).await.unwrap();
    let (mut reader, mut writer) = client.split();

    let request = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
    AgentCodec::write(&mut writer, &request).await.unwrap();

    let response = AgentCodec::read(&mut reader).await.unwrap().unwrap();
    assert_eq!(response.msg_type, MessageType::IdentitiesAnswer);

    // Drop the client to let the proxy task finish
    drop(writer);
    drop(reader);
    drop(client);
    accept_task.abort();

    response.parse_identities().unwrap()
}

/// Helper: send a SIGN_REQUEST through the proxy and return the response.
async fn sign_via_proxy(proxy: &Arc<Proxy>, key_blob: &Bytes) -> AgentMessage {
    let dir = tempdir().unwrap();
    let warden_sock = dir.path().join("warden.sock");

    let listener = UnixListener::bind(&warden_sock).unwrap();

    let proxy_clone = Arc::clone(proxy);
    let accept_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        proxy_clone.handle_client(stream).await.ok();
    });

    let mut client = UnixStream::connect(&warden_sock).await.unwrap();
    let (mut reader, mut writer) = client.split();

    // First, send REQUEST_IDENTITIES to populate the allowed keys cache
    let id_request = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
    AgentCodec::write(&mut writer, &id_request).await.unwrap();
    let _id_response = AgentCodec::read(&mut reader).await.unwrap().unwrap();

    // Now send the SIGN_REQUEST
    let sign_request = build_sign_request(key_blob);
    AgentCodec::write(&mut writer, &sign_request).await.unwrap();

    let response = AgentCodec::read(&mut reader).await.unwrap().unwrap();

    drop(writer);
    drop(reader);
    drop(client);
    accept_task.abort();

    response
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

/// Verify that all mock agent identities pass through the proxy unfiltered
/// when no filter rules are configured.
#[tokio::test]
async fn test_proxy_passes_through_identities() {
    let filter = FilterEvaluator::default(); // empty = allow all
    let (proxy, mock_task) = setup_proxy(filter).await;

    let identities = request_identities_via_proxy(&proxy).await;

    assert_eq!(identities.len(), 3);
    let comments: Vec<&str> = identities.iter().map(|i| i.comment.as_str()).collect();
    assert!(comments.contains(&"work@laptop"));
    assert!(comments.contains(&"personal@desktop"));
    assert!(comments.contains(&"deploy@ci"));

    mock_task.abort();
}

/// Verify that a comment filter restricts which keys are visible.
#[tokio::test]
async fn test_proxy_filters_by_comment() {
    // Only allow keys whose comment matches "work*"
    let filter = FilterEvaluator::parse(&[vec!["comment=work*".to_string()]]).unwrap();
    let (proxy, mock_task) = setup_proxy(filter).await;

    let identities = request_identities_via_proxy(&proxy).await;

    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment, "work@laptop");

    mock_task.abort();
}

/// Verify that a SIGN_REQUEST for an allowed key is forwarded to the
/// upstream mock agent and returns a sign response.
#[tokio::test]
async fn test_proxy_sign_request_allowed() {
    let filter = FilterEvaluator::default(); // allow all
    let (proxy, mock_task) = setup_proxy(filter).await;

    let key_blob = test_identities()[0].key_blob.clone(); // work@laptop
    let response = sign_via_proxy(&proxy, &key_blob).await;

    assert_eq!(
        response.msg_type,
        MessageType::SignResponse,
        "Expected SignResponse for allowed key, got {:?}",
        response.msg_type
    );

    mock_task.abort();
}

/// Verify that a SIGN_REQUEST for a key rejected by the filter returns FAILURE.
#[tokio::test]
async fn test_proxy_sign_request_denied() {
    // Only allow "work*" comments — the other keys should be denied
    let filter = FilterEvaluator::parse(&[vec!["comment=work*".to_string()]]).unwrap();
    let (proxy, mock_task) = setup_proxy(filter).await;

    // Use the "personal@desktop" key which does not match the filter
    let key_blob = test_identities()[1].key_blob.clone();
    let response = sign_via_proxy(&proxy, &key_blob).await;

    assert_eq!(
        response.msg_type,
        MessageType::Failure,
        "Expected Failure for denied key, got {:?}",
        response.msg_type
    );

    mock_task.abort();
}
