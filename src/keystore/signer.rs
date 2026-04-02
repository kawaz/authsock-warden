//! Local signing using ssh-key crate
//!
//! Handles parsing of private keys from various PEM formats and signing
//! data using the SSH agent protocol's SignRequest format.

use crate::error::{Error, Result};
use crate::protocol::{AgentMessage, MessageType};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use signature::Signer;
use ssh_key::PrivateKey;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
use tracing::debug;

/// Sign data from an SSH agent SignRequest using a private key.
///
/// Parses the SignRequest payload to extract the data to sign,
/// then produces a SignResponse with the signature.
pub fn sign_with_key(
    private_key: &PrivateKey,
    sign_request_payload: &Bytes,
) -> Result<AgentMessage> {
    // Parse SignRequest payload: key_blob (string) + data (string) + flags (u32)
    let mut buf = &sign_request_payload[..];

    // Skip key_blob
    if buf.remaining() < 4 {
        return Err(Error::Protocol("SignRequest too short".to_string()));
    }
    let key_len = buf.get_u32() as usize;
    if buf.remaining() < key_len {
        return Err(Error::Protocol(
            "SignRequest key blob truncated".to_string(),
        ));
    }
    buf.advance(key_len);

    // Read data to sign
    if buf.remaining() < 4 {
        return Err(Error::Protocol(
            "SignRequest data length missing".to_string(),
        ));
    }
    let data_len = buf.get_u32() as usize;
    if buf.remaining() < data_len {
        return Err(Error::Protocol("SignRequest data truncated".to_string()));
    }
    let data = &buf[..data_len];
    buf.advance(data_len);

    // Read flags (optional)
    // SSH agent protocol flags for RSA key type selection:
    //   SSH_AGENT_RSA_SHA2_256 = 0x02
    //   SSH_AGENT_RSA_SHA2_512 = 0x04
    // Ed25519 keys ignore flags (algorithm is fixed).
    // TODO: RSA SHA2 flags are not yet supported; RSA keys should use agent proxy mode.
    let flags = if buf.remaining() >= 4 {
        buf.get_u32()
    } else {
        0
    };

    if flags != 0 {
        debug!(flags = flags, "Sign request flags present");
    }

    debug!(data_len = data.len(), flags = flags, "Signing data locally");

    // Sign using the ssh-key crate's Signer trait
    let signature: ssh_key::Signature = private_key
        .try_sign(data)
        .map_err(|e| Error::Protocol(format!("Signing failed: {}", e)))?;

    // Encode signature to SSH wire format: string(algorithm) + string(sig_data)
    let sig_blob: Vec<u8> = signature.try_into().map_err(|e: ssh_key::Error| {
        Error::Protocol(format!("Failed to encode signature: {}", e))
    })?;

    // Build SignResponse: u32(sig_blob_len) + sig_blob
    let mut payload = BytesMut::new();
    payload.put_u32(sig_blob.len() as u32);
    payload.put_slice(&sig_blob);

    Ok(AgentMessage::new(
        MessageType::SignResponse,
        payload.freeze(),
    ))
}

/// Parse a PEM private key string into an ssh-key PrivateKey.
///
/// Supports:
/// - OpenSSH format ("BEGIN OPENSSH PRIVATE KEY") — any key type supported by ssh-key crate
/// - PKCS#8 format ("BEGIN PRIVATE KEY") — **Ed25519 only** (as returned by 1Password)
///
/// PKCS#8 RSA or ECDSA keys are not supported by the PKCS#8 path.
/// For those key types, use OpenSSH format or agent proxy mode.
pub fn parse_private_key(pem: &str) -> Result<PrivateKey> {
    // Try OpenSSH format first (supports all key types)
    if let Ok(key) = PrivateKey::from_openssh(pem) {
        return Ok(key);
    }

    // Try PKCS#8 PEM format (1Password returns "BEGIN PRIVATE KEY")
    // Only Ed25519 is supported via this path.
    if pem.contains("BEGIN PRIVATE KEY") {
        return parse_pkcs8_ed25519(pem);
    }

    Err(Error::KeyStore(
        "Failed to parse private key: unsupported format. \
         Expected OpenSSH (\"BEGIN OPENSSH PRIVATE KEY\") or \
         PKCS#8 Ed25519 (\"BEGIN PRIVATE KEY\")"
            .to_string(),
    ))
}

/// Parse a PKCS#8-encoded Ed25519 private key PEM.
///
/// 1Password returns Ed25519 keys in PKCS#8 DER format wrapped in PEM.
/// The structure is:
///   SEQUENCE {
///     INTEGER 0                           -- version
///     SEQUENCE { OID 1.3.101.112 }        -- Ed25519 algorithm
///     OCTET STRING {
///       OCTET STRING { 32 bytes seed }    -- private key seed
///     }
///     [1] { BIT STRING { 32 bytes pubkey } }  -- optional public key
///   }
///
/// We extract the 32-byte seed and construct an Ed25519Keypair from it.
fn parse_pkcs8_ed25519(pem: &str) -> Result<PrivateKey> {
    // Strip PEM headers and decode base64
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| Error::KeyStore(format!("Failed to base64 decode PKCS#8 key: {}", e)))?;

    // Extract Ed25519 seed from PKCS#8 DER
    let seed = extract_ed25519_seed_from_pkcs8(&der)?;

    // Construct keypair from seed (derives public key automatically)
    let keypair = Ed25519Keypair::from_seed(&seed);
    let private_key = PrivateKey::from(keypair);

    Ok(private_key)
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 DER blob.
///
/// The Ed25519 OID is 1.3.101.112 = [06 03 2b 65 70].
/// The seed is wrapped in an OCTET STRING inside another OCTET STRING.
///
/// We use a simple pattern-matching approach rather than a full ASN.1 parser,
/// since the PKCS#8 structure for Ed25519 is fixed and well-known.
fn extract_ed25519_seed_from_pkcs8(der: &[u8]) -> Result<[u8; 32]> {
    // Ed25519 OID bytes: 06 03 2b 65 70
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    // Find the OID in the DER
    let oid_pos = der
        .windows(ED25519_OID.len())
        .position(|w| w == ED25519_OID)
        .ok_or_else(|| Error::KeyStore("PKCS#8 key does not contain Ed25519 OID".to_string()))?;

    // After the algorithm identifier SEQUENCE, we expect:
    //   OCTET STRING (tag 0x04) containing:
    //     OCTET STRING (tag 0x04) containing the 32-byte seed
    //
    // Navigate past the OID and its enclosing SEQUENCE
    let after_oid = oid_pos + ED25519_OID.len();
    let rest = &der[after_oid..];

    // Find the first OCTET STRING (outer wrapper for private key)
    // It may be preceded by closing bytes of the algorithm SEQUENCE
    let outer_pos = rest.iter().position(|&b| b == 0x04).ok_or_else(|| {
        Error::KeyStore("PKCS#8: could not find private key OCTET STRING".to_string())
    })?;

    let outer = &rest[outer_pos..];
    if outer.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: outer OCTET STRING too short".to_string(),
        ));
    }

    // Parse outer OCTET STRING length
    let outer_len = outer[1] as usize;
    let outer_content = outer
        .get(2..2 + outer_len)
        .ok_or_else(|| Error::KeyStore("PKCS#8: outer OCTET STRING truncated".to_string()))?;

    // The inner content should start with another OCTET STRING tag (0x04)
    if outer_content.first() != Some(&0x04) {
        return Err(Error::KeyStore(
            "PKCS#8: expected inner OCTET STRING for Ed25519 seed".to_string(),
        ));
    }

    if outer_content.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: inner OCTET STRING too short".to_string(),
        ));
    }

    let inner_len = outer_content[1] as usize;
    if inner_len != Ed25519PrivateKey::BYTE_SIZE {
        return Err(Error::KeyStore(format!(
            "PKCS#8: Ed25519 seed has unexpected length {} (expected {})",
            inner_len,
            Ed25519PrivateKey::BYTE_SIZE
        )));
    }

    let seed_bytes = outer_content
        .get(2..2 + inner_len)
        .ok_or_else(|| Error::KeyStore("PKCS#8: Ed25519 seed data truncated".to_string()))?;

    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_bytes);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::Algorithm;

    // The test PEM from the 1Password output in the spec
    const OP_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n";

    // Corresponding public key
    const OP_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ";

    #[test]
    fn parse_pkcs8_ed25519_from_1password() {
        let key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn parsed_key_matches_expected_public_key() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();
        let public_key = private_key.public_key();
        let public_key_str = public_key.to_openssh().unwrap();
        assert_eq!(public_key_str, OP_PUBLIC_KEY);
    }

    #[test]
    fn parse_private_key_rejects_garbage() {
        let result = parse_private_key("not a key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_private_key_rejects_invalid_pkcs8() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n";
        let result = parse_private_key(pem);
        assert!(result.is_err());
    }

    #[test]
    fn extract_ed25519_seed_rejects_non_ed25519_oid() {
        // RSA OID instead of Ed25519
        let der = vec![0x30, 0x10, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86];
        let result = extract_ed25519_seed_from_pkcs8(&der);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ed25519 OID"));
    }

    #[test]
    fn sign_with_key_produces_valid_sign_response() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();
        let public_key = private_key.public_key();

        // Build a minimal SignRequest payload
        let key_blob = public_key.to_bytes().unwrap();
        let data_to_sign = b"test data to sign";

        let mut payload = BytesMut::new();
        // key_blob as SSH string
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(&key_blob);
        // data as SSH string
        payload.put_u32(data_to_sign.len() as u32);
        payload.put_slice(data_to_sign);
        // flags
        payload.put_u32(0);

        let response = sign_with_key(&private_key, &payload.freeze()).unwrap();
        assert_eq!(response.msg_type, MessageType::SignResponse);
        assert!(!response.payload.is_empty());
    }

    #[test]
    fn sign_with_key_rejects_truncated_payload() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();

        // Empty payload
        let result = sign_with_key(&private_key, &Bytes::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn sign_with_key_rejects_truncated_key_blob() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();

        // Key blob length says 100 but only 10 bytes follow
        let mut payload = BytesMut::new();
        payload.put_u32(100);
        payload.put_slice(&[0u8; 10]);

        let result = sign_with_key(&private_key, &payload.freeze());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("key blob truncated")
        );
    }

    #[test]
    fn sign_with_key_rejects_missing_data_length() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();

        // Zero-length key blob, then no more data
        let mut payload = BytesMut::new();
        payload.put_u32(0);

        let result = sign_with_key(&private_key, &payload.freeze());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("data length missing")
        );
    }

    #[test]
    fn sign_with_key_handles_missing_flags() {
        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();
        let public_key = private_key.public_key();

        // Build payload without flags (flags are optional)
        let key_blob = public_key.to_bytes().unwrap();
        let data_to_sign = b"hello";

        let mut payload = BytesMut::new();
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(&key_blob);
        payload.put_u32(data_to_sign.len() as u32);
        payload.put_slice(data_to_sign);
        // No flags

        let response = sign_with_key(&private_key, &payload.freeze()).unwrap();
        assert_eq!(response.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_produces_verifiable_signature() {
        use ssh_key::PublicKey;

        let private_key = parse_private_key(OP_PRIVATE_KEY_PEM).unwrap();
        let public_key = private_key.public_key();

        let data_to_sign = b"critical authentication data";

        // Build SignRequest payload
        let key_blob = public_key.to_bytes().unwrap();
        let mut payload = BytesMut::new();
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(&key_blob);
        payload.put_u32(data_to_sign.len() as u32);
        payload.put_slice(data_to_sign);
        payload.put_u32(0);

        let response = sign_with_key(&private_key, &payload.freeze()).unwrap();

        // Parse the signature from the response
        let mut resp_buf = &response.payload[..];
        let sig_len = resp_buf.get_u32() as usize;
        let sig_bytes = &resp_buf[..sig_len];

        // Verify the signature using the public key
        let sig = ssh_key::Signature::try_from(sig_bytes).unwrap();

        let pub_key = PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        // Use the Verifier trait explicitly to avoid conflict with PublicKey::verify(namespace, msg, SshSig)
        <PublicKey as signature::Verifier<ssh_key::Signature>>::verify(
            &pub_key,
            data_to_sign,
            &sig,
        )
        .unwrap();
    }
}
