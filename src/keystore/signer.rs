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
use zeroize::Zeroizing;

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
    let flags = if buf.remaining() >= 4 {
        buf.get_u32()
    } else {
        0
    };

    if flags != 0 {
        debug!(flags = flags, "Sign request flags present");
    }

    debug!(data_len = data.len(), flags = flags, "Signing data locally");

    // For RSA keys, select the hash algorithm based on flags
    let signature: ssh_key::Signature = if matches!(private_key.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
        sign_rsa(private_key, data, flags)?
    } else {
        private_key
            .try_sign(data)
            .map_err(|e| Error::Protocol(format!("Signing failed: {}", e)))?
    };

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

/// SSH agent protocol flags
const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Sign data with an RSA key, respecting SSH agent flags for hash algorithm selection.
fn sign_rsa(private_key: &PrivateKey, data: &[u8], flags: u32) -> Result<ssh_key::Signature> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::SignatureEncoding;
    use ssh_key::private::RsaKeypair;

    let keypair: RsaKeypair = private_key
        .key_data()
        .rsa()
        .ok_or_else(|| Error::Protocol("Expected RSA key data".to_string()))?
        .clone();
    let rsa_private: rsa::RsaPrivateKey = keypair.try_into().map_err(|e: ssh_key::Error| {
        Error::Protocol(format!("RSA key conversion failed: {}", e))
    })?;

    if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        let signing_key = SigningKey::<sha2::Sha512>::new(rsa_private);
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        Ok(ssh_key::Signature::new(
            ssh_key::Algorithm::Other(
                ssh_key::AlgorithmName::new("rsa-sha2-512")
                    .map_err(|e| Error::Protocol(format!("Algorithm name error: {}", e)))?,
            ),
            sig.to_vec(),
        )
        .map_err(|e| Error::Protocol(format!("Signature construction failed: {}", e)))?)
    } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        let signing_key = SigningKey::<sha2::Sha256>::new(rsa_private);
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        Ok(ssh_key::Signature::new(
            ssh_key::Algorithm::Other(
                ssh_key::AlgorithmName::new("rsa-sha2-256")
                    .map_err(|e| Error::Protocol(format!("Algorithm name error: {}", e)))?,
            ),
            sig.to_vec(),
        )
        .map_err(|e| Error::Protocol(format!("Signature construction failed: {}", e)))?)
    } else {
        // Default: use ssh-key's built-in signing (sha1 / ssh-rsa)
        private_key
            .try_sign(data)
            .map_err(|e| Error::Protocol(format!("RSA signing failed: {}", e)))
    }
}

/// Parse a PEM private key string into an ssh-key PrivateKey.
///
/// Supports:
/// - OpenSSH format ("BEGIN OPENSSH PRIVATE KEY") — any key type supported by ssh-key crate
/// - PKCS#8 format ("BEGIN PRIVATE KEY") — Ed25519 and RSA (as returned by 1Password)
pub fn parse_private_key(pem: &str) -> Result<PrivateKey> {
    // Try OpenSSH format first (supports all key types)
    if let Ok(key) = PrivateKey::from_openssh(pem) {
        return Ok(key);
    }

    // Try PKCS#8 PEM format (1Password returns "BEGIN PRIVATE KEY")
    if pem.contains("BEGIN PRIVATE KEY") {
        return parse_pkcs8(pem);
    }

    Err(Error::KeyStore(
        "Failed to parse private key: unsupported format. \
         Expected OpenSSH (\"BEGIN OPENSSH PRIVATE KEY\") or \
         PKCS#8 (\"BEGIN PRIVATE KEY\")"
            .to_string(),
    ))
}

/// Parse a PKCS#8 PEM private key (Ed25519 or RSA).
fn parse_pkcs8(pem: &str) -> Result<PrivateKey> {
    // Try Ed25519 first (1Password's Ed25519 output has non-canonical DER)
    if let Ok(key) = parse_pkcs8_ed25519(pem) {
        return Ok(key);
    }

    // Try RSA via the rsa crate's PKCS#8 parser
    parse_pkcs8_rsa(pem)
}

/// Parse a PKCS#8-encoded RSA private key PEM.
fn parse_pkcs8_rsa(pem: &str) -> Result<PrivateKey> {
    use pkcs8::DecodePrivateKey;
    use ssh_key::private::RsaKeypair;

    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|e| Error::KeyStore(format!("Failed to parse PKCS#8 RSA key: {}", e)))?;

    let keypair = RsaKeypair::try_from(rsa_key)
        .map_err(|e| Error::KeyStore(format!("Failed to convert RSA key to SSH format: {}", e)))?;

    Ok(PrivateKey::from(keypair))
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
/// We use the pkcs8 crate for proper ASN.1 parsing rather than hand-rolled pattern matching.
/// Design rationale: We use a targeted OID + offset approach instead of the `pkcs8` crate
/// because 1Password's PKCS#8 output is not strict DER (contains non-canonical encodings
/// that `pkcs8::PrivateKeyInfo` rejects). The Ed25519 PKCS#8 structure is simple and fixed,
/// so this targeted parsing is safe for this specific case.
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

    let seed = extract_ed25519_seed_from_pkcs8(&der)?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    Ok(PrivateKey::from(keypair))
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 DER blob.
///
/// Looks for the Ed25519 OID (1.3.101.112 = [06 03 2b 65 70]), then
/// navigates to the nested OCTET STRING containing the 32-byte seed.
/// The returned seed is wrapped in `Zeroizing` for secure memory erasure.
fn extract_ed25519_seed_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    let oid_pos = der
        .windows(ED25519_OID.len())
        .position(|w| w == ED25519_OID)
        .ok_or_else(|| {
            Error::KeyStore(
                "PKCS#8 key does not contain Ed25519 OID. \
                 Only Ed25519 keys in PKCS#8 format are supported."
                    .to_string(),
            )
        })?;

    let rest = &der[oid_pos + ED25519_OID.len()..];

    // Find the outer OCTET STRING (tag 0x04)
    let outer_pos = rest.iter().position(|&b| b == 0x04).ok_or_else(|| {
        Error::KeyStore("PKCS#8: could not find private key OCTET STRING".to_string())
    })?;

    let outer = &rest[outer_pos..];
    if outer.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: outer OCTET STRING too short".to_string(),
        ));
    }

    let outer_len = outer[1] as usize;
    let outer_content = outer
        .get(2..2 + outer_len)
        .ok_or_else(|| Error::KeyStore("PKCS#8: outer OCTET STRING truncated".to_string()))?;

    // Inner OCTET STRING containing the 32-byte seed
    if outer_content.first() != Some(&0x04) || outer_content.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: expected inner OCTET STRING for Ed25519 seed".to_string(),
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

    let mut seed = Zeroizing::new([0u8; 32]);
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
