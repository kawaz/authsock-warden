//! Local signing adapter.
//!
//! This module is a stateless adapter: it accepts a PEM-encoded private key
//! string, parses it into a transient algorithm-specific representation just
//! long enough to produce the SignResponse, then drops the key material.
//! Callers (the KV / cache layer) own key persistence; this module owns
//! nothing.
//!
//! Design rationale: an earlier implementation kept `ssh_key::PrivateKey`
//! alive in the cache layer and converted to `rsa::RsaPrivateKey` at sign
//! time. That round-trip conversion failed for some PKCS#8 RSA keys
//! ("RSA key conversion failed: cryptographic error"). By keeping signing
//! transient and storing each algorithm in its native crate's type
//! end-to-end, we avoid intermediate conversions entirely.

use crate::error::{Error, Result};
use crate::protocol::{AgentMessage, MessageType};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use ssh_key::PrivateKey;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
use tracing::debug;
use zeroize::Zeroizing;

/// SSH agent protocol flags for RSA hash algorithm selection.
///   SSH_AGENT_RSA_SHA2_256 = 0x02
///   SSH_AGENT_RSA_SHA2_512 = 0x04
/// When both bits are zero, ssh-rsa (SHA-1) is used (legacy OpenSSH servers).
const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Sign an SSH agent SignRequest payload using a PEM-encoded private key.
///
/// The key is parsed, used to sign, and dropped within this call.
/// This is the only public entry point of the signer module.
pub fn sign_pem(pem: &str, sign_request_payload: &Bytes) -> Result<AgentMessage> {
    let parsed = parse_sign_request(sign_request_payload)?;
    let material = KeyMaterial::from_pem(pem)?;
    let blob = material.sign(&parsed.data, parsed.flags)?;
    Ok(encode_sign_response(blob))
}

/// Parsed SignRequest fields the signer cares about.
/// (key_blob is ignored — caller has already routed by key.)
struct ParsedSignRequest {
    data: Vec<u8>,
    flags: u32,
}

fn parse_sign_request(payload: &Bytes) -> Result<ParsedSignRequest> {
    let mut buf = &payload[..];

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

    if buf.remaining() < 4 {
        return Err(Error::Protocol(
            "SignRequest data length missing".to_string(),
        ));
    }
    let data_len = buf.get_u32() as usize;
    if buf.remaining() < data_len {
        return Err(Error::Protocol("SignRequest data truncated".to_string()));
    }
    let data = buf[..data_len].to_vec();
    buf.advance(data_len);

    let flags = if buf.remaining() >= 4 {
        buf.get_u32()
    } else {
        0
    };

    if flags != 0 {
        debug!(flags = flags, "Sign request flags present");
    }
    debug!(data_len = data.len(), flags = flags, "Signing data locally");

    Ok(ParsedSignRequest { data, flags })
}

fn encode_sign_response(sig_blob: Vec<u8>) -> AgentMessage {
    let mut payload = BytesMut::new();
    payload.put_u32(sig_blob.len() as u32);
    payload.put_slice(&sig_blob);
    AgentMessage::new(MessageType::SignResponse, payload.freeze())
}

/// Encode an SSH signature blob: `string(algorithm) + string(signature)`.
///
/// We build this manually instead of going through `ssh_key::Signature`
/// because ssh-key 0.6 rejects `Algorithm::Rsa { hash: None }` (legacy
/// ssh-rsa / SHA-1) in `Signature::new`. The wire format is identical
/// regardless of who builds it.
fn encode_signature_blob(algorithm_name: &str, sig_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + algorithm_name.len() + sig_bytes.len());
    blob.extend_from_slice(&(algorithm_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(algorithm_name.as_bytes());
    blob.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig_bytes);
    blob
}

/// Algorithm-specific private key material.
///
/// Each variant holds the native type of the signing crate, so we never
/// convert between representations at sign time.
enum KeyMaterial {
    Ed25519(Ed25519Keypair),
    // Boxed because rsa::RsaPrivateKey is ~344 bytes vs Ed25519Keypair's 64;
    // keeps the enum compact for moves through Result.
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl KeyMaterial {
    /// Parse a PEM string into key material.
    ///
    /// Supports:
    /// - OpenSSH format ("BEGIN OPENSSH PRIVATE KEY") for Ed25519 / RSA
    /// - PKCS#8 format ("BEGIN PRIVATE KEY") for Ed25519 / RSA (1Password)
    fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(key) = PrivateKey::from_openssh(pem) {
            return Self::from_openssh_private_key(&key);
        }

        if pem.contains("BEGIN PRIVATE KEY") {
            return Self::from_pkcs8(pem);
        }

        Err(Error::KeyStore(
            "Failed to parse private key: unsupported format. \
             Expected OpenSSH (\"BEGIN OPENSSH PRIVATE KEY\") or \
             PKCS#8 (\"BEGIN PRIVATE KEY\")"
                .to_string(),
        ))
    }

    fn from_openssh_private_key(key: &PrivateKey) -> Result<Self> {
        use ssh_key::private::KeypairData;
        match key.key_data() {
            KeypairData::Ed25519(kp) => Ok(KeyMaterial::Ed25519(kp.clone())),
            KeypairData::Rsa(kp) => Ok(KeyMaterial::Rsa(Box::new(rsa_keypair_to_rsa_private_key(
                kp,
            )?))),
            other => Err(Error::KeyStore(format!(
                "Unsupported key algorithm: {:?}. Only Ed25519 and RSA are supported.",
                other.algorithm()
            ))),
        }
    }

    /// Parse a PKCS#8 PEM. Tries Ed25519 first (1Password's non-canonical DER
    /// is detected by OID), then falls back to RSA via the rsa crate.
    fn from_pkcs8(pem: &str) -> Result<Self> {
        if let Ok(material) = parse_pkcs8_ed25519(pem) {
            return Ok(material);
        }
        parse_pkcs8_rsa(pem)
    }

    /// Sign and return an SSH signature blob (`string(algo) + string(sig)`).
    fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        match self {
            KeyMaterial::Ed25519(kp) => sign_ed25519(kp, data),
            KeyMaterial::Rsa(key) => sign_rsa(key, data, flags),
        }
    }
}

fn sign_ed25519(kp: &Ed25519Keypair, data: &[u8]) -> Result<Vec<u8>> {
    // ssh_key's Ed25519Keypair → PrivateKey → try_sign gives us a
    // ready-to-encode ssh_key::Signature. flags are ignored for Ed25519.
    let private_key = PrivateKey::from(kp.clone());
    let signature: ssh_key::Signature = signature::Signer::try_sign(&private_key, data)
        .map_err(|e| Error::Protocol(format!("Ed25519 signing failed: {}", e)))?;
    signature
        .try_into()
        .map_err(|e: ssh_key::Error| Error::Protocol(format!("Failed to encode signature: {}", e)))
}

fn sign_rsa(key: &rsa::RsaPrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let (algorithm_name, sig_bytes) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        let signing_key = RsaSigningKey::<sha2::Sha512>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("rsa-sha2-512", sig.to_vec())
    } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        let signing_key = RsaSigningKey::<sha2::Sha256>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("rsa-sha2-256", sig.to_vec())
    } else {
        // Legacy ssh-rsa (SHA-1). Required by old OpenSSH servers
        // (e.g. CentOS 6 / OpenSSH 5.3) that advertise only ssh-rsa.
        let signing_key = RsaSigningKey::<sha1::Sha1>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("ssh-rsa", sig.to_vec())
    };

    Ok(encode_signature_blob(algorithm_name, &sig_bytes))
}

/// Convert ssh-key's RsaKeypair into rsa::RsaPrivateKey by reconstructing
/// from raw components. This avoids ssh-key's `TryFrom<RsaKeypair>` impl,
/// whose CRT validation fails on some otherwise-valid keys with
/// "cryptographic error".
fn rsa_keypair_to_rsa_private_key(kp: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    use rsa::BigUint;
    let to_bigint = |m: &ssh_key::Mpint, label: &str| -> Result<BigUint> {
        m.as_positive_bytes()
            .map(BigUint::from_bytes_be)
            .ok_or_else(|| Error::KeyStore(format!("RSA component {} is not positive", label)))
    };

    let n = to_bigint(&kp.public.n, "n")?;
    let e = to_bigint(&kp.public.e, "e")?;
    let d = to_bigint(&kp.private.d, "d")?;
    let p = to_bigint(&kp.private.p, "p")?;
    let q = to_bigint(&kp.private.q, "q")?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|err| Error::KeyStore(format!("RSA component reconstruction failed: {}", err)))
}

fn parse_pkcs8_rsa(pem: &str) -> Result<KeyMaterial> {
    use pkcs8::DecodePrivateKey;

    let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|e| Error::KeyStore(format!("Failed to parse PKCS#8 RSA key: {}", e)))?;
    Ok(KeyMaterial::Rsa(Box::new(key)))
}

/// Parse a PKCS#8-encoded Ed25519 private key PEM.
///
/// Design rationale: We use a targeted OID + offset approach instead of the
/// `pkcs8` crate because 1Password's PKCS#8 output is not strict DER
/// (contains non-canonical encodings that `pkcs8::PrivateKeyInfo` rejects).
/// The Ed25519 PKCS#8 structure is simple and fixed, so this targeted
/// parsing is safe for this specific case.
fn parse_pkcs8_ed25519(pem: &str) -> Result<KeyMaterial> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| Error::KeyStore(format!("Failed to base64 decode PKCS#8 key: {}", e)))?;

    let seed = extract_ed25519_seed_from_pkcs8(&der)?;
    let kp = Ed25519Keypair::from_seed(&seed);
    Ok(KeyMaterial::Ed25519(kp))
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 DER blob.
///
/// Looks for the Ed25519 OID (1.3.101.112 = [06 03 2b 65 70]), then
/// navigates to the nested OCTET STRING containing the 32-byte seed.
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

    // The test PEM from the 1Password output in the spec.
    const OP_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n";

    const OP_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ";

    // Test PKCS#8 RSA 2048 key + matching OpenSSH public key (generated for tests).
    const RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDs/reWpFe7Nfte
seN0L0ZIW5xXtFNLDcNvZ7rIf4Rp7MOeB+GoBvJqw6gCL2S3RZBB1HgFnoeMMW1V
hu/2Jw7S2twOeNCmtDpThG3VBXMJhbwE7oqlWGIa1dIQDqt8x+xndkc0KlRP5BLj
wP8FFfpKrSyHG7Ix9IG24jw4RD39KehnH0SSe0buT2LOVTrFAVihplRICVxIxPTC
ViUcanJC32c3wZDfiRebT8oxSNJvJjhkxBE/zJVXZ045qG1EgPdM0LGozMqeFCGc
xHz3ZVCqItLpu1a7tQyOnbZMyGhMP+PDjbYYvahFqf5iftWKZsWGXFPhCzdqU3lB
stP3v7HnAgMBAAECggEARPk+8itDUzt7PIyWL47ArDdpUYcsRKgtTGOKk2a1YWSk
a/5MOOxIqjTmVTh43fPzb41IHw6L0YvjD6S1etTUNh63M8kKpLHIVd0xX/F1kPxo
g6DvHf8Skk/PkpfKZgcDcPsV7wMwxY2Rx9I4BkFmtkwfLPUtD+fixpiiQRfvWJnF
24Aupf9Yvdx2qPqu12jtaz9JKOfLiyD1vindvDHVwEfEJtGG7NRtPm4OmLIxPihh
9Y2WgLaWJhv6hKAzD/nGitBJUBzItg+wEviCQJ48rTa7OPTn9AblqMbRPeANr9sK
qBUNqj/2l/7MmDjSsz/SvkkL1DE7EbGWiy+aFttMEQKBgQD8qcYReWr5Ap2KyBn3
Bc09ya9e4syE6ycfj4QRMb3otX7y1l8qmYJvaH4MKcTuT4InmazUoqqoRHpyKBRU
wcAioCjL8VKYV4oZiOMNPhbUhCQRNqQbL+l15Vx/hkIUmY6cwAuxpWHYcthbpAJz
EwQ7vbIGLMnhC1ei5LIf562ZEQKBgQDwH/iUvtsoXtnF91QoXziMvQSK6wUKfX5A
zJQxADcHzynPDoQZKST0pprVYTxeCs1J+kSDq9kpbdDR4wkeGTvH1B/1w4ddkcve
xSJOuYjuyoN99Rjl6ocwT6h3o+mpG88FFZdEdi6kmWpaoqguTvOYEeJAKIpjdwiO
2TSuolzbdwKBgQD3AO4uhRmr5/+l/itMD/Luta3pQCWax9zOgNomiQ9UYaKCukn8
9mfKjEe1klwAceAW4KhSk9fsek2OLlp55ZP1Bcf8YKZTYjkS73ywpINjLO+pmFZk
cbl1VU3RKaqOQvRlj2WfPMPj+5pCNJtkbjHUSYWxfbW6eQEqsRLmF/LhUQKBgBVk
09H02zPSl5aCvbXHHhOz94ak/9L6cVg2ofFnsn94nqH7ChvvxYIioeLnAejjD31K
1fXhRrzhMtywXKyY1PGt3ZcY76OPjNlxOOhIsYGM+4AqaSh658aPIlRefz/44U3z
qYGJAgjaPlaK7W8Ky7s9xKmwsvu/rDyF76KrhphrAoGBAOO4bvMQz9ksp8s1fPoB
+H8CJoZgcWKHdD65AUJAbfSGJluqSzKYb6XwRswyV2J+rLJak2lT3IN9kUsOdR/g
/F+QQjFBq+gR1FVb/n4fKNNuazOUQcuTaoFRx4GhSYMhlhW3Nbd5aNXH8zJhqMBW
IGmiN6jIaYLa8S4Be472ERHj
-----END PRIVATE KEY-----
";
    const RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs/reWpFe7NfteseN0L0ZIW5xXtFNLDcNvZ7rIf4Rp7MOeB+GoBvJqw6gCL2S3RZBB1HgFnoeMMW1Vhu/2Jw7S2twOeNCmtDpThG3VBXMJhbwE7oqlWGIa1dIQDqt8x+xndkc0KlRP5BLjwP8FFfpKrSyHG7Ix9IG24jw4RD39KehnH0SSe0buT2LOVTrFAVihplRICVxIxPTCViUcanJC32c3wZDfiRebT8oxSNJvJjhkxBE/zJVXZ045qG1EgPdM0LGozMqeFCGcxHz3ZVCqItLpu1a7tQyOnbZMyGhMP+PDjbYYvahFqf5iftWKZsWGXFPhCzdqU3lBstP3v7Hn";

    /// Build a SignRequest payload (key_blob + data + flags) for tests.
    fn build_sign_request(public_key: &ssh_key::PublicKey, data: &[u8], flags: u32) -> Bytes {
        let key_blob = public_key.to_bytes().unwrap();
        let mut payload = BytesMut::new();
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(&key_blob);
        payload.put_u32(data.len() as u32);
        payload.put_slice(data);
        payload.put_u32(flags);
        payload.freeze()
    }

    fn extract_signature(response: &AgentMessage) -> ssh_key::Signature {
        let mut buf = &response.payload[..];
        let sig_len = buf.get_u32() as usize;
        let sig_bytes = &buf[..sig_len];
        ssh_key::Signature::try_from(sig_bytes).unwrap()
    }

    fn verify(pub_key: &ssh_key::PublicKey, data: &[u8], sig: &ssh_key::Signature) {
        <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(pub_key, data, sig)
            .unwrap();
    }

    /// Parse a SignResponse payload into (algorithm_name, signature_bytes).
    /// Used for ssh-rsa where ssh_key 0.6 refuses to construct the Signature.
    fn parse_response_blob(response: &AgentMessage) -> (String, Vec<u8>) {
        let mut buf = &response.payload[..];
        let _blob_len = buf.get_u32() as usize;
        let algo_len = buf.get_u32() as usize;
        let algo = std::str::from_utf8(&buf[..algo_len]).unwrap().to_string();
        buf.advance(algo_len);
        let sig_len = buf.get_u32() as usize;
        let sig = buf[..sig_len].to_vec();
        (algo, sig)
    }

    /// Verify an ssh-rsa (SHA-1) signature directly via the rsa crate.
    fn verify_rsa_sha1(pem: &str, data: &[u8], response: &AgentMessage) {
        use pkcs8::DecodePrivateKey;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let (algo, sig_bytes) = parse_response_blob(response);
        assert_eq!(algo, "ssh-rsa");
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifier = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pub_key);
        <rsa::pkcs1v15::VerifyingKey<sha1::Sha1> as signature::Verifier<
            rsa::pkcs1v15::Signature,
        >>::verify(&verifier, data, &sig)
        .unwrap();
    }

    #[test]
    fn from_pem_parses_pkcs8_ed25519() {
        let material = KeyMaterial::from_pem(OP_PRIVATE_KEY_PEM).unwrap();
        assert!(matches!(material, KeyMaterial::Ed25519(_)));
    }

    #[test]
    fn from_pem_parses_pkcs8_rsa() {
        let material = KeyMaterial::from_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        assert!(matches!(material, KeyMaterial::Rsa(_)));
    }

    #[test]
    fn from_pem_rejects_garbage() {
        assert!(KeyMaterial::from_pem("not a key").is_err());
    }

    #[test]
    fn from_pem_rejects_invalid_pkcs8() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n";
        assert!(KeyMaterial::from_pem(pem).is_err());
    }

    #[test]
    fn extract_ed25519_seed_rejects_non_ed25519_oid() {
        let der = vec![0x30, 0x10, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86];
        let result = extract_ed25519_seed_from_pkcs8(&der);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ed25519 OID"));
    }

    #[test]
    fn sign_pem_rejects_truncated_payload() {
        let result = sign_pem(OP_PRIVATE_KEY_PEM, &Bytes::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn sign_pem_rejects_truncated_key_blob() {
        let mut payload = BytesMut::new();
        payload.put_u32(100);
        payload.put_slice(&[0u8; 10]);

        let result = sign_pem(OP_PRIVATE_KEY_PEM, &payload.freeze());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("key blob truncated")
        );
    }

    #[test]
    fn sign_pem_rejects_missing_data_length() {
        let mut payload = BytesMut::new();
        payload.put_u32(0);

        let result = sign_pem(OP_PRIVATE_KEY_PEM, &payload.freeze());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("data length missing")
        );
    }

    #[test]
    fn sign_pem_handles_missing_flags() {
        let pub_key = ssh_key::PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        let data = b"hello";
        let key_blob = pub_key.to_bytes().unwrap();
        let mut payload = BytesMut::new();
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(&key_blob);
        payload.put_u32(data.len() as u32);
        payload.put_slice(data);
        // No flags suffix.

        let response = sign_pem(OP_PRIVATE_KEY_PEM, &payload.freeze()).unwrap();
        assert_eq!(response.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_pem_ed25519_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        let data = b"ed25519 challenge";

        let payload = build_sign_request(&pub_key, data, 0);
        let response = sign_pem(OP_PRIVATE_KEY_PEM, &payload).unwrap();
        let sig = extract_signature(&response);

        verify(&pub_key, data, &sig);
    }

    #[test]
    fn sign_pem_rsa_with_default_flags_produces_verifiable_signature() {
        // flags=0 -> ssh-rsa (SHA-1). Used by legacy OpenSSH (e.g. r3.kawaz.jp).
        // ssh-key 0.6 refuses Algorithm::Rsa { hash: None }, so verify via rsa crate.
        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"r3 legacy ssh-rsa challenge";

        let payload = build_sign_request(&pub_key, data, 0);
        let response = sign_pem(RSA_PRIVATE_KEY_PEM, &payload).unwrap();
        verify_rsa_sha1(RSA_PRIVATE_KEY_PEM, data, &response);
    }

    #[test]
    fn sign_pem_rsa_with_sha2_256_flag_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"rsa-sha2-256 challenge";

        let payload = build_sign_request(&pub_key, data, SSH_AGENT_RSA_SHA2_256);
        let response = sign_pem(RSA_PRIVATE_KEY_PEM, &payload).unwrap();
        let sig = extract_signature(&response);

        verify(&pub_key, data, &sig);
    }

    #[test]
    fn sign_pem_rsa_with_sha2_512_flag_produces_verifiable_signature() {
        // Modern OpenSSH clients request rsa-sha2-512 first.
        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"rsa-sha2-512 challenge";

        let payload = build_sign_request(&pub_key, data, SSH_AGENT_RSA_SHA2_512);
        let response = sign_pem(RSA_PRIVATE_KEY_PEM, &payload).unwrap();
        let sig = extract_signature(&response);

        verify(&pub_key, data, &sig);
    }

    #[test]
    fn sign_pem_rsa_openssh_format_works() {
        // Ensure RSA keys parsed from OpenSSH format (not just PKCS#8) sign too.
        // Convert the test PKCS#8 RSA into OpenSSH format using ssh-key, then
        // route through sign_pem.
        use pkcs8::DecodePrivateKey;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        let kp = ssh_key::private::RsaKeypair::try_from(rsa_key).unwrap();
        let pk = ssh_key::PrivateKey::from(kp);
        let openssh_pem = pk.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"openssh format rsa";
        let payload = build_sign_request(&pub_key, data, SSH_AGENT_RSA_SHA2_512);
        let response = sign_pem(&openssh_pem, &payload).unwrap();
        let sig = extract_signature(&response);

        verify(&pub_key, data, &sig);
    }
}
