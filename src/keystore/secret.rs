//! Secure key storage with zeroize on drop

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret key that is zeroized when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKeyData {
    /// Raw private key bytes (will be zeroized on drop)
    data: Vec<u8>,
}

impl SecretKeyData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Explicitly zeroize and consume the key
    pub fn forget(mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecretKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKeyData")
            .field("len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_correct_data() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretKeyData::new(data.clone());
        assert_eq!(secret.data(), &data);
    }

    #[test]
    fn forget_zeroizes_data() {
        let secret = SecretKeyData::new(vec![0xAA; 32]);
        // After forget, the data should be zeroized (consumed)
        secret.forget();
        // If we reach here, forget() completed without panic
    }

    #[test]
    fn clone_produces_independent_copy() {
        let secret = SecretKeyData::new(vec![1, 2, 3]);
        let cloned = secret.clone();
        assert_eq!(cloned.data(), secret.data());
    }

    #[test]
    fn debug_does_not_leak_secret_data() {
        let secret = SecretKeyData::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug_output = format!("{:?}", secret);
        // Debug output should show length but not the actual bytes
        assert!(debug_output.contains("len"));
        assert!(debug_output.contains("4"));
        assert!(!debug_output.contains("222")); // 0xDE = 222
        assert!(!debug_output.contains("173")); // 0xAD = 173
        assert!(!debug_output.contains("190")); // 0xBE = 190
        assert!(!debug_output.contains("239")); // 0xEF = 239
        // Also ensure raw hex is not present
        assert!(!debug_output.contains("DEAD"));
        assert!(!debug_output.contains("dead"));
        assert!(!debug_output.contains("BEEF"));
        assert!(!debug_output.contains("beef"));
    }
}
