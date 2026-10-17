use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Key category managed by KeyRing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Aes128,
    Aes256,
    TlsCertificate,
    XorMask,
    CustomSeed,
    OperatorSecret,
}

/// A stored encryption key or certificate with metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub target_scope: String,
    pub secret_bytes: Vec<u8>,
}

/// Thread-safe key registry for bus decryptors and verification engines
#[derive(Debug, Default, Clone)]
pub struct KeyRing {
    keys: Arc<RwLock<HashMap<String, ManagedKey>>>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert_key(&self, key: ManagedKey) {
        let mut guard = self.keys.write().unwrap();
        guard.insert(key.key_id.clone(), key);
    }

    pub fn insert_symmetric_key(&self, key_id: impl Into<String>, secret_bytes: &[u8]) {
        self.insert_key(ManagedKey {
            key_id: key_id.into(),
            key_type: KeyType::Aes128,
            target_scope: "global".to_string(),
            secret_bytes: secret_bytes.to_vec(),
        });
    }

    pub fn get_key(&self, key_id: &str) -> Option<ManagedKey> {
        self.keys.read().unwrap().get(key_id).cloned()
    }

    pub fn get_symmetric_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.get_key(key_id).map(|k| k.secret_bytes)
    }

    pub fn find_for_scope(&self, scope: &str) -> Vec<ManagedKey> {
        self.keys
            .read()
            .unwrap()
            .values()
            .filter(|k| k.target_scope == scope)
            .cloned()
            .collect()
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.keys.read().unwrap().keys().cloned().collect()
    }

    /// Sign a safety permit using a designated key in the keyring
    pub fn sign_permit(&self, key_id: &str, permit: &mut fp_core::SafetyPermit) -> bool {
        let key = match self.get_key(key_id) {
            Some(k) => k,
            None => return false,
        };
        let canonical = permit.canonical_bytes();
        let mac = crate::hmac::hmac_sha256(&key.secret_bytes, &canonical);
        permit.signature = Some(crate::hmac::to_hex(&mac));
        true
    }

    /// Cryptographically verify a safety permit against operator secrets in the keyring
    pub fn verify_permit(&self, permit: &fp_core::SafetyPermit) -> bool {
        let sig = match &permit.signature {
            Some(s) => s,
            None => return false,
        };
        let canonical = permit.canonical_bytes();

        let guard = self.keys.read().unwrap();
        // Check all OperatorSecret keys or keys matching authorized_caller
        for key in guard.values() {
            if (key.key_type == KeyType::OperatorSecret
                || key.key_id == permit.authorized_caller
                || key.target_scope == "operator")
                && crate::hmac::verify_hmac_sha256(&key.secret_bytes, &canonical, sig)
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fp_core::chrono::{Duration, Utc};
    use fp_core::{SafetyPermit, SafetyTier};

    #[test]
    fn test_keyring_storage_and_retrieval() {
        let keyring = KeyRing::new();
        keyring.insert_symmetric_key("test-key", &[1, 2, 3, 4]);

        assert_eq!(keyring.get_symmetric_key("test-key"), Some(vec![1, 2, 3, 4]));
        assert_eq!(keyring.get_symmetric_key("missing"), None);
    }

    #[test]
    fn test_safety_permit_signing_and_verification() {
        let keyring = KeyRing::new();
        let secret = b"super-secret-operator-key-32bytes!";
        keyring.insert_key(ManagedKey {
            key_id: "op-key-1".to_string(),
            key_type: KeyType::OperatorSecret,
            target_scope: "operator".to_string(),
            secret_bytes: secret.to_vec(),
        });

        let mut permit = SafetyPermit::new(
            "permit-123",
            SafetyTier::ReadOnlyProbe,
            "field-engineer",
            Utc::now() + Duration::hours(1),
            Some("CAN:0x7E0".to_string()),
        );

        assert!(!keyring.verify_permit(&permit)); // No signature yet

        assert!(keyring.sign_permit("op-key-1", &mut permit));
        assert!(permit.signature.is_some());
        assert!(keyring.verify_permit(&permit));

        // Tampering with scope breaks signature
        permit.scope = Some("CAN:0x7E1".to_string());
        assert!(!keyring.verify_permit(&permit));
    }
}

