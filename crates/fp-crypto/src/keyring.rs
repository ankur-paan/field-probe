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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_storage_and_retrieval() {
        let keyring = KeyRing::new();
        keyring.insert_symmetric_key("test-key", &[1, 2, 3, 4]);

        assert_eq!(keyring.get_symmetric_key("test-key"), Some(vec![1, 2, 3, 4]));
        assert_eq!(keyring.get_symmetric_key("missing"), None);
    }
}

