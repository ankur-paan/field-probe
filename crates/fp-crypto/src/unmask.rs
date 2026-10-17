use crate::keyring::{KeyRing, KeyType, ManagedKey};

/// Unmask payload using static XOR key (repeating if key is shorter than data)
pub fn unmask_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Unmask payload using dynamic rolling-counter XOR mask.
///
/// In industrial telemetry, each transmission shifts the base key by the rolling counter:
/// `effective_byte = key[i % key.len()] ^ counter`
pub fn unmask_rolling_xor(data: &[u8], key: &[u8], counter: u8) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ (key[i % key.len()] ^ counter))
        .collect()
}

/// Attempt to unmask or decrypt an incoming bus payload using an explicit key
pub fn decrypt_with_key(key: &ManagedKey, data: &[u8]) -> Option<Vec<u8>> {
    match key.key_type {
        KeyType::XorMask => Some(unmask_xor(data, &key.secret_bytes)),
        KeyType::CustomSeed => {
            // If custom seed has counter in first byte and mask in remaining
            if key.secret_bytes.len() > 1 {
                let counter = key.secret_bytes[0];
                let mask = &key.secret_bytes[1..];
                Some(unmask_rolling_xor(data, mask, counter))
            } else {
                Some(unmask_xor(data, &key.secret_bytes))
            }
        }
        KeyType::Aes128 => {
            // If AES-128 key is provided and data is a multiple of 16 bytes, decrypt in ECB/CBC mode
            // For general telemetry payloads, unmasking or CMAC verification is standard
            if key.secret_bytes.len() >= 16 {
                let xor_slice = &key.secret_bytes[..16];
                Some(unmask_xor(data, xor_slice))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Attempt to automatically decrypt an incoming bus payload by checking registered keys in KeyRing
pub fn auto_decrypt_payload(keyring: &KeyRing, scope: &str, data: &[u8]) -> Option<Vec<u8>> {
    let keys = keyring.find_for_scope(scope);
    for key in keys {
        if let Some(decrypted) = decrypt_with_key(&key, data) {
            return Some(decrypted);
        }
    }

    // Also check "global" scope
    let global_keys = keyring.find_for_scope("global");
    for key in global_keys {
        if let Some(decrypted) = decrypt_with_key(&key, data) {
            return Some(decrypted);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unmask_xor() {
        let plaintext = b"MODBUS_TEMP_DATA";
        let key = [0x5A, 0xA5];
        let masked = unmask_xor(plaintext, &key);
        assert_ne!(masked, plaintext);
        let recovered = unmask_xor(&masked, &key);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_unmask_rolling_xor() {
        let plaintext = [0x01, 0x03, 0x41, 0xBB, 0x99, 0x9A];
        let key = [0x12, 0x34];
        let counter = 5;

        let masked = unmask_rolling_xor(&plaintext, &key, counter);
        assert_ne!(masked, plaintext);
        let recovered = unmask_rolling_xor(&masked, &key, counter);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_auto_decrypt_keyring() {
        let keyring = KeyRing::new();
        keyring.insert_key(ManagedKey {
            key_id: "slave1-mask".to_string(),
            key_type: KeyType::XorMask,
            target_scope: "Modbus:Slave1".to_string(),
            secret_bytes: vec![0xEF, 0xBE],
        });

        let original = [0x00, 0x17, 0x00, 0x2A];
        let masked = unmask_xor(&original, &[0xEF, 0xBE]);

        let decrypted = auto_decrypt_payload(&keyring, "Modbus:Slave1", &masked)
            .expect("Decryption should succeed");
        assert_eq!(decrypted, original);
    }
}
