//! `fp-crypto`
//!
//! Encryption and security key management, entropy scoring, AUTOSAR E2E, and SecOC support for `field-probe`.

pub mod e2e;
pub mod entropy;
pub mod hmac;
pub mod keyring;
pub mod secoc;
pub mod unmask;

pub use e2e::{
    calculate_e2e_p1_crc, calculate_e2e_p2_crc, generate_e2e_notch_mask, validate_e2e_p1,
    validate_e2e_p2, E2eStatus,
};
pub use entropy::{calculate_shannon_entropy, is_high_entropy_payload};
pub use hmac::{hmac_sha256, sha256, to_hex, verify_hmac_sha256};
pub use keyring::{KeyRing, KeyType, ManagedKey};
pub use secoc::{
    aes128_cmac, aes128_encrypt_block, aes128_key_expansion, derive_cmac_subkeys, verify_secoc_mac,
};
pub use unmask::{auto_decrypt_payload, decrypt_with_key, unmask_rolling_xor, unmask_xor};
