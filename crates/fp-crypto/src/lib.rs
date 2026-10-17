//! `fp-crypto`
//!
//! Encryption and security key management, entropy scoring, and SecOC support for `field-probe`.

pub mod entropy;
pub mod hmac;
pub mod keyring;
pub mod secoc;
pub mod unmask;

pub use entropy::{calculate_shannon_entropy, is_high_entropy_payload};
pub use hmac::{hmac_sha256, sha256, to_hex, verify_hmac_sha256};
pub use keyring::{KeyRing, KeyType, ManagedKey};
pub use secoc::{aes128_cmac, aes128_encrypt_block, aes128_key_expansion, derive_cmac_subkeys, verify_secoc_mac};
pub use unmask::{auto_decrypt_payload, decrypt_with_key, unmask_rolling_xor, unmask_xor};

