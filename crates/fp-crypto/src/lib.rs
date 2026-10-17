//! `fp-crypto`
//!
//! Encryption and security key management, entropy scoring, and SecOC support for `field-probe`.

pub mod entropy;
pub mod keyring;

pub use entropy::{calculate_shannon_entropy, is_high_entropy_payload};
pub use keyring::{KeyRing, KeyType, ManagedKey};
