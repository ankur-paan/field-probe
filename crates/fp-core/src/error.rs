use thiserror::Error;

use crate::safety::SafetyTier;

/// Standard Hardware Abstraction Layer errors.
#[derive(Debug, Error)]
pub enum HalError {
    #[error("Safety tier violation: operation requires tier {required:?}, interface is in tier {current:?}")]
    SafetyViolation {
        required: SafetyTier,
        current: SafetyTier,
    },

    #[error("Missing or invalid safety permit: {0}")]
    InvalidPermit(String),

    #[error("Safety permit expired or caller unauthorized")]
    PermitRejected,

    #[error("Interface closed or disconnected: {0}")]
    Disconnected(String),

    #[error("Unsupported link parameters: {0}")]
    UnsupportedParameters(String),

    #[error("Transmission failed: {0}")]
    TxFailed(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Hardware timeout: {0}")]
    Timeout(String),
}
