use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Operational safety tier for connected bus adapters.
/// Invariant: adapters MUST always default to `PassiveListenOnly`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum SafetyTier {
    /// Tier 0 (Default): Passive listen-only mode. Zero transmissions allowed.
    /// Hardware transceiver TX line is held tri-state or listen-only bit is set.
    #[default]
    PassiveListenOnly = 0,

    /// Tier 1: Non-intrusive read-only probes (e.g., Modbus device ID query, diagnostic ping).
    /// Requires an authorized SafetyPermit.
    ReadOnlyProbe = 1,

    /// Tier 2: Active read/write operations (e.g. register write, coil actuation).
    /// Requires an explicit permit with active write scope.
    ActiveWrite = 2,
}

impl SafetyTier {
    /// Human-readable name with tier identifier
    pub fn name(&self) -> &'static str {
        match self {
            Self::PassiveListenOnly => "Tier-0: PassiveListenOnly",
            Self::ReadOnlyProbe => "Tier-1: ReadOnlyProbe",
            Self::ActiveWrite => "Tier-2: ActiveWrite",
        }
    }

    /// Whether this tier enforces passive zero-transmission
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::PassiveListenOnly)
    }
}

/// A cryptographic / token permit required to elevate safety tiers above Tier-0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyPermit {
    /// Unique identifier for the permit
    pub permit_id: String,
    /// Authorized tier granted by this permit
    pub granted_tier: SafetyTier,
    /// Authorized identity or session
    pub authorized_caller: String,
    /// Expiration time in UTC
    pub expires_at: DateTime<Utc>,
    /// Optional target restriction (e.g. "CAN:0x7E0" or "Modbus:Slave04")
    pub scope: Option<String>,
    /// Optional cryptographic signature (e.g. HMAC-SHA256 hex string)
    pub signature: Option<String>,
}

impl SafetyPermit {
    /// Create a new transient permit for testing or field operations
    pub fn new(
        permit_id: impl Into<String>,
        granted_tier: SafetyTier,
        authorized_caller: impl Into<String>,
        expires_at: DateTime<Utc>,
        scope: Option<String>,
    ) -> Self {
        Self {
            permit_id: permit_id.into(),
            granted_tier,
            authorized_caller: authorized_caller.into(),
            expires_at,
            scope,
            signature: None,
        }
    }

    /// Attach a cryptographic signature to the permit
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// Canonical byte representation of permit fields for cryptographic signing
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.permit_id.as_bytes());
        buf.push(b':');
        buf.push(self.granted_tier as u8);
        buf.push(b':');
        buf.extend_from_slice(self.authorized_caller.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(&self.expires_at.timestamp().to_be_bytes());
        buf.push(b':');
        if let Some(ref scope) = self.scope {
            buf.extend_from_slice(scope.as_bytes());
        }
        buf
    }

    /// Check if target matches permit scope restriction
    pub fn matches_scope(&self, target_scope: &str) -> bool {
        match &self.scope {
            None => true,
            Some(s) if s == "*" || s.eq_ignore_ascii_case("global") => true,
            Some(s) => s.eq_ignore_ascii_case(target_scope) || target_scope.starts_with(s),
        }
    }

    /// Check if permit is currently valid and satisfies requested tier
    pub fn is_valid_for(&self, requested: SafetyTier, now: DateTime<Utc>) -> bool {
        self.granted_tier >= requested && self.expires_at > now
    }

    /// Check if permit satisfies tier, expiration, and target scope
    pub fn is_valid_with_scope(
        &self,
        requested: SafetyTier,
        target_scope: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.is_valid_for(requested, now) && self.matches_scope(target_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_safety_tier_default_is_passive() {
        assert_eq!(SafetyTier::default(), SafetyTier::PassiveListenOnly);
    }

    #[test]
    fn test_safety_permit_validation() {
        let now = Utc::now();
        let permit = SafetyPermit::new(
            "test-1",
            SafetyTier::ReadOnlyProbe,
            "operator",
            now + Duration::minutes(5),
            None,
        );

        assert!(permit.is_valid_for(SafetyTier::ReadOnlyProbe, now));
        assert!(permit.is_valid_for(SafetyTier::PassiveListenOnly, now));
        assert!(!permit.is_valid_for(SafetyTier::ActiveWrite, now));

        let expired = SafetyPermit::new(
            "test-2",
            SafetyTier::ActiveWrite,
            "operator",
            now - Duration::seconds(1),
            None,
        );
        assert!(!expired.is_valid_for(SafetyTier::ReadOnlyProbe, now));
    }
}
