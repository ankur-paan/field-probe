use async_trait::async_trait;
use fp_core::{
    AdapterCapabilities, HalError, LinkParams, OutboundFrame, RawBusEvent, SafetyPermit,
    SafetyTier,
};
use tokio::sync::broadcast;

/// Unified async interface for physical dongles and synthetic replay buses.
#[async_trait]
pub trait BusInterface: Send + Sync {
    /// Return capabilities and metadata of the underlying adapter
    fn capabilities(&self) -> AdapterCapabilities;

    /// Return the active safety tier
    fn current_safety_tier(&self) -> SafetyTier;

    /// Reconfigure bus link parameters (baud rate, parity, CAN bitrate)
    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError>;

    /// Adjust the operational safety tier.
    /// Invariant: adapters must power on / initialize at SafetyTier::PassiveListenOnly.
    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError>;

    /// Subscribe to real-time incoming and outgoing bus events
    fn subscribe_rx(&self) -> broadcast::Receiver<RawBusEvent>;

    /// Transmit a frame on the bus.
    /// STRICT INVARIANT: MUST FAIL if current tier is PassiveListenOnly or permit is invalid.
    async fn transmit(
        &mut self,
        frame: OutboundFrame,
        permit: &SafetyPermit,
    ) -> Result<(), HalError>;
}
