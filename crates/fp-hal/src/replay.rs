use async_trait::async_trait;
use chrono::Utc;
use fp_core::{
    AdapterCapabilities, CanFrame, HalError, IndustrialChip, LinkParams, OutboundFrame,
    RawBusEvent, RawFrame, SafetyPermit, SafetyTier, TimestampedChunk,
};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::interface::BusInterface;

/// A deterministic, hardware-agnostic synthetic bus interface for CI and simulation.
#[derive(Clone)]
pub struct ReplayInterface {
    capabilities: AdapterCapabilities,
    tier: Arc<RwLock<SafetyTier>>,
    link_params: Arc<RwLock<LinkParams>>,
    tx_sender: broadcast::Sender<RawBusEvent>,
    transmitted_history: Arc<RwLock<Vec<OutboundFrame>>>,
}

impl ReplayInterface {
    /// Create a new synthetic replay interface with a broadcast capacity.
    /// Invariant: Tier initializes to Tier-0 PassiveListenOnly.
    pub fn new(interface_id: impl Into<String>, capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        let id_str = interface_id.into();
        Self {
            capabilities: AdapterCapabilities {
                interface_id: id_str.clone(),
                chip_type: IndustrialChip::SyntheticReplay,
                supports_serial: true,
                supports_can: true,
                supports_can_fd: true,
                supports_listen_only: true,
                supported_baud_rates: vec![9600, 19200, 38400, 57600, 115200, 230400],
                supported_can_bitrates: vec![500_000, 250_000, 125_000, 1_000_000],
                usb_vid: None,
                usb_pid: None,
                serial_number: Some("REPLAY-VIRTUAL-001".to_string()),
                description: format!("Virtual Replay Interface ({})", id_str),
            },
            tier: Arc::new(RwLock::new(SafetyTier::PassiveListenOnly)),
            link_params: Arc::new(RwLock::new(LinkParams::Auto)),
            tx_sender: tx,
            transmitted_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Inject a synthetic bus event into the receiver stream.
    pub fn inject_event(&self, event: RawBusEvent) -> Result<usize, HalError> {
        self.tx_sender
            .send(event)
            .map_err(|e| HalError::Io(format!("Failed to broadcast replay event: {}", e)))
    }

    /// Inject a raw synthetic Modbus RTU chunk.
    pub fn inject_modbus_rtu(
        &self,
        timestamp_us: u64,
        payload: &[u8],
        inter_frame_gap_us: Option<u64>,
    ) -> Result<usize, HalError> {
        let params = {
            let p = self.link_params.try_read().map_err(|_| HalError::Timeout("Lock contention".into()))?;
            p.clone()
        };
        let chunk = TimestampedChunk::new(payload.to_vec(), inter_frame_gap_us);
        let event = RawBusEvent::new_serial_rx(
            self.capabilities.interface_id.clone(),
            timestamp_us,
            params,
            chunk,
        );
        self.inject_event(event)
    }

    /// Inject a synthetic CAN frame.
    pub fn inject_can_frame(&self, timestamp_us: u64, frame: CanFrame) -> Result<usize, HalError> {
        let params = {
            let p = self.link_params.try_read().map_err(|_| HalError::Timeout("Lock contention".into()))?;
            p.clone()
        };
        let event = RawBusEvent::new_can_rx(
            self.capabilities.interface_id.clone(),
            timestamp_us,
            params,
            frame,
        );
        self.inject_event(event)
    }

    /// Return recorded transmitted frames (for assertion in tests)
    pub async fn get_transmitted(&self) -> Vec<OutboundFrame> {
        self.transmitted_history.read().await.clone()
    }
}

#[async_trait]
impl BusInterface for ReplayInterface {
    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn current_safety_tier(&self) -> SafetyTier {
        // Fast synchronous check if possible
        if let Ok(guard) = self.tier.try_read() {
            *guard
        } else {
            SafetyTier::PassiveListenOnly
        }
    }

    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError> {
        let mut guard = self.link_params.write().await;
        *guard = params.clone();
        Ok(())
    }

    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError> {
        let mut guard = self.tier.write().await;
        *guard = tier;
        Ok(())
    }

    fn subscribe_rx(&self) -> broadcast::Receiver<RawBusEvent> {
        self.tx_sender.subscribe()
    }

    async fn transmit(
        &mut self,
        frame: OutboundFrame,
        permit: &SafetyPermit,
    ) -> Result<(), HalError> {
        let current_tier = *self.tier.read().await;

        // Tier-0 Zero-TX Default invariant
        if current_tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: current_tier,
            });
        }

        // Validate permit
        let now = Utc::now();
        if !permit.is_valid_for(current_tier, now) {
            return Err(HalError::PermitRejected);
        }

        // Store transmitted frame
        self.transmitted_history.write().await.push(frame.clone());

        // Emit loopback/direction TX event on bus
        let current_params = self.link_params.read().await.clone();
        let payload = match frame {
            OutboundFrame::Serial(b) => RawFrame::Serial(TimestampedChunk::new(b, None)),
            OutboundFrame::Can(c) => RawFrame::Can(c),
        };
        let tx_event = RawBusEvent {
            interface_id: self.capabilities.interface_id.clone(),
            timestamp_us: (now.timestamp_micros()).max(0) as u64,
            link_params: current_params,
            payload,
            direction: fp_core::Direction::Tx,
            error_flags: Default::default(),
        };

        let _ = self.tx_sender.send(tx_event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Duration;
    use fp_core::{CanFrame, CanId, SerialParams};

    #[tokio::test]
    async fn test_initial_tier_is_passive_and_blocks_tx() {
        let mut replay = ReplayInterface::new("vbus0", 16);
        assert_eq!(replay.current_safety_tier(), SafetyTier::PassiveListenOnly);

        let now = Utc::now();
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ActiveWrite,
            "tester",
            now + Duration::minutes(1),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        let result = replay.transmit(frame, &permit).await;

        match result {
            Err(HalError::SafetyViolation { required, current }) => {
                assert_eq!(required, SafetyTier::ReadOnlyProbe);
                assert_eq!(current, SafetyTier::PassiveListenOnly);
            }
            _ => panic!("Expected SafetyViolation error, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_elevated_tier_with_valid_permit_allows_tx() {
        let mut replay = ReplayInterface::new("vbus1", 16);
        replay.set_safety_tier(SafetyTier::ReadOnlyProbe).await.unwrap();

        let now = Utc::now();
        let permit = SafetyPermit::new(
            "p2",
            SafetyTier::ReadOnlyProbe,
            "tester",
            now + Duration::minutes(1),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        replay.transmit(frame.clone(), &permit).await.expect("Transmit should succeed");

        let history = replay.get_transmitted().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], frame);
    }

    #[tokio::test]
    async fn test_expired_permit_is_rejected() {
        let mut replay = ReplayInterface::new("vbus2", 16);
        replay.set_safety_tier(SafetyTier::ReadOnlyProbe).await.unwrap();

        let now = Utc::now();
        let expired_permit = SafetyPermit::new(
            "p3",
            SafetyTier::ReadOnlyProbe,
            "tester",
            now - Duration::seconds(5),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        let result = replay.transmit(frame, &expired_permit).await;
        assert!(matches!(result, Err(HalError::PermitRejected)));
    }

    #[tokio::test]
    async fn test_synthetic_event_streaming() {
        let mut replay = ReplayInterface::new("vbus_stream", 32);
        replay
            .set_link_params(&LinkParams::Serial(SerialParams::default()))
            .await
            .unwrap();

        let mut rx = replay.subscribe_rx();

        // Inject Modbus query
        let modbus_req = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x74, 0x17];
        replay.inject_modbus_rtu(1000, &modbus_req, Some(3500)).unwrap();

        // Inject CAN frame
        let can_frame = CanFrame::new_standard(0x7DF, &[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        replay.inject_can_frame(2500, can_frame).unwrap();

        let ev1 = rx.recv().await.unwrap();
        assert_eq!(ev1.timestamp_us, 1000);
        if let RawFrame::Serial(chunk) = ev1.payload {
            assert_eq!(&chunk.data[..], &modbus_req);
            assert_eq!(chunk.inter_frame_gap_us, Some(3500));
        } else {
            panic!("Expected serial event");
        }

        let ev2 = rx.recv().await.unwrap();
        assert_eq!(ev2.timestamp_us, 2500);
        if let RawFrame::Can(can) = ev2.payload {
            assert_eq!(can.id, CanId::Standard(0x7DF));
            assert_eq!(can.dlc, 8);
        } else {
            panic!("Expected CAN event");
        }
    }
}
