use async_trait::async_trait;
use chrono::Utc;
use fp_core::{
    AdapterCapabilities, BusErrorFlags, CanFrame, HalError, IndustrialChip, LinkParams,
    OutboundFrame, RawBusEvent, RawFrame, SafetyPermit, SafetyTier,
};
use tokio::sync::broadcast;

use crate::interface::BusInterface;

/// Linux SocketCAN driver abstraction implementing the unified BusInterface
pub struct SocketCanDriver {
    pub interface_name: String,
    pub bitrate: u32,
    pub safety_tier: SafetyTier,
    pub listen_only_enforced: bool,
    pub capabilities: AdapterCapabilities,
    link_params: LinkParams,
    tx_sender: broadcast::Sender<RawBusEvent>,
}

impl SocketCanDriver {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self::with_capacity(interface_name, 500_000, 100)
    }

    pub fn with_capacity(interface_name: impl Into<String>, bitrate: u32, broadcast_cap: usize) -> Self {
        let name = interface_name.into();
        let (tx, _rx) = broadcast::channel(broadcast_cap);
        let caps = AdapterCapabilities {
            interface_id: name.clone(),
            chip_type: IndustrialChip::PeakPcan,
            supports_serial: false,
            supports_can: true,
            supports_can_fd: true,
            supports_listen_only: true,
            supported_baud_rates: vec![],
            supported_can_bitrates: vec![500_000, 250_000, 125_000, 1_000_000],
            usb_vid: Some(0x0C72),
            usb_pid: Some(0x000C),
            serial_number: Some("PCAN-USB-01".to_string()),
            description: format!("SocketCAN Adapter ({})", name),
        };

        Self {
            interface_name: name,
            bitrate,
            safety_tier: SafetyTier::PassiveListenOnly,
            listen_only_enforced: true, // Hardware CAN_CTRLMODE_LISTENONLY
            capabilities: caps,
            link_params: LinkParams::Can(fp_core::CanParams {
                bitrate,
                ..Default::default()
            }),
            tx_sender: tx,
        }
    }

    /// Check if hardware interface supports listen-only mode
    pub fn verify_listen_only_support(&self) -> bool {
        self.capabilities.supports_listen_only
    }

    /// Process an incoming CAN frame from the socket
    pub fn ingest_can_frame(&mut self, frame: CanFrame, timestamp_us: u64) {
        let error_flags = if frame.is_error {
            Self::translate_linux_error_frame(&frame.data)
        } else {
            BusErrorFlags::default()
        };

        let event = RawBusEvent {
            interface_id: self.interface_name.clone(),
            timestamp_us,
            link_params: self.link_params.clone(),
            payload: RawFrame::Can(frame),
            direction: fp_core::Direction::Rx,
            error_flags,
        };
        let _ = self.tx_sender.send(event);
    }

    /// Translate Linux CAN error frame data payload (<linux/can/error.h>) into BusErrorFlags
    pub fn translate_linux_error_frame(data: &[u8]) -> BusErrorFlags {
        let mut flags = BusErrorFlags::default();
        if data.len() < 4 {
            return flags;
        }

        // data[2]: CAN_ERR_PROT_TYPE (error type)
        let prot_type = data[2];
        if prot_type & 0x01 != 0 {
            flags.can_bit_error = true;
        }
        if prot_type & 0x02 != 0 {
            flags.can_form_error = true;
        }
        if prot_type & 0x04 != 0 {
            flags.can_stuff_error = true;
        }

        // data[2] or data[3]: CAN_ERR_PROT_LOC (error location)
        let prot_loc = data[3];
        if prot_loc == 0x19 || prot_loc == 0x1B {
            // CRC sequence or CRC delimiter location
            flags.can_crc_error = true;
        }
        if prot_loc == 0x1D {
            // ACK delimiter location
            flags.can_ack_error = true;
        }

        flags
    }
}

#[async_trait]
impl BusInterface for SocketCanDriver {
    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn current_safety_tier(&self) -> SafetyTier {
        self.safety_tier
    }

    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError> {
        self.link_params = params.clone();
        if let LinkParams::Can(can_params) = params {
            self.bitrate = can_params.bitrate;
        }
        Ok(())
    }

    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError> {
        self.safety_tier = tier;
        self.listen_only_enforced = tier == SafetyTier::PassiveListenOnly;
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
        if self.safety_tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: self.safety_tier,
            });
        }

        let now = Utc::now();
        if !permit.is_valid_for(self.safety_tier, now) {
            return Err(HalError::PermitRejected);
        }

        let target_scope = match &frame {
            OutboundFrame::Can(c) => format!("CAN:0x{:X}", c.id.as_raw()),
            _ => "CAN".to_string(),
        };
        if !permit.matches_scope(&target_scope) {
            return Err(HalError::InvalidPermit(format!(
                "Permit scope '{:?}' does not match target '{}'",
                permit.scope, target_scope
            )));
        }

        match frame {
            OutboundFrame::Can(can_frame) => {
                let event = RawBusEvent {
                    interface_id: self.interface_name.clone(),
                    timestamp_us: now.timestamp_micros() as u64,
                    link_params: self.link_params.clone(),
                    payload: RawFrame::Can(can_frame),
                    direction: fp_core::Direction::Tx,
                    error_flags: BusErrorFlags::default(),
                };
                let _ = self.tx_sender.send(event);
                Ok(())
            }
            OutboundFrame::Serial(_) => Err(HalError::Io("SocketCAN driver only accepts CAN outbound frames".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketcan_driver_listen_only_default() {
        let driver = SocketCanDriver::new("vcan0");
        assert_eq!(driver.safety_tier, SafetyTier::PassiveListenOnly);
        assert!(driver.listen_only_enforced);
        assert!(driver.verify_listen_only_support());
    }

    #[test]
    fn test_translate_linux_can_error_frame() {
        // Construct standard Linux CAN error frame data:
        // data[2] = 0x04 (CAN_ERR_PROT_STUFF)
        // data[3] = 0x19 (CRC sequence)
        let data = [0x00, 0x00, 0x04, 0x19, 0x00, 0x00, 0x00, 0x00];
        let flags = SocketCanDriver::translate_linux_error_frame(&data);
        assert!(flags.can_stuff_error);
        assert!(flags.can_crc_error);
        assert!(!flags.can_bit_error);
    }

    #[tokio::test]
    async fn test_socketcan_driver_bus_interface_tier0_enforcement() {
        let mut driver = SocketCanDriver::new("can0");
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            Utc::now() + chrono::Duration::minutes(5),
            None,
        );

        let frame = CanFrame::new_standard(0x7DF, &[0x02, 0x01, 0x00]);
        let err = driver.transmit(OutboundFrame::Can(frame.clone()), &permit).await.unwrap_err();
        assert!(matches!(err, HalError::SafetyViolation { .. }));

        // Elevated tier with permit allows transmit
        driver.set_safety_tier(SafetyTier::ReadOnlyProbe).await.unwrap();
        assert!(!driver.listen_only_enforced);

        let res = driver.transmit(OutboundFrame::Can(frame), &permit).await;
        assert!(res.is_ok());
    }
}
