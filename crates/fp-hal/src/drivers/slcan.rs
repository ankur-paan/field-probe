use fp_core::{CanFrame, CanId, HalError, SafetyPermit, SafetyTier};

/// SLCAN (Lawicel ASCII protocol) frame codec and state machine.
/// Implements standard SLCAN parsing and generation with Tier-0 Listen-Only enforcement.
#[derive(Debug, Clone, Default)]
pub struct SlcanCodec {
    buffer: Vec<u8>,
}

impl SlcanCodec {
    pub fn new() -> Self {
        Self { buffer: Vec::with_capacity(256) }
    }

    /// Feed incoming bytes from serial stream and extract parsed CanFrames
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> Vec<CanFrame> {
        let mut frames = Vec::new();
        for &b in bytes {
            if b == b'\r' || b == b'\n' {
                if !self.buffer.is_empty() {
                    if let Ok(frame) = Self::parse_line(&self.buffer) {
                        frames.push(frame);
                    }
                    self.buffer.clear();
                }
            } else if self.buffer.len() < 128 {
                self.buffer.push(b);
            } else {
                // Buffer overflow protection: reset buffer on run-away line
                self.buffer.clear();
            }
        }
        frames
    }

    /// Parse a single SLCAN line into a `CanFrame`
    pub fn parse_line(line: &[u8]) -> Result<CanFrame, HalError> {
        if line.is_empty() {
            return Err(HalError::Io("Empty line".to_string()));
        }

        let cmd = line[0];
        match cmd {
            b't' => {
                // Standard data frame: t<ID:3hex><DLC:1hex><DATA:2*DLC hex>
                if line.len() < 5 {
                    return Err(HalError::Io("Short standard frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..4])
                    .map_err(|_| HalError::Io("Non-UTF8 ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ID".to_string()))?;

                let dlc = (line[4] as char).to_digit(10)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as usize;

                if dlc > 8 || line.len() < 5 + dlc * 2 {
                    return Err(HalError::Io("Mismatched DLC and data length".to_string()));
                }

                let mut data = Vec::with_capacity(dlc);
                for i in 0..dlc {
                    let start = 5 + i * 2;
                    let byte_str = std::str::from_utf8(&line[start..start + 2])
                        .map_err(|_| HalError::Io("Non-UTF8 byte".to_string()))?;
                    let b = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| HalError::Io("Invalid hex data".to_string()))?;
                    data.push(b);
                }

                Ok(CanFrame::new_standard(id_raw as u16, &data))
            }
            b'T' => {
                // Extended data frame: T<ID:8hex><DLC:1hex><DATA:2*DLC hex>
                if line.len() < 10 {
                    return Err(HalError::Io("Short extended frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..9])
                    .map_err(|_| HalError::Io("Non-UTF8 ext ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ext ID".to_string()))?;

                let dlc = (line[9] as char).to_digit(10)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as usize;

                if dlc > 8 || line.len() < 10 + dlc * 2 {
                    return Err(HalError::Io("Mismatched DLC and data length".to_string()));
                }

                let mut data = Vec::with_capacity(dlc);
                for i in 0..dlc {
                    let start = 10 + i * 2;
                    let byte_str = std::str::from_utf8(&line[start..start + 2])
                        .map_err(|_| HalError::Io("Non-UTF8 byte".to_string()))?;
                    let b = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| HalError::Io("Invalid hex data".to_string()))?;
                    data.push(b);
                }

                Ok(CanFrame::new_extended(id_raw, &data))
            }
            b'r' => {
                // Standard remote frame: r<ID:3hex><DLC:1hex>
                if line.len() < 5 {
                    return Err(HalError::Io("Short standard RTR frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..4])
                    .map_err(|_| HalError::Io("Non-UTF8 ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ID".to_string()))?;
                let dlc = (line[4] as char).to_digit(10)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as u8;

                Ok(CanFrame::new_standard_rtr(id_raw as u16, dlc))
            }
            b'R' => {
                // Extended remote frame: R<ID:8hex><DLC:1hex>
                if line.len() < 10 {
                    return Err(HalError::Io("Short extended RTR frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..9])
                    .map_err(|_| HalError::Io("Non-UTF8 ext ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ext ID".to_string()))?;
                let dlc = (line[9] as char).to_digit(10)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as u8;

                Ok(CanFrame::new_extended_rtr(id_raw, dlc))
            }
            b'd' | b'b' => {
                // Standard CAN-FD frame: d/b<ID:3hex><DLC:1hex><DATA:2*len hex>
                if line.len() < 5 {
                    return Err(HalError::Io("Short standard CAN-FD frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..4])
                    .map_err(|_| HalError::Io("Non-UTF8 ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ID".to_string()))?;
                let dlc = (line[4] as char).to_digit(16)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as usize;
                let byte_len = dlc_to_byte_len(dlc);

                if line.len() < 5 + byte_len * 2 {
                    return Err(HalError::Io("Mismatched CAN-FD DLC and data length".to_string()));
                }

                let mut data = Vec::with_capacity(byte_len);
                for i in 0..byte_len {
                    let start = 5 + i * 2;
                    let byte_str = std::str::from_utf8(&line[start..start + 2])
                        .map_err(|_| HalError::Io("Non-UTF8 byte".to_string()))?;
                    let b = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| HalError::Io("Invalid hex data".to_string()))?;
                    data.push(b);
                }

                Ok(CanFrame::new_standard_fd(id_raw as u16, &data))
            }
            b'D' | b'B' => {
                // Extended CAN-FD frame: D/B<ID:8hex><DLC:1hex><DATA:2*len hex>
                if line.len() < 10 {
                    return Err(HalError::Io("Short extended CAN-FD frame".to_string()));
                }
                let id_str = std::str::from_utf8(&line[1..9])
                    .map_err(|_| HalError::Io("Non-UTF8 ext ID".to_string()))?;
                let id_raw = u32::from_str_radix(id_str, 16)
                    .map_err(|_| HalError::Io("Invalid hex ext ID".to_string()))?;
                let dlc = (line[9] as char).to_digit(16)
                    .ok_or_else(|| HalError::Io("Invalid DLC".to_string()))? as usize;
                let byte_len = dlc_to_byte_len(dlc);

                if line.len() < 10 + byte_len * 2 {
                    return Err(HalError::Io("Mismatched CAN-FD DLC and data length".to_string()));
                }

                let mut data = Vec::with_capacity(byte_len);
                for i in 0..byte_len {
                    let start = 10 + i * 2;
                    let byte_str = std::str::from_utf8(&line[start..start + 2])
                        .map_err(|_| HalError::Io("Non-UTF8 byte".to_string()))?;
                    let b = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| HalError::Io("Invalid hex data".to_string()))?;
                    data.push(b);
                }

                Ok(CanFrame::new_extended_fd(id_raw, &data))
            }
            _ => Err(HalError::Io(format!("Unsupported SLCAN command: {}", cmd as char))),
        }
    }

    /// Format a CanFrame into SLCAN ASCII command for transmission.
    /// STRICT INVARIANT: Requires active safety tier >= ReadOnlyProbe and valid SafetyPermit.
    pub fn encode_frame(
        frame: &CanFrame,
        tier: SafetyTier,
        permit: &SafetyPermit,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, HalError> {
        if tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: tier,
            });
        }

        if !permit.is_valid_for(tier, now) {
            return Err(HalError::PermitRejected);
        }

        match frame.id {
            CanId::Standard(id) => {
                if frame.is_rtr {
                    Ok(format!("r{:03X}{}\r", id & 0x7FF, frame.dlc))
                } else if frame.is_fd {
                    let mut s = format!("d{:03X}{:X}", id & 0x7FF, frame.dlc);
                    for b in &frame.data {
                        s.push_str(&format!("{:02X}", b));
                    }
                    s.push('\r');
                    Ok(s)
                } else {
                    let mut s = format!("t{:03X}{}", id & 0x7FF, frame.dlc);
                    for b in &frame.data {
                        s.push_str(&format!("{:02X}", b));
                    }
                    s.push('\r');
                    Ok(s)
                }
            }
            CanId::Extended(id) => {
                if frame.is_rtr {
                    Ok(format!("R{:08X}{}\r", id & 0x1FFFFFFF, frame.dlc))
                } else if frame.is_fd {
                    let mut s = format!("D{:08X}{:X}", id & 0x1FFFFFFF, frame.dlc);
                    for b in &frame.data {
                        s.push_str(&format!("{:02X}", b));
                    }
                    s.push('\r');
                    Ok(s)
                } else {
                    let mut s = format!("T{:08X}{}", id & 0x1FFFFFFF, frame.dlc);
                    for b in &frame.data {
                        s.push_str(&format!("{:02X}", b));
                    }
                    s.push('\r');
                    Ok(s)
                }
            }
        }
    }

    /// Generate initialization command sequence for SLCAN adapter.
    /// By default sends `C\r` (close), `S<rate>\r` (set bitrate), and `L\r` (open in LISTEN-ONLY mode).
    pub fn init_commands(bitrate: u32, listen_only: bool) -> Vec<String> {
        let speed_cmd = match bitrate {
            10_000 => "S0\r",
            20_000 => "S1\r",
            50_000 => "S2\r",
            100_000 => "S3\r",
            125_000 => "S4\r",
            250_000 => "S5\r",
            500_000 => "S6\r",
            800_000 => "S7\r",
            1_000_000 => "S8\r",
            _ => "S6\r", // Default 500 kbps
        };

        let open_cmd = if listen_only {
            "L\r" // Open in listen-only mode (Zero-TX hardware enforced)
        } else {
            "O\r" // Open in normal mode (TX allowed)
        };

        vec!["C\r".to_string(), speed_cmd.to_string(), open_cmd.to_string()]
    }
}

fn dlc_to_byte_len(dlc: usize) -> usize {
    match dlc {
        0..=8 => dlc,
        9 => 12,
        10 => 16,
        11 => 20,
        12 => 24,
        13 => 32,
        14 => 48,
        15 => 64,
        _ => 64,
    }
}

use async_trait::async_trait;
use fp_core::{AdapterCapabilities, IndustrialChip, LinkParams, OutboundFrame, RawBusEvent};
use tokio::sync::broadcast;
use crate::interface::BusInterface;

/// Asynchronous SLCAN serial hardware driver implementing BusInterface.
/// Defaults to Tier-0 PassiveListenOnly with hardware command `L\r`.
pub struct SlcanDriver {
    pub interface_name: String,
    pub capabilities: AdapterCapabilities,
    tier: SafetyTier,
    link_params: LinkParams,
    tx_sender: broadcast::Sender<RawBusEvent>,
    codec: SlcanCodec,
    pub connect_commands: Vec<String>,
}

impl SlcanDriver {
    pub fn new(interface_name: impl Into<String>, bitrate: u32, broadcast_cap: usize) -> Self {
        let name = interface_name.into();
        let (tx, _rx) = broadcast::channel(broadcast_cap);
        let caps = AdapterCapabilities {
            interface_id: name.clone(),
            chip_type: IndustrialChip::LawicelSlcan,
            supports_serial: true,
            supports_can: true,
            supports_can_fd: true,
            supports_listen_only: true,
            supported_baud_rates: vec![115200, 230400, 921600],
            supported_can_bitrates: vec![10_000, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 800_000, 1_000_000],
            usb_vid: Some(0x0403),
            usb_pid: Some(0x6001),
            serial_number: Some("CANUSB-001".to_string()),
            description: format!("SLCAN Adapter ({})", name),
        };

        // Invariant: Always start with listen_only = true ("L\r")
        let connect_commands = SlcanCodec::init_commands(bitrate, true);

        Self {
            interface_name: name,
            capabilities: caps,
            tier: SafetyTier::PassiveListenOnly,
            link_params: LinkParams::Can(fp_core::CanParams {
                bitrate,
                ..Default::default()
            }),
            tx_sender: tx,
            codec: SlcanCodec::new(),
            connect_commands,
        }
    }

    /// Process incoming serial bytes received from the SLCAN dongle
    pub fn ingest_bytes(&mut self, bytes: &[u8], timestamp_us: u64) {
        let frames = self.codec.feed_bytes(bytes);
        for frame in frames {
            let event = RawBusEvent::new_can_rx(
                &self.interface_name,
                timestamp_us,
                self.link_params.clone(),
                frame,
            );
            let _ = self.tx_sender.send(event);
        }
    }
}

#[async_trait]
impl BusInterface for SlcanDriver {
    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn current_safety_tier(&self) -> SafetyTier {
        self.tier
    }

    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError> {
        self.link_params = params.clone();
        if let LinkParams::Can(can_params) = params {
            self.connect_commands = SlcanCodec::init_commands(can_params.bitrate, self.tier == SafetyTier::PassiveListenOnly);
        }
        Ok(())
    }

    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError> {
        self.tier = tier;
        let bitrate = match &self.link_params {
            LinkParams::Can(can_params) => can_params.bitrate,
            _ => 500_000,
        };
        self.connect_commands = SlcanCodec::init_commands(bitrate, tier == SafetyTier::PassiveListenOnly);
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
        if self.tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: self.tier,
            });
        }

        let now = chrono::Utc::now();
        if !permit.is_valid_for(self.tier, now) {
            return Err(HalError::PermitRejected);
        }

        match frame {
            OutboundFrame::Can(can_frame) => {
                let _slcan_cmd = SlcanCodec::encode_frame(&can_frame, self.tier, permit, now)?;
                let event = RawBusEvent {
                    interface_id: self.interface_name.clone(),
                    timestamp_us: now.timestamp_micros() as u64,
                    link_params: self.link_params.clone(),
                    payload: fp_core::RawFrame::Can(can_frame),
                    direction: fp_core::Direction::Tx,
                    error_flags: fp_core::BusErrorFlags::default(),
                };
                let _ = self.tx_sender.send(event);
                Ok(())
            }
            OutboundFrame::Serial(_) => Err(HalError::Io("SLCAN driver only accepts CAN outbound frames".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slcan_parse_standard_frame() {
        let line = b"t123411223344\r";
        let mut codec = SlcanCodec::new();
        let frames = codec.feed_bytes(line);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id, CanId::Standard(0x123));
        assert_eq!(frames[0].data.as_ref(), &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_slcan_parse_extended_frame() {
        let line = b"T0CF0040081122334455667788\r";
        let mut codec = SlcanCodec::new();
        let frames = codec.feed_bytes(line);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id, CanId::Extended(0x0CF00400));
        assert_eq!(frames[0].data.len(), 8);
    }

    #[test]
    fn test_slcan_zero_tx_enforcement() {
        let frame = CanFrame::new_standard(0x100, &[1, 2]);
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            chrono::Utc::now() + chrono::Duration::minutes(5),
            None,
        );

        let err = SlcanCodec::encode_frame(
            &frame,
            SafetyTier::PassiveListenOnly,
            &permit,
            chrono::Utc::now(),
        ).unwrap_err();

        assert!(matches!(err, HalError::SafetyViolation { .. }));
    }

    #[test]
    fn test_slcan_init_commands_listen_only() {
        let cmds = SlcanCodec::init_commands(500_000, true);
        assert_eq!(cmds, vec!["C\r", "S6\r", "L\r"]);
    }

    #[test]
    fn test_slcan_parse_and_encode_rtr_frames() {
        // Standard RTR
        let line_rtr_std = b"r1234\r";
        let frame_std = SlcanCodec::parse_line(line_rtr_std).expect("Parsed std RTR");
        assert_eq!(frame_std.id, CanId::Standard(0x123));
        assert_eq!(frame_std.dlc, 4);
        assert!(frame_std.is_rtr);
        assert_eq!(frame_std.data.len(), 0);

        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            chrono::Utc::now() + chrono::Duration::minutes(5),
            None,
        );
        let encoded_std = SlcanCodec::encode_frame(&frame_std, SafetyTier::ReadOnlyProbe, &permit, chrono::Utc::now()).unwrap();
        assert_eq!(encoded_std, "r1234\r");

        // Extended RTR
        let line_rtr_ext = b"R000004568\r";
        let frame_ext = SlcanCodec::parse_line(line_rtr_ext).expect("Parsed ext RTR");
        assert_eq!(frame_ext.id, CanId::Extended(0x456));
        assert_eq!(frame_ext.dlc, 8);
        assert!(frame_ext.is_rtr);

        let encoded_ext = SlcanCodec::encode_frame(&frame_ext, SafetyTier::ReadOnlyProbe, &permit, chrono::Utc::now()).unwrap();
        assert_eq!(encoded_ext, "R000004568\r");
    }

    #[test]
    fn test_slcan_parse_and_encode_canfd_frames() {
        // Standard CAN-FD
        let line_fd_std = b"d1234AABBCCDD\r";
        let frame_std = SlcanCodec::parse_line(line_fd_std).expect("Parsed std CAN-FD");
        assert_eq!(frame_std.id, CanId::Standard(0x123));
        assert_eq!(frame_std.data.as_ref(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(frame_std.is_fd);

        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            chrono::Utc::now() + chrono::Duration::minutes(5),
            None,
        );
        let encoded_std = SlcanCodec::encode_frame(&frame_std, SafetyTier::ReadOnlyProbe, &permit, chrono::Utc::now()).unwrap();
        assert_eq!(encoded_std, "d1234AABBCCDD\r");
    }

    #[tokio::test]
    async fn test_slcan_driver_bus_interface_tier0_zero_tx() {
        let mut driver = SlcanDriver::new("slcan0", 500_000, 100);
        assert_eq!(driver.current_safety_tier(), SafetyTier::PassiveListenOnly);
        assert_eq!(driver.connect_commands, vec!["C\r", "S6\r", "L\r"]);

        let mut rx = driver.subscribe_rx();

        // Feed bytes and verify broadcast
        driver.ingest_bytes(b"t1232AABB\r", 1_000_000);
        let event = rx.recv().await.expect("Received broadcast event");
        assert_eq!(event.interface_id, "slcan0");
        if let fp_core::RawFrame::Can(frame) = event.payload {
            assert_eq!(frame.id, CanId::Standard(0x123));
            assert_eq!(frame.data.as_ref(), &[0xAA, 0xBB]);
        } else {
            panic!("Expected CAN frame");
        }

        // Verify zero-tx invariant
        let frame = CanFrame::new_standard(0x100, &[1, 2]);
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            chrono::Utc::now() + chrono::Duration::minutes(5),
            None,
        );
        let err = driver.transmit(OutboundFrame::Can(frame), &permit).await.unwrap_err();
        assert!(matches!(err, HalError::SafetyViolation { .. }));
    }
}
