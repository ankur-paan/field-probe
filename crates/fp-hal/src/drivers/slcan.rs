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
                let mut s = format!("t{:03X}{}", id & 0x7FF, frame.dlc);
                for b in &frame.data {
                    s.push_str(&format!("{:02X}", b));
                }
                s.push('\r');
                Ok(s)
            }
            CanId::Extended(id) => {
                let mut s = format!("T{:08X}{}", id & 0x1FFFFFFF, frame.dlc);
                for b in &frame.data {
                    s.push_str(&format!("{:02X}", b));
                }
                s.push('\r');
                Ok(s)
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
}
