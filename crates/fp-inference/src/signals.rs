use serde::{Deserialize, Serialize};

/// Byte ordering for CAN signal unpacking (from CAN DBC specification)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalByteOrder {
    /// Intel (Little-Endian)
    LittleEndian,
    /// Motorola (Big-Endian)
    BigEndian,
}

/// Definition of an engineering signal embedded in a CAN frame payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalDefinition {
    pub name: String,
    pub start_bit: usize,
    pub bit_length: usize,
    pub byte_order: SignalByteOrder,
    pub is_signed: bool,
    pub scale: f64,
    pub offset: f64,
    pub unit: String,
}

impl SignalDefinition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        start_bit: usize,
        bit_length: usize,
        byte_order: SignalByteOrder,
        is_signed: bool,
        scale: f64,
        offset: f64,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            start_bit,
            bit_length,
            byte_order,
            is_signed,
            scale,
            offset,
            unit: unit.into(),
        }
    }

    /// Extract raw integer bits from payload according to Intel/Motorola conventions
    pub fn extract_raw_u64(&self, payload: &[u8]) -> Option<u64> {
        if self.bit_length == 0 || self.bit_length > 64 {
            return None;
        }

        let mut raw: u64 = 0;

        match self.byte_order {
            SignalByteOrder::LittleEndian => {
                // Intel format: consecutive bits starting from start_bit ascending
                for i in 0..self.bit_length {
                    let bit_index = self.start_bit + i;
                    let byte_index = bit_index / 8;
                    let bit_in_byte = bit_index % 8;

                    if byte_index >= payload.len() {
                        return None;
                    }

                    let bit_val = ((payload[byte_index] >> bit_in_byte) & 0x01) as u64;
                    raw |= bit_val << i;
                }
            }
            SignalByteOrder::BigEndian => {
                // Motorola format (sawtooth layout standard in Vector DBC):
                // Bits are read downwards MSB to LSB
                for i in 0..self.bit_length {
                    let current_bit = self.start_bit.saturating_sub(i);
                    let byte_index = current_bit / 8;
                    let bit_in_byte = current_bit % 8;

                    if byte_index >= payload.len() {
                        return None;
                    }

                    let bit_val = ((payload[byte_index] >> bit_in_byte) & 0x01) as u64;
                    let target_shift = self.bit_length - 1 - i;
                    raw |= bit_val << target_shift;
                }
            }
        }

        Some(raw)
    }

    /// Unpack payload into physical engineering value: (raw * scale) + offset
    pub fn unpack(&self, payload: &[u8]) -> Option<f64> {
        let raw = self.extract_raw_u64(payload)?;

        let num = if self.is_signed {
            // Sign-extend if MSB is set
            let sign_bit = 1u64 << (self.bit_length - 1);
            if (raw & sign_bit) != 0 {
                let mask = (!0u64) << self.bit_length;
                (raw | mask) as i64 as f64
            } else {
                raw as f64
            }
        } else {
            raw as f64
        };

        Some((num * self.scale) + self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_signal_unpacking() {
        // Vehicle speed: 16 bits, start_bit 8 (Byte 1), scale 0.01, offset 0.0, LittleEndian
        let speed_sig = SignalDefinition::new(
            "WheelSpeed",
            8,
            16,
            SignalByteOrder::LittleEndian,
            false,
            0.01,
            0.0,
            "km/h",
        );

        // Payload with 100.00 km/h => raw = 10000 = 0x2710
        // Byte 0 = 0x00, Byte 1 = 0x10, Byte 2 = 0x27
        let payload = [0x00, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00];
        let val = speed_sig.unpack(&payload).expect("Unpacked speed");
        assert!((val - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_signed_temperature_unpacking() {
        // Temperature: 8 bits, start_bit 0, scale 1.0, offset -40.0, signed
        let temp_sig = SignalDefinition::new(
            "CoolantTemp",
            0,
            8,
            SignalByteOrder::LittleEndian,
            false, // raw 0..255 with offset -40 is standard J1939
            1.0,
            -40.0,
            "degC",
        );

        // Raw 65 => 65 - 40 = 25 deg C
        let payload = [65, 0, 0, 0, 0, 0, 0, 0];
        let val = temp_sig.unpack(&payload).expect("Unpacked temp");
        assert_eq!(val, 25.0);
    }
}
