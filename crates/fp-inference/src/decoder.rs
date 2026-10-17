use serde::{Deserialize, Serialize};

/// Value decoded into a specific data representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InferredValue {
    UInt16(u16),
    Int16(i16),
    UInt32(u32),
    Int32(i32),
    Float32(f32),
    Float64(f64),
    Ascii(String),
    Bitfield(u16),
    Mod10000(u64),
    FixedPoint {
        raw: i32,
        scale: f32,
        scaled_val: f32,
        unit: Option<String>,
    },
}

/// Endianness byte-swapping order for multi-register values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WordOrder {
    /// Big-endian words, big-endian bytes (ABCD) - Standard IEEE
    Abcd,
    /// Little-endian words, big-endian bytes (CDAB) - Common in Modbus
    Cdab,
    /// Big-endian words, little-endian bytes (BADC) - Mid-big endian
    Badc,
    /// Little-endian words, little-endian bytes (DCBA) - True little-endian
    Dcba,
}

/// Decode two 16-bit registers [r0, r1] into raw 4 bytes using specified word order
pub fn word_order_to_bytes(r0: u16, r1: u16, order: WordOrder) -> [u8; 4] {
    let b0 = (r0 >> 8) as u8;
    let b1 = (r0 & 0xFF) as u8;
    let b2 = (r1 >> 8) as u8;
    let b3 = (r1 & 0xFF) as u8;

    match order {
        WordOrder::Abcd => [b0, b1, b2, b3],
        WordOrder::Cdab => [b2, b3, b0, b1],
        WordOrder::Badc => [b1, b0, b3, b2],
        WordOrder::Dcba => [b3, b2, b1, b0],
    }
}

/// Decode two 16-bit registers [r0, r1] into Float32 with specified word/byte swapping
pub fn decode_float32(r0: u16, r1: u16, order: WordOrder) -> f32 {
    let bytes = word_order_to_bytes(r0, r1, order);
    f32::from_be_bytes(bytes)
}

/// Decode two 16-bit registers [r0, r1] into UInt32
pub fn decode_uint32(r0: u16, r1: u16, order: WordOrder) -> u32 {
    let bytes = word_order_to_bytes(r0, r1, order);
    u32::from_be_bytes(bytes)
}

/// Decode two 16-bit registers [r0, r1] into Int32
pub fn decode_int32(r0: u16, r1: u16, order: WordOrder) -> i32 {
    let bytes = word_order_to_bytes(r0, r1, order);
    i32::from_be_bytes(bytes)
}

/// Decode four 16-bit registers into Float64 (Double Precision)
pub fn decode_float64(r0: u16, r1: u16, r2: u16, r3: u16, order: WordOrder) -> f64 {
    let mut bytes = [0u8; 8];
    match order {
        WordOrder::Abcd => {
            bytes[0..4].copy_from_slice(&word_order_to_bytes(r0, r1, WordOrder::Abcd));
            bytes[4..8].copy_from_slice(&word_order_to_bytes(r2, r3, WordOrder::Abcd));
        }
        WordOrder::Cdab => {
            bytes[0..4].copy_from_slice(&word_order_to_bytes(r2, r3, WordOrder::Cdab));
            bytes[4..8].copy_from_slice(&word_order_to_bytes(r0, r1, WordOrder::Cdab));
        }
        WordOrder::Badc => {
            bytes[0..4].copy_from_slice(&word_order_to_bytes(r0, r1, WordOrder::Badc));
            bytes[4..8].copy_from_slice(&word_order_to_bytes(r2, r3, WordOrder::Badc));
        }
        WordOrder::Dcba => {
            bytes[0..4].copy_from_slice(&word_order_to_bytes(r3, r2, WordOrder::Dcba));
            bytes[4..8].copy_from_slice(&word_order_to_bytes(r1, r0, WordOrder::Dcba));
        }
    }
    f64::from_be_bytes(bytes)
}

/// Decode two 16-bit registers using Mod10000 format standard in energy/flow meters:
/// `total = r1 * 10,000 + r0`
pub fn decode_mod10000(r0: u16, r1: u16) -> u64 {
    (r1 as u64) * 10_000 + (r0 as u64)
}

/// Decode printable ASCII string from a slice of 16-bit registers
pub fn decode_ascii_string(registers: &[u16]) -> Option<String> {
    if registers.is_empty() {
        return None;
    }

    let mut bytes = Vec::with_capacity(registers.len() * 2);
    for &reg in registers {
        let hi = (reg >> 8) as u8;
        let lo = (reg & 0xFF) as u8;
        bytes.push(hi);
        bytes.push(lo);
    }

    // Check if non-null characters are printable ASCII (0x20..=0x7E or 0x00 at the end)
    let mut s = String::new();
    for &b in &bytes {
        if b == 0x00 {
            // Null terminator allowed at tail
            continue;
        }
        if (0x20..=0x7E).contains(&b) {
            s.push(b as char);
        } else {
            return None;
        }
    }

    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Decode 16-bit unsigned integer with fixed-point scale factor (e.g. 0.1, 0.01)
pub fn decode_fixed_point_u16(val: u16, scale: f32) -> f32 {
    (val as f32) * scale
}

/// Decode 16-bit signed integer with fixed-point scale factor (e.g. 0.1, 0.01)
pub fn decode_fixed_point_i16(val: i16, scale: f32) -> f32 {
    (val as f32) * scale
}

/// Evaluates adjacent 16-bit register pair across all primary representations
pub fn decode_register_representations(r0: u16, r1: u16) -> Vec<(WordOrder, f32)> {
    vec![
        (WordOrder::Abcd, decode_float32(r0, r1, WordOrder::Abcd)),
        (WordOrder::Cdab, decode_float32(r0, r1, WordOrder::Cdab)),
        (WordOrder::Badc, decode_float32(r0, r1, WordOrder::Badc)),
        (WordOrder::Dcba, decode_float32(r0, r1, WordOrder::Dcba)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float32_word_orders() {
        // 23.45 in IEEE 754: 0x41BB999A
        let val_cdab = decode_float32(0x999A, 0x41BB, WordOrder::Cdab);
        assert!((val_cdab - 23.45).abs() < 0.01);

        let val_abcd = decode_float32(0x41BB, 0x999A, WordOrder::Abcd);
        assert!((val_abcd - 23.45).abs() < 0.01);
    }

    #[test]
    fn test_uint32_and_int32() {
        assert_eq!(decode_uint32(0x1234, 0x5678, WordOrder::Abcd), 0x12345678);
        assert_eq!(decode_uint32(0x5678, 0x1234, WordOrder::Cdab), 0x12345678);
        assert_eq!(decode_int32(0xFFFF, 0xFFFE, WordOrder::Abcd), -2);
    }

    #[test]
    fn test_ascii_string_decoding() {
        // "TEST" -> 'T'=0x54, 'E'=0x45, 'S'=0x53, 'T'=0x54
        // r0 = 0x5445, r1 = 0x5354
        let regs = [0x5445, 0x5354];
        let s = decode_ascii_string(&regs).expect("Decodes ASCII");
        assert_eq!(s, "TEST");

        // Non-printable character rejected
        let invalid_regs = [0x5445, 0x00FF];
        assert_eq!(decode_ascii_string(&invalid_regs), None);
    }

    #[test]
    fn test_mod10000_totalizer() {
        // r1 = 3 (30,000), r0 = 4521 => 34,521
        assert_eq!(decode_mod10000(4521, 3), 34521);
    }

    #[test]
    fn test_fixed_point_scaling() {
        // 2300 * 0.1 = 230.0 V
        assert!((decode_fixed_point_u16(2300, 0.1) - 230.0).abs() < 0.001);
        // 5000 * 0.01 = 50.00 Hz
        assert!((decode_fixed_point_u16(5000, 0.01) - 50.0).abs() < 0.001);
        // -250 * 0.1 = -25.0 °C
        assert!((decode_fixed_point_i16(-250, 0.1) - (-25.0)).abs() < 0.001);
    }
}
