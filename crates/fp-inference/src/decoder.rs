use serde::{Deserialize, Serialize};

/// Value decoded into a specific data representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InferredValue {
    UInt16(u16),
    Int16(i16),
    UInt32(u32),
    Int32(i32),
    Float32(f32),
    Ascii(String),
    Bitfield(u16),
}

/// Endianness byte-swapping order for 32-bit floating point and integer values
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

/// Decode two 16-bit registers [r0, r1] into Float32 with specified word/byte swapping
pub fn decode_float32(r0: u16, r1: u16, order: WordOrder) -> f32 {
    let b0 = (r0 >> 8) as u8;
    let b1 = (r0 & 0xFF) as u8;
    let b2 = (r1 >> 8) as u8;
    let b3 = (r1 & 0xFF) as u8;

    let bytes = match order {
        WordOrder::Abcd => [b0, b1, b2, b3],
        WordOrder::Cdab => [b2, b3, b0, b1],
        WordOrder::Badc => [b1, b0, b3, b2],
        WordOrder::Dcba => [b3, b2, b1, b0],
    };

    f32::from_be_bytes(bytes)
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
        // Representation of 23.45 in IEEE 754: 0x41BB999A
        // In CDAB (Modbus swapped): r0 = 0x999A, r1 = 0x41BB
        let val_cdab = decode_float32(0x999A, 0x41BB, WordOrder::Cdab);
        assert!((val_cdab - 23.45).abs() < 0.01);

        // In ABCD: r0 = 0x41BB, r1 = 0x999A
        let val_abcd = decode_float32(0x41BB, 0x999A, WordOrder::Abcd);
        assert!((val_abcd - 23.45).abs() < 0.01);
    }
}
