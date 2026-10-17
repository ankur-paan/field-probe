use serde::{Deserialize, Serialize};

/// M-Bus (EN 13757) Frame Types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MbusFrameType {
    SingleCharAck,
    ShortFrame,
    ControlFrame,
    LongFrame,
}

/// M-Bus Device Medium / Utility Type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MbusMedium {
    Other,
    Oil,
    Electricity,
    Gas,
    Heat,
    Steam,
    WarmWater,
    Water,
    HeatCostAllocator,
    CompressedAir,
    CoolingLoadMeter,
    CoolingMeter,
    HeatCoolingMeter,
    BusSystem,
    HotWater,
    ColdWater,
    Unknown(u8),
}

impl From<u8> for MbusMedium {
    fn from(val: u8) -> Self {
        match val {
            0x00 => MbusMedium::Other,
            0x01 => MbusMedium::Oil,
            0x02 => MbusMedium::Electricity,
            0x03 => MbusMedium::Gas,
            0x04 => MbusMedium::Heat,
            0x05 => MbusMedium::Steam,
            0x06 => MbusMedium::WarmWater,
            0x07 => MbusMedium::Water,
            0x08 => MbusMedium::HeatCostAllocator,
            0x09 => MbusMedium::CompressedAir,
            0x0A => MbusMedium::CoolingLoadMeter,
            0x0B => MbusMedium::CoolingMeter,
            0x0C => MbusMedium::HeatCoolingMeter,
            0x0D => MbusMedium::BusSystem,
            0x15 => MbusMedium::HotWater,
            0x16 => MbusMedium::ColdWater,
            other => MbusMedium::Unknown(other),
        }
    }
}

pub fn mbus_medium_name(medium: &MbusMedium) -> &'static str {
    match medium {
        MbusMedium::Other => "Other",
        MbusMedium::Oil => "Oil Meter",
        MbusMedium::Electricity => "Electricity Meter",
        MbusMedium::Gas => "Gas Meter",
        MbusMedium::Heat => "Heat Meter",
        MbusMedium::Steam => "Steam Meter",
        MbusMedium::WarmWater => "Warm Water Meter (30-90 C)",
        MbusMedium::Water => "Water Meter",
        MbusMedium::HeatCostAllocator => "Heat Cost Allocator",
        MbusMedium::CompressedAir => "Compressed Air",
        MbusMedium::CoolingLoadMeter => "Cooling Load Meter",
        MbusMedium::CoolingMeter => "Cooling Meter",
        MbusMedium::HeatCoolingMeter => "Combined Heat/Cooling Meter",
        MbusMedium::BusSystem => "Bus System",
        MbusMedium::HotWater => "Hot Water Meter (>90 C)",
        MbusMedium::ColdWater => "Cold Water Meter",
        MbusMedium::Unknown(_) => "Unknown Medium",
    }
}

/// M-Bus Fixed Header Data (present in Long Frames with CI = 0x72 or 0x76)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MbusFixedHeader {
    pub identification_number: u32,
    pub identification_string: String,
    pub manufacturer: String,
    pub version: u8,
    pub medium: MbusMedium,
    pub medium_name: String,
    pub access_counter: u8,
    pub status: u8,
    pub signature: u16,
}

/// Dissected M-Bus Telegram
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MbusMessage {
    pub frame_type: MbusFrameType,
    pub control_field: u8,
    pub primary_address: u8,
    pub control_information: Option<u8>,
    pub fixed_header: Option<MbusFixedHeader>,
    pub payload: Vec<u8>,
    pub checksum_valid: bool,
}

/// Calculate M-Bus 8-bit checksum (sum modulo 256)
pub fn calculate_mbus_checksum(data: &[u8]) -> u8 {
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    (sum % 256) as u8
}

/// Decode 2-byte manufacturer ID into 3 ASCII uppercase characters (e.g. "KAM")
pub fn decode_mbus_manufacturer(raw: u16) -> String {
    let c1 = (((raw >> 10) & 0x1F) as u8) + b'@';
    let c2 = (((raw >> 5) & 0x1F) as u8) + b'@';
    let c3 = ((raw & 0x1F) as u8) + b'@';
    String::from_utf8_lossy(&[c1, c2, c3]).to_string()
}

/// Decode 4-byte little-endian BCD identification number (e.g. [0x78, 0x56, 0x34, 0x12] -> 12345678)
pub fn decode_bcd_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let mut num: u32 = 0;
    // Little-endian order: byte 3 (most significant) down to byte 0
    for &b in bytes.iter().take(4).rev() {
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        if hi > 9 || lo > 9 {
            return None;
        }
        num = num * 100 + (hi as u32) * 10 + (lo as u32);
    }
    Some(num)
}

/// Dissect raw M-Bus serial frame
pub fn dissect_mbus(data: &[u8]) -> Option<MbusMessage> {
    if data.is_empty() {
        return None;
    }

    // Single Character Acknowledgment: 0xE5
    if data.len() == 1 && data[0] == 0xE5 {
        return Some(MbusMessage {
            frame_type: MbusFrameType::SingleCharAck,
            control_field: 0xE5,
            primary_address: 0,
            control_information: None,
            fixed_header: None,
            payload: Vec::new(),
            checksum_valid: true,
        });
    }

    // Short Frame: [0x10, C, A, CS, 0x16] (5 bytes)
    if data[0] == 0x10 && data.len() == 5 && data[4] == 0x16 {
        let c = data[1];
        let a = data[2];
        let cs = data[3];
        let checksum_valid = calculate_mbus_checksum(&[c, a]) == cs;

        return Some(MbusMessage {
            frame_type: MbusFrameType::ShortFrame,
            control_field: c,
            primary_address: a,
            control_information: None,
            fixed_header: None,
            payload: Vec::new(),
            checksum_valid,
        });
    }

    // Control or Long Frame: [0x68, L, L, 0x68, C, A, CI, ...]
    if data.len() >= 9 && data[0] == 0x68 && data[3] == 0x68 {
        let l1 = data[1];
        let l2 = data[2];
        if l1 != l2 {
            return None;
        }

        let l = l1 as usize;
        let total_expected_len = l + 6;
        if data.len() < total_expected_len || data[total_expected_len - 1] != 0x16 {
            return None;
        }

        let body = &data[4..4 + l];
        let cs = data[4 + l];
        let checksum_valid = calculate_mbus_checksum(body) == cs;

        let c = body[0];
        let a = body[1];
        let ci = body[2];

        if l == 3 {
            // Control Frame: [0x68, 0x03, 0x03, 0x68, C, A, CI, CS, 0x16]
            return Some(MbusMessage {
                frame_type: MbusFrameType::ControlFrame,
                control_field: c,
                primary_address: a,
                control_information: Some(ci),
                fixed_header: None,
                payload: Vec::new(),
                checksum_valid,
            });
        }

        // Long Frame (l > 3)
        let payload = body[3..].to_vec();
        let mut fixed_header = None;

        // Check for standard Variable Data Header (CI == 0x72 or 0x76)
        if (ci == 0x72 || ci == 0x76) && payload.len() >= 12 {
            let id_num = decode_bcd_u32(&payload[0..4]).unwrap_or(0);
            let id_str = format!("{:08}", id_num);
            let mfg_raw = u16::from_le_bytes([payload[4], payload[5]]);
            let manufacturer = decode_mbus_manufacturer(mfg_raw);
            let version = payload[6];
            let medium = MbusMedium::from(payload[7]);
            let medium_name = mbus_medium_name(&medium).to_string();
            let access_counter = payload[8];
            let status = payload[9];
            let signature = u16::from_le_bytes([payload[10], payload[11]]);

            fixed_header = Some(MbusFixedHeader {
                identification_number: id_num,
                identification_string: id_str,
                manufacturer,
                version,
                medium,
                medium_name,
                access_counter,
                status,
                signature,
            });
        }

        return Some(MbusMessage {
            frame_type: MbusFrameType::LongFrame,
            control_field: c,
            primary_address: a,
            control_information: Some(ci),
            fixed_header,
            payload,
            checksum_valid,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_mbus_short_frame() {
        // Short frame: SND_NKE (0x40) to Primary Address 1 (0x01).
        // Checksum = (0x40 + 0x01) % 256 = 0x41. End Delimiter: 0x16.
        let frame = [0x10, 0x40, 0x01, 0x41, 0x16];
        let msg = dissect_mbus(&frame).expect("Dissect M-Bus Short Frame");
        assert_eq!(msg.frame_type, MbusFrameType::ShortFrame);
        assert_eq!(msg.control_field, 0x40);
        assert_eq!(msg.primary_address, 1);
        assert!(msg.checksum_valid);
    }

    #[test]
    fn test_mbus_long_frame_heat_meter() {
        // Long frame from Kamstrup Heat Meter:
        // CI = 0x72 (Variable data structure), ID = 12345678 (BCD [0x78, 0x56, 0x34, 0x12])
        // Manufacturer = "KAM" -> 'K'-'@' = 11, 'A'-'@' = 1, 'M'-'@' = 13
        // raw = (11 << 10) | (1 << 5) | 13 = 11264 | 32 | 13 = 11309 = 0x2C2D -> [0x2D, 0x2C]
        // Version = 0x01, Medium = 0x04 (Heat), Access = 0x05, Status = 0x00, Signature = 0x0000
        let body = vec![
            0x08, // C (RSP_UD)
            0x01, // Primary Address 1
            0x72, // CI (Variable Data)
            0x78, 0x56, 0x34, 0x12, // ID: 12345678
            0x2D, 0x2C, // Mfg: KAM
            0x01, // Version 1
            0x04, // Medium: Heat Meter
            0x05, // Access counter 5
            0x00, // Status OK
            0x00, 0x00, // Signature
        ];

        let l = body.len() as u8;
        let cs = calculate_mbus_checksum(&body);

        let mut frame = vec![0x68, l, l, 0x68];
        frame.extend_from_slice(&body);
        frame.push(cs);
        frame.push(0x16);

        let msg = dissect_mbus(&frame).expect("Dissect M-Bus Long Frame");
        assert_eq!(msg.frame_type, MbusFrameType::LongFrame);
        assert_eq!(msg.primary_address, 1);
        assert!(msg.checksum_valid);

        let header = msg.fixed_header.expect("Fixed header present");
        assert_eq!(header.identification_number, 12345678);
        assert_eq!(header.identification_string, "12345678");
        assert_eq!(header.manufacturer, "KAM");
        assert_eq!(header.medium, MbusMedium::Heat);
        assert_eq!(header.medium_name, "Heat Meter");
    }

    proptest! {
        #[test]
        fn fuzz_mbus_dissector_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = dissect_mbus(&data);
            let _ = calculate_mbus_checksum(&data);
        }
    }
}
