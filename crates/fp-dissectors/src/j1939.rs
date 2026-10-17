use serde::{Deserialize, Serialize};

/// SAE J1939 29-bit CAN ID fields
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct J1939Header {
    pub priority: u8,
    pub data_page: u8,
    pub pdu_format: u8,
    pub pdu_specific: u8,
    pub source_address: u8,
    pub pgn: u32,
    pub is_pdu1: bool,
    pub destination_address: Option<u8>,
}

/// Standard J1939 Parameter Group Numbers (PGNs)
pub const PGN_EEC1: u32 = 61444; // 0x00F004 - Electronic Engine Controller 1
pub const PGN_EEC2: u32 = 61443; // 0x00F003 - Electronic Engine Controller 2
pub const PGN_ET1: u32 = 65262;  // 0x00FEEE - Engine Temperature 1
pub const PGN_CCVS1: u32 = 65265;// 0x00FEF1 - Cruise Control/Vehicle Speed 1
pub const PGN_ADDRESS_CLAIMED: u32 = 60928; // 0x00EE00

/// High-level decoded J1939 signal payloads
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum J1939Payload {
    /// PGN 61444 (EEC1)
    EngineController1 {
        engine_speed_rpm: f32,
        actual_engine_torque_percent: i8,
        drivers_demand_torque_percent: i8,
    },
    /// PGN 61443 (EEC2)
    EngineController2 {
        accelerator_pedal_position_percent: f32,
        engine_percent_load_at_current_speed: u8,
    },
    /// PGN 65262 (ET1)
    EngineTemperature1 {
        coolant_temp_deg_c: i16,
        fuel_temp_deg_c: i16,
        oil_temp_deg_c: i16,
    },
    /// PGN 65265 (CCVS1)
    VehicleSpeed1 {
        wheel_based_vehicle_speed_kmh: f32,
        parking_brake_switch_active: bool,
    },
    /// General or unrecognized PGN
    Generic {
        pgn: u32,
        name: String,
        data: Vec<u8>,
    },
}

/// Fully dissected J1939 Frame
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct J1939Message {
    pub header: J1939Header,
    pub payload: J1939Payload,
}

/// Dissects a 29-bit CAN ID into J1939 header fields as per SAE J1939-21
pub fn parse_j1939_header(can_id: u32) -> J1939Header {
    // 29-bit CAN ID:
    // Bits 28-26: Priority (3 bits)
    // Bit 25: Reserved (1 bit)
    // Bit 24: Data Page (1 bit)
    // Bits 23-16: PDU Format (PF, 8 bits)
    // Bits 15-8: PDU Specific (PS, 8 bits)
    // Bits 7-0: Source Address (SA, 8 bits)
    let priority = ((can_id >> 26) & 0x07) as u8;
    let data_page = ((can_id >> 24) & 0x01) as u8;
    let pdu_format = ((can_id >> 16) & 0xFF) as u8;
    let pdu_specific = ((can_id >> 8) & 0xFF) as u8;
    let source_address = (can_id & 0xFF) as u8;

    let is_pdu1 = pdu_format < 240;
    let (pgn, destination_address) = if is_pdu1 {
        // PDU1 Format: Destination Specific; PS is Destination Address (DA)
        let pgn = ((data_page as u32) << 16) | ((pdu_format as u32) << 8);
        (pgn, Some(pdu_specific))
    } else {
        // PDU2 Format: Broadcast; PS is Group Extension (GE)
        let pgn = ((data_page as u32) << 16) | ((pdu_format as u32) << 8) | (pdu_specific as u32);
        (pgn, None)
    };

    J1939Header {
        priority,
        data_page,
        pdu_format,
        pdu_specific,
        source_address,
        pgn,
        is_pdu1,
        destination_address,
    }
}

/// Dissect raw CAN frame into J1939 message with physical signal extraction
pub fn dissect_j1939(can_id: u32, data: &[u8]) -> Option<J1939Message> {
    let header = parse_j1939_header(can_id);

    let payload = match header.pgn {
        PGN_EEC1 if data.len() >= 8 => {
            // Actual Engine % Torque: Byte 2 (0-indexed 1) - 125% offset, 1%/bit
            let actual_engine_torque_percent = (data[2] as i16 - 125) as i8;
            // Driver's Demand % Torque: Byte 1 (0-indexed 1) - 125% offset
            let drivers_demand_torque_percent = (data[1] as i16 - 125) as i8;
            // Engine Speed: Bytes 3-4 (0-indexed 3,4), Little-Endian, 0.125 RPM/bit
            let raw_speed = u16::from_le_bytes([data[3], data[4]]);
            let engine_speed_rpm = (raw_speed as f32) * 0.125;

            J1939Payload::EngineController1 {
                engine_speed_rpm,
                actual_engine_torque_percent,
                drivers_demand_torque_percent,
            }
        }
        PGN_EEC2 if data.len() >= 8 => {
            // Accelerator Pedal 1: Byte 1, 0.4%/bit
            let accelerator_pedal_position_percent = (data[1] as f32) * 0.4;
            // Percent Load at Current Speed: Byte 2, 1%/bit
            let engine_percent_load_at_current_speed = data[2];

            J1939Payload::EngineController2 {
                accelerator_pedal_position_percent,
                engine_percent_load_at_current_speed,
            }
        }
        PGN_ET1 if data.len() >= 8 => {
            // Coolant Temp: Byte 0, 1 deg C/bit, -40 offset
            let coolant_temp_deg_c = data[0] as i16 - 40;
            // Fuel Temp: Byte 1, 1 deg C/bit, -40 offset
            let fuel_temp_deg_c = data[1] as i16 - 40;
            // Oil Temp: Bytes 2-3, 0.03125 deg C/bit, -273 offset
            let raw_oil = u16::from_le_bytes([data[2], data[3]]);
            let oil_temp_deg_c = ((raw_oil as f32 * 0.03125) - 273.0) as i16;

            J1939Payload::EngineTemperature1 {
                coolant_temp_deg_c,
                fuel_temp_deg_c,
                oil_temp_deg_c,
            }
        }
        PGN_CCVS1 if data.len() >= 8 => {
            // Parking Brake Switch: Byte 0, bits 2-3
            let parking_brake_switch_active = ((data[0] >> 2) & 0x03) == 0x01;
            // Wheel-Based Vehicle Speed: Bytes 1-2, 1/256 km/h per bit
            let raw_speed = u16::from_le_bytes([data[1], data[2]]);
            let wheel_based_vehicle_speed_kmh = (raw_speed as f32) / 256.0;

            J1939Payload::VehicleSpeed1 {
                wheel_based_vehicle_speed_kmh,
                parking_brake_switch_active,
            }
        }
        _ => J1939Payload::Generic {
            pgn: header.pgn,
            name: pgn_name(header.pgn).to_string(),
            data: data.to_vec(),
        },
    };

    Some(J1939Message { header, payload })
}

fn pgn_name(pgn: u32) -> &'static str {
    match pgn {
        PGN_EEC1 => "Electronic Engine Controller 1 (EEC1)",
        PGN_EEC2 => "Electronic Engine Controller 2 (EEC2)",
        PGN_ET1 => "Engine Temperature 1 (ET1)",
        PGN_CCVS1 => "Cruise Control/Vehicle Speed (CCVS1)",
        PGN_ADDRESS_CLAIMED => "Address Claimed",
        _ => "Proprietary or Unregistered PGN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_j1939_header_pdu1_destination_specific() {
        // Priority 6 (0x18), Data Page 0, PF 0xEF (239 < 240, PDU1), DA 0x05, SA 0x01
        // ID: (6 << 26) | (0xEF << 16) | (0x05 << 8) | 0x01 = 0x18EF0501
        let id = 0x18EF0501;
        let hdr = parse_j1939_header(id);
        assert_eq!(hdr.priority, 6);
        assert_eq!(hdr.data_page, 0);
        assert_eq!(hdr.pdu_format, 0xEF);
        assert_eq!(hdr.pdu_specific, 0x05);
        assert_eq!(hdr.source_address, 0x01);
        assert!(hdr.is_pdu1);
        assert_eq!(hdr.destination_address, Some(0x05));
        assert_eq!(hdr.pgn, 0xEF00);
    }

    #[test]
    fn test_j1939_eec1_dissection() {
        // Priority 3, PGN 61444 (0xF004), SA 0x00 -> 0x0CF00400
        let id = 0x0CF00400;
        // Data: [0xFF, 0x7D (0% demand), 0x7D (0% actual), 0x00, 0x20 (8192 => 1024 RPM), 0xFF, 0xFF, 0xFF]
        let data = [0xFF, 0x7D, 0x7D, 0x00, 0x20, 0xFF, 0xFF, 0xFF];
        let msg = dissect_j1939(id, &data).expect("Dissected EEC1");
        assert_eq!(msg.header.pgn, PGN_EEC1);
        match msg.payload {
            J1939Payload::EngineController1 {
                engine_speed_rpm,
                actual_engine_torque_percent,
                drivers_demand_torque_percent,
            } => {
                assert_eq!(actual_engine_torque_percent, 0); // 0x7D = 125 - 125 = 0%
                assert_eq!(drivers_demand_torque_percent, 0);
                assert_eq!(engine_speed_rpm, 1024.0); // 0x2000 = 8192 * 0.125 = 1024.0
            }
            _ => panic!("Expected EngineController1"),
        }
    }

    proptest::proptest! {
        #[test]
        fn fuzz_j1939_dissector_never_panics(id in any::<u32>(), data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = dissect_j1939(id, &data);
            let _ = parse_j1939_header(id);
        }
    }
}
