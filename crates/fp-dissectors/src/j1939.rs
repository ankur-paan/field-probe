use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
pub const PGN_EBC1: u32 = 61441; // 0x00F001 - Electronic Brake Controller 1
pub const PGN_ETC1: u32 = 61442; // 0x00F002 - Electronic Transmission Controller 1
pub const PGN_EEC2: u32 = 61443; // 0x00F003 - Electronic Engine Controller 2
pub const PGN_EEC1: u32 = 61444; // 0x00F004 - Electronic Engine Controller 1
pub const PGN_ETC2: u32 = 61445; // 0x00F005 - Electronic Transmission Controller 2
pub const PGN_HOURS: u32 = 65253; // 0x00FEE5 - Engine Hours & Revolutions
pub const PGN_ET1: u32 = 65262; // 0x00FEEE - Engine Temperature 1
pub const PGN_CCVS1: u32 = 65265; // 0x00FEF1 - Cruise Control/Vehicle Speed 1
pub const PGN_FUEL: u32 = 65266; // 0x00FEF2 - Fuel Economy
pub const PGN_ADDRESS_CLAIMED: u32 = 60928; // 0x00EE00 - Address Claimed

// J1939 Transport Protocol PGNs
pub const PGN_TP_CM: u32 = 60416; // 0x00EC00 - Transport Protocol Connection Management
pub const PGN_TP_DT: u32 = 60160; // 0x00EB00 - Transport Protocol Data Transfer

// Standard Multi-Packet PGNs
pub const PGN_DM1: u32 = 65226; // 0x00FECA - Active Diagnostic Trouble Codes
pub const PGN_COMPONENT_ID: u32 = 65259; // 0x00FEEB - Component Identification
pub const PGN_VIN: u32 = 65260; // 0x00FEEC - Vehicle Identification Number
pub const PGN_SOFTWARE_ID: u32 = 65242; // 0x00FEDA - Software Identification

/// Diagnostic Trouble Code (DTC) decoded from J1939 DM1 Active Trouble Codes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct J1939Dtc {
    pub spn: u32,
    pub fmi: u8,
    pub occurrence_count: u8,
    pub description: String,
}

/// SAE J1939-81 64-bit NAME field representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct J1939Name {
    pub raw: u64,
    pub arbitrary_address_capable: bool,
    pub industry_group: u8,
    pub industry_group_name: String,
    pub vehicle_system_instance: u8,
    pub vehicle_system: u8,
    pub function: u8,
    pub function_name: String,
    pub function_instance: u8,
    pub ecu_instance: u8,
    pub manufacturer_code: u16,
    pub manufacturer_name: Option<String>,
    pub identity_number: u32,
}

impl J1939Name {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let raw = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        Some(Self::from_u64(raw))
    }

    pub fn from_u64(raw: u64) -> Self {
        let identity_number = (raw & 0x1FFFFF) as u32;
        let manufacturer_code = ((raw >> 21) & 0x7FF) as u16;
        let ecu_instance = ((raw >> 32) & 0x07) as u8;
        let function_instance = ((raw >> 35) & 0x1F) as u8;
        let function = ((raw >> 40) & 0xFF) as u8;
        let vehicle_system = ((raw >> 49) & 0x7F) as u8;
        let vehicle_system_instance = ((raw >> 56) & 0x0F) as u8;
        let industry_group = ((raw >> 60) & 0x07) as u8;
        let arbitrary_address_capable = ((raw >> 63) & 0x01) != 0;

        let industry_group_name = match industry_group {
            0 => "Global",
            1 => "On-Highway Equipment",
            2 => "Agricultural and Forestry Equipment",
            3 => "Construction Equipment",
            4 => "Marine",
            5 => "Industrial/Stationary",
            _ => "Reserved",
        }
        .to_string();

        let function_name = match function {
            0 => "Engine",
            3 => "Transmission",
            4 => "Brakes/ABS",
            23 => "Instrument Cluster",
            25 => "Shift Console",
            49 => "Cab Controller",
            52 => "Body Controller",
            _ => "Vehicle Function",
        }
        .to_string();

        let manufacturer_name = match manufacturer_code {
            11 => Some("Cummins"),
            12 => Some("Detroit Diesel"),
            14 => Some("Caterpillar"),
            16 => Some("Eaton"),
            18 => Some("John Deere"),
            19 => Some("Volvo"),
            22 => Some("Bosch"),
            43 => Some("Allison Transmission"),
            160 => Some("Navistar"),
            185 => Some("PACCAR"),
            214 => Some("Bendix"),
            _ => None,
        }
        .map(|s| s.to_string());

        Self {
            raw,
            arbitrary_address_capable,
            industry_group,
            industry_group_name,
            vehicle_system_instance,
            vehicle_system,
            function,
            function_name,
            function_instance,
            ecu_instance,
            manufacturer_code,
            manufacturer_name,
            identity_number,
        }
    }
}

/// High-level decoded J1939 signal payloads
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum J1939Payload {
    /// PGN 61441 (EBC1)
    ElectronicBrakeController1 {
        brake_pedal_position_percent: f32,
        abs_active: bool,
        brake_switch_active: bool,
    },
    /// PGN 61442 (ETC1)
    ElectronicTransmissionController1 {
        driveline_engaged: bool,
        shift_in_process: bool,
        output_shaft_speed_rpm: f32,
    },
    /// PGN 61443 (EEC2)
    EngineController2 {
        accelerator_pedal_position_percent: f32,
        engine_percent_load_at_current_speed: u8,
    },
    /// PGN 61444 (EEC1)
    EngineController1 {
        engine_speed_rpm: f32,
        actual_engine_torque_percent: i8,
        drivers_demand_torque_percent: i8,
    },
    /// PGN 61445 (ETC2)
    ElectronicTransmissionController2 { selected_gear: i8, current_gear: i8 },
    /// PGN 65253 (HOURS)
    EngineHours {
        total_engine_hours: f32,
        total_revolutions: u64,
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
    /// PGN 65266 (LFE)
    FuelEconomy {
        fuel_rate_l_per_h: f32,
        instantaneous_fuel_economy_km_per_l: f32,
    },
    /// PGN 60928 (Address Claimed - J1939-81)
    AddressClaimed { name: J1939Name },
    /// PGN 65260 (VIN - Reassembled Multi-Packet)
    VehicleIdentificationNumber(String),
    /// PGN 65259 (Component ID - Reassembled Multi-Packet)
    ComponentIdentification {
        make: String,
        model: String,
        serial_number: String,
    },
    /// PGN 65226 (DM1 - Reassembled Multi-Packet Active Diagnostic Trouble Codes)
    ActiveDiagnosticTroubleCodes {
        protect_lamp: u8,
        amber_warning_lamp: u8,
        red_stop_lamp: u8,
        dtcs: Vec<J1939Dtc>,
    },
    /// PGN 60416 (TP.CM Connection Management Frame)
    TransportConnectionManagement {
        control_byte: u8,
        total_bytes: u16,
        total_packets: u8,
        target_pgn: u32,
    },
    /// PGN 60160 (TP.DT Data Transfer Frame)
    TransportDataTransfer { sequence_number: u8, data: Vec<u8> },
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
    let priority = ((can_id >> 26) & 0x07) as u8;
    let data_page = ((can_id >> 24) & 0x01) as u8;
    let pdu_format = ((can_id >> 16) & 0xFF) as u8;
    let pdu_specific = ((can_id >> 8) & 0xFF) as u8;
    let source_address = (can_id & 0xFF) as u8;

    let is_pdu1 = pdu_format < 240;
    let (pgn, destination_address) = if is_pdu1 {
        let pgn = ((data_page as u32) << 16) | ((pdu_format as u32) << 8);
        (pgn, Some(pdu_specific))
    } else {
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
    let payload = dissect_j1939_payload(header.pgn, data);
    Some(J1939Message { header, payload })
}

/// Dissect J1939 payload for a specific PGN
pub fn dissect_j1939_payload(pgn: u32, data: &[u8]) -> J1939Payload {
    match pgn {
        PGN_EBC1 if data.len() >= 2 => {
            let brake_switch_active = (data[0] & 0x03) == 0x01;
            let abs_active = ((data[0] >> 4) & 0x03) == 0x01;
            let brake_pedal_position_percent = (data[1] as f32) * 0.4;
            J1939Payload::ElectronicBrakeController1 {
                brake_pedal_position_percent,
                abs_active,
                brake_switch_active,
            }
        }
        PGN_ETC1 if data.len() >= 3 => {
            let driveline_engaged = (data[0] & 0x03) == 0x01;
            let shift_in_process = ((data[0] >> 4) & 0x03) == 0x01;
            let raw_speed = u16::from_le_bytes([data[1], data[2]]);
            let output_shaft_speed_rpm = (raw_speed as f32) * 0.125;
            J1939Payload::ElectronicTransmissionController1 {
                driveline_engaged,
                shift_in_process,
                output_shaft_speed_rpm,
            }
        }
        PGN_EEC1 if data.len() >= 8 => {
            let actual_engine_torque_percent = (data[2] as i16 - 125) as i8;
            let drivers_demand_torque_percent = (data[1] as i16 - 125) as i8;
            let raw_speed = u16::from_le_bytes([data[3], data[4]]);
            let engine_speed_rpm = (raw_speed as f32) * 0.125;

            J1939Payload::EngineController1 {
                engine_speed_rpm,
                actual_engine_torque_percent,
                drivers_demand_torque_percent,
            }
        }
        PGN_EEC2 if data.len() >= 8 => {
            let accelerator_pedal_position_percent = (data[1] as f32) * 0.4;
            let engine_percent_load_at_current_speed = data[2];

            J1939Payload::EngineController2 {
                accelerator_pedal_position_percent,
                engine_percent_load_at_current_speed,
            }
        }
        PGN_ETC2 if data.len() >= 4 => {
            let selected_gear = (data[0] as i16 - 125) as i8;
            let current_gear = (data[3] as i16 - 125) as i8;
            J1939Payload::ElectronicTransmissionController2 {
                selected_gear,
                current_gear,
            }
        }
        PGN_HOURS if data.len() >= 8 => {
            let raw_hours = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let raw_revs = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            J1939Payload::EngineHours {
                total_engine_hours: (raw_hours as f32) * 0.05,
                total_revolutions: (raw_revs as u64) * 1000,
            }
        }
        PGN_ET1 if data.len() >= 8 => {
            let coolant_temp_deg_c = data[0] as i16 - 40;
            let fuel_temp_deg_c = data[1] as i16 - 40;
            let raw_oil = u16::from_le_bytes([data[2], data[3]]);
            let oil_temp_deg_c = ((raw_oil as f32 * 0.03125) - 273.0) as i16;

            J1939Payload::EngineTemperature1 {
                coolant_temp_deg_c,
                fuel_temp_deg_c,
                oil_temp_deg_c,
            }
        }
        PGN_CCVS1 if data.len() >= 8 => {
            let parking_brake_switch_active = ((data[0] >> 2) & 0x03) == 0x01;
            let raw_speed = u16::from_le_bytes([data[1], data[2]]);
            let wheel_based_vehicle_speed_kmh = (raw_speed as f32) / 256.0;

            J1939Payload::VehicleSpeed1 {
                wheel_based_vehicle_speed_kmh,
                parking_brake_switch_active,
            }
        }
        PGN_FUEL if data.len() >= 4 => {
            let raw_rate = u16::from_le_bytes([data[0], data[1]]);
            let raw_econ = u16::from_le_bytes([data[2], data[3]]);
            J1939Payload::FuelEconomy {
                fuel_rate_l_per_h: (raw_rate as f32) * 0.05,
                instantaneous_fuel_economy_km_per_l: (raw_econ as f32) / 512.0,
            }
        }
        PGN_ADDRESS_CLAIMED if data.len() >= 8 => {
            if let Some(name) = J1939Name::from_bytes(data) {
                J1939Payload::AddressClaimed { name }
            } else {
                J1939Payload::Generic {
                    pgn,
                    name: "Address Claimed".to_string(),
                    data: data.to_vec(),
                }
            }
        }
        PGN_TP_CM if data.len() >= 8 => {
            let control_byte = data[0];
            let total_bytes = u16::from_le_bytes([data[1], data[2]]);
            let total_packets = data[3];
            let target_pgn = (data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16);

            J1939Payload::TransportConnectionManagement {
                control_byte,
                total_bytes,
                total_packets,
                target_pgn,
            }
        }
        PGN_TP_DT if !data.is_empty() => {
            let sequence_number = data[0];
            J1939Payload::TransportDataTransfer {
                sequence_number,
                data: data[1..].to_vec(),
            }
        }
        PGN_VIN => {
            let vin_str = String::from_utf8_lossy(data)
                .trim_matches('\0')
                .trim()
                .to_string();
            J1939Payload::VehicleIdentificationNumber(vin_str)
        }
        PGN_COMPONENT_ID => {
            let fields: Vec<String> = data
                .split(|&b| b == b'*')
                .map(|chunk| String::from_utf8_lossy(chunk).trim().to_string())
                .collect();
            J1939Payload::ComponentIdentification {
                make: fields.first().cloned().unwrap_or_default(),
                model: fields.get(1).cloned().unwrap_or_default(),
                serial_number: fields.get(2).cloned().unwrap_or_default(),
            }
        }
        PGN_DM1 if data.len() >= 2 => {
            let protect_lamp = (data[0] >> 6) & 0x03;
            let amber_warning_lamp = (data[0] >> 4) & 0x03;
            let red_stop_lamp = (data[0] >> 2) & 0x03;

            let mut dtcs = Vec::new();
            let mut i = 2;
            while i + 3 < data.len() {
                let spn_lo = data[i] as u32;
                let spn_mid = data[i + 1] as u32;
                let spn_hi = ((data[i + 2] >> 5) & 0x07) as u32;
                let spn = spn_lo | (spn_mid << 8) | (spn_hi << 16);
                let fmi = data[i + 2] & 0x1F;
                let occurrence_count = data[i + 3] & 0x7F;

                dtcs.push(J1939Dtc {
                    spn,
                    fmi,
                    occurrence_count,
                    description: format!(
                        "SPN {} FMI {} (Occurred {}x)",
                        spn, fmi, occurrence_count
                    ),
                });
                i += 4;
            }

            J1939Payload::ActiveDiagnosticTroubleCodes {
                protect_lamp,
                amber_warning_lamp,
                red_stop_lamp,
                dtcs,
            }
        }
        _ => J1939Payload::Generic {
            pgn,
            name: pgn_name(pgn).to_string(),
            data: data.to_vec(),
        },
    }
}

/// Active transport reassembly session for a specific J1939 node
#[derive(Debug, Clone)]
struct TransportSession {
    target_pgn: u32,
    total_bytes: usize,
    expected_seq: u8,
    buffer: Vec<u8>,
    last_timestamp_us: u64,
}

/// Reassembler for J1939 Broadcast Announce Message (BAM) and Connection Mode Data Transfer (CMDT)
#[derive(Debug, Clone, Default)]
pub struct J1939TransportReassembler {
    sessions: HashMap<u8, TransportSession>, // keyed by Source Address
}

impl J1939TransportReassembler {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Ingest a J1939 frame. If a multi-packet message is completed, returns the reassembled J1939Message.
    pub fn ingest_frame(
        &mut self,
        can_id: u32,
        data: &[u8],
        timestamp_us: u64,
    ) -> Option<J1939Message> {
        let header = parse_j1939_header(can_id);

        match header.pgn {
            PGN_TP_CM if data.len() >= 8 => {
                let control_byte = data[0];
                let total_bytes = u16::from_le_bytes([data[1], data[2]]) as usize;
                let target_pgn =
                    (data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16);

                // 0x20: BAM (Broadcast Announce Message), 0x10: RTS (Connection Mode)
                if control_byte == 0x20 || control_byte == 0x10 {
                    self.sessions.insert(
                        header.source_address,
                        TransportSession {
                            target_pgn,
                            total_bytes,
                            expected_seq: 1,
                            buffer: Vec::with_capacity(total_bytes.min(65535)),
                            last_timestamp_us: timestamp_us,
                        },
                    );
                }
                None
            }

            PGN_TP_DT if data.len() >= 2 => {
                let seq = data[0];
                let session = self.sessions.get_mut(&header.source_address)?;

                if seq != session.expected_seq {
                    // Out-of-order packet; discard session
                    self.sessions.remove(&header.source_address);
                    return None;
                }

                session.expected_seq += 1;
                session.last_timestamp_us = timestamp_us;

                let remaining = session.total_bytes.saturating_sub(session.buffer.len());
                let bytes_in_packet = (data.len() - 1).min(remaining);
                session
                    .buffer
                    .extend_from_slice(&data[1..1 + bytes_in_packet]);

                if session.buffer.len() >= session.total_bytes {
                    let completed = self.sessions.remove(&header.source_address)?;
                    let reassembled_payload =
                        dissect_j1939_payload(completed.target_pgn, &completed.buffer);

                    let mut reassembled_header = header;
                    reassembled_header.pgn = completed.target_pgn;

                    Some(J1939Message {
                        header: reassembled_header,
                        payload: reassembled_payload,
                    })
                } else {
                    None
                }
            }

            // Regular single-packet J1939 frame
            _ => dissect_j1939(can_id, data),
        }
    }
}

pub fn pgn_name(pgn: u32) -> &'static str {
    match pgn {
        PGN_EBC1 => "Electronic Brake Controller 1 (EBC1)",
        PGN_ETC1 => "Electronic Transmission Controller 1 (ETC1)",
        PGN_EEC2 => "Electronic Engine Controller 2 (EEC2)",
        PGN_EEC1 => "Electronic Engine Controller 1 (EEC1)",
        PGN_ETC2 => "Electronic Transmission Controller 2 (ETC2)",
        PGN_HOURS => "Engine Hours & Revolutions",
        PGN_ET1 => "Engine Temperature 1 (ET1)",
        PGN_CCVS1 => "Cruise Control/Vehicle Speed (CCVS1)",
        PGN_FUEL => "Fuel Economy (LFE)",
        PGN_ADDRESS_CLAIMED => "Address Claimed",
        PGN_TP_CM => "Transport Protocol Connection Management (TP.CM)",
        PGN_TP_DT => "Transport Protocol Data Transfer (TP.DT)",
        PGN_DM1 => "Active Diagnostic Trouble Codes (DM1)",
        PGN_VIN => "Vehicle Identification Number (VIN)",
        PGN_COMPONENT_ID => "Component Identification",
        PGN_SOFTWARE_ID => "Software Identification",
        _ => "Proprietary or Unregistered PGN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_j1939_header_pdu1_destination_specific() {
        // Priority 3, Data Page 0, PF 239 (0xEF), Destination 0x28, Source 0xF1
        let can_id = 0x0CEF28F1;
        let header = parse_j1939_header(can_id);

        assert_eq!(header.priority, 3);
        assert_eq!(header.pdu_format, 239);
        assert_eq!(header.pdu_specific, 0x28);
        assert_eq!(header.destination_address, Some(0x28));
        assert_eq!(header.source_address, 0xF1);
        assert_eq!(header.pgn, 0x00EF00);
        assert!(header.is_pdu1);
    }

    #[test]
    fn test_j1939_eec1_dissection() {
        // EEC1: PGN 61444 (0x00F004) -> ID = 0x0CF00400 (Source = 0x00 Engine)
        let can_id = 0x0CF00400;
        let data = [
            0xF0, // Torque Mode / State
            0x7D, // Driver's demand torque: 125 - 125 = 0%
            0x87, // Actual torque: 135 - 125 = +10%
            0x00, 0x20, // RPM: 0x2000 = 8192 * 0.125 = 1024 rpm
            0x00, 0x00, 0x00,
        ];

        let msg = dissect_j1939(can_id, &data).expect("Dissected EEC1");
        assert_eq!(msg.header.pgn, PGN_EEC1);
        match msg.payload {
            J1939Payload::EngineController1 {
                engine_speed_rpm,
                actual_engine_torque_percent,
                drivers_demand_torque_percent,
            } => {
                assert_eq!(engine_speed_rpm, 1024.0);
                assert_eq!(actual_engine_torque_percent, 10);
                assert_eq!(drivers_demand_torque_percent, 0);
            }
            _ => panic!("Expected EngineController1"),
        }
    }

    #[test]
    fn test_j1939_name_and_address_claimed() {
        // PGN 60928 (0x00EE00) - Address Claimed: ID = 0x18EEFF00
        let can_id = 0x18EEFF00;
        // Construct NAME:
        // Identity: 12345 (0x3039)
        // Manufacturer: 11 (Cummins -> 0x0B)
        // ECU Instance: 0, Function Instance: 0
        // Function: 0 (Engine)
        // Vehicle System: 0
        // Industry Group: 1 (On-Highway)
        // Arbitrary Address Capable: 1
        let mut name_u64 = 12345u64;
        name_u64 |= (11u64) << 21;
        name_u64 |= (0u64) << 40; // Engine
        name_u64 |= (1u64) << 60; // On-Highway
        name_u64 |= (1u64) << 63; // Arbitrary Address Capable

        let name_bytes = name_u64.to_le_bytes();
        let msg = dissect_j1939(can_id, &name_bytes).expect("Dissected Address Claimed");
        match msg.payload {
            J1939Payload::AddressClaimed { name } => {
                assert_eq!(name.identity_number, 12345);
                assert_eq!(name.manufacturer_code, 11);
                assert_eq!(name.manufacturer_name, Some("Cummins".to_string()));
                assert_eq!(name.function, 0);
                assert_eq!(name.function_name, "Engine");
                assert_eq!(name.industry_group, 1);
                assert_eq!(name.industry_group_name, "On-Highway Equipment");
                assert!(name.arbitrary_address_capable);
            }
            _ => panic!("Expected AddressClaimed"),
        }
    }

    #[test]
    fn test_j1939_heavy_duty_pgns() {
        // EBC1 (61441 = 0xF001): Brake pedal 50% (50 / 0.4 = 125 = 0x7D), ABS active (bit 4 = 1 -> 0x10)
        let ebc1 = dissect_j1939(0x18F0010B, &[0x10, 0x7D]).unwrap();
        match ebc1.payload {
            J1939Payload::ElectronicBrakeController1 {
                brake_pedal_position_percent,
                abs_active,
                ..
            } => {
                assert_eq!(brake_pedal_position_percent, 50.0);
                assert!(abs_active);
            }
            _ => panic!("Expected ElectronicBrakeController1"),
        }

        // HOURS (65253 = 0xFEE5): 1000 hours (1000 / 0.05 = 20000 = 0x4E20)
        let hours_data = [0x20, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let hours_msg = dissect_j1939(0x18FEE500, &hours_data).unwrap();
        match hours_msg.payload {
            J1939Payload::EngineHours {
                total_engine_hours, ..
            } => {
                assert_eq!(total_engine_hours, 1000.0);
            }
            _ => panic!("Expected EngineHours"),
        }
    }

    #[test]
    fn test_j1939_bam_vin_reassembly() {
        let mut reassembler = J1939TransportReassembler::new();
        let tp_cm_id = 0x18ECFF00;

        // TP.CM BAM for VIN (PGN 65260 = 0x00FEEC), 17 bytes, 3 packets
        let cm_data = [0x20, 17, 0x00, 3, 0xFF, 0xEC, 0xFE, 0x00];
        assert_eq!(reassembler.ingest_frame(tp_cm_id, &cm_data, 1000), None);

        let tp_dt_id = 0x18EBFF00;
        let dt1 = [1, b'1', b'H', b'G', b'C', b'R', b'2', b'F', b'8'];
        assert_eq!(reassembler.ingest_frame(tp_dt_id, &dt1, 2000), None);

        let dt2 = [2, b'3', b'H', b'A', b'0', b'0', b'0', b'1', b'2'];
        assert_eq!(reassembler.ingest_frame(tp_dt_id, &dt2, 3000), None);

        let dt3 = [3, b'3', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let res = reassembler
            .ingest_frame(tp_dt_id, &dt3, 4000)
            .expect("Reassembly complete");

        assert_eq!(res.header.pgn, PGN_VIN);
        assert_eq!(
            res.payload,
            J1939Payload::VehicleIdentificationNumber("1HGCR2F83HA000123".to_string())
        );
    }

    #[test]
    fn test_j1939_dm1_active_trouble_codes() {
        let mut reassembler = J1939TransportReassembler::new();
        let tp_cm_id = 0x18ECFF00;

        // TP.CM BAM for DM1 (PGN 65226 = 0x00FECA), 6 bytes
        let cm_data = [0x10, 6, 0x00, 1, 0xFF, 0xCA, 0xFE, 0x00];
        assert_eq!(reassembler.ingest_frame(tp_cm_id, &cm_data, 1000), None);

        let dt_data = [1, 0x00, 0x00, 0x64, 0x00, 0x01, 0x05, 0xFF];
        let tp_dt_id = 0x18EBFF00;
        let res = reassembler
            .ingest_frame(tp_dt_id, &dt_data, 2000)
            .expect("DM1 complete");

        assert_eq!(res.header.pgn, PGN_DM1);
        match res.payload {
            J1939Payload::ActiveDiagnosticTroubleCodes { dtcs, .. } => {
                assert_eq!(dtcs.len(), 1);
                assert_eq!(dtcs[0].spn, 100);
                assert_eq!(dtcs[0].fmi, 1);
                assert_eq!(dtcs[0].occurrence_count, 5);
            }
            _ => panic!("Expected DM1 ActiveDiagnosticTroubleCodes"),
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
