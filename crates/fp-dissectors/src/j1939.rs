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
pub const PGN_EEC1: u32 = 61444; // 0x00F004 - Electronic Engine Controller 1
pub const PGN_EEC2: u32 = 61443; // 0x00F003 - Electronic Engine Controller 2
pub const PGN_ET1: u32 = 65262;  // 0x00FEEE - Engine Temperature 1
pub const PGN_CCVS1: u32 = 65265;// 0x00FEF1 - Cruise Control/Vehicle Speed 1
pub const PGN_ADDRESS_CLAIMED: u32 = 60928; // 0x00EE00

// J1939 Transport Protocol PGNs
pub const PGN_TP_CM: u32 = 60416; // 0x00EC00 - Transport Protocol Connection Management
pub const PGN_TP_DT: u32 = 60160; // 0x00EB00 - Transport Protocol Data Transfer

// Standard Multi-Packet PGNs
pub const PGN_DM1: u32 = 65226;          // 0x00FECA - Active Diagnostic Trouble Codes
pub const PGN_COMPONENT_ID: u32 = 65259; // 0x00FEEB - Component Identification
pub const PGN_VIN: u32 = 65260;          // 0x00FEEC - Vehicle Identification Number
pub const PGN_SOFTWARE_ID: u32 = 65242;  // 0x00FEDA - Software Identification

/// Diagnostic Trouble Code (DTC) decoded from J1939 DM1 Active Trouble Codes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct J1939Dtc {
    pub spn: u32,
    pub fmi: u8,
    pub occurrence_count: u8,
    pub description: String,
}

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
    TransportDataTransfer {
        sequence_number: u8,
        data: Vec<u8>,
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
            let vin_str = String::from_utf8_lossy(data).trim_matches('\0').trim().to_string();
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
                    description: format!("SPN {} FMI {} (Occurred {}x)", spn, fmi, occurrence_count),
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
                // 0x10 = BAM, 0x11 = RTS
                if control_byte == 0x10 || control_byte == 0x11 {
                    let total_bytes = u16::from_le_bytes([data[1], data[2]]) as usize;
                    let target_pgn =
                        (data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16);

                    self.sessions.insert(
                        header.source_address,
                        TransportSession {
                            target_pgn,
                            total_bytes,
                            expected_seq: 1,
                            buffer: Vec::with_capacity(total_bytes),
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
                session.buffer.extend_from_slice(&data[1..1 + bytes_in_packet]);

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
        PGN_EEC1 => "Electronic Engine Controller 1 (EEC1)",
        PGN_EEC2 => "Electronic Engine Controller 2 (EEC2)",
        PGN_ET1 => "Engine Temperature 1 (ET1)",
        PGN_CCVS1 => "Cruise Control/Vehicle Speed (CCVS1)",
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
        let id = 0x18EF0501;
        let hdr = parse_j1939_header(id);
        assert_eq!(hdr.priority, 6);
        assert_eq!(hdr.source_address, 0x01);
        assert!(hdr.is_pdu1);
        assert_eq!(hdr.destination_address, Some(0x05));
        assert_eq!(hdr.pgn, 0xEF00);
    }

    #[test]
    fn test_j1939_eec1_dissection() {
        let id = 0x0CF00400;
        let data = [0xFF, 0x7D, 0x7D, 0x00, 0x20, 0xFF, 0xFF, 0xFF];
        let msg = dissect_j1939(id, &data).expect("Dissected EEC1");
        assert_eq!(msg.header.pgn, PGN_EEC1);
        match msg.payload {
            J1939Payload::EngineController1 {
                engine_speed_rpm,
                actual_engine_torque_percent,
                drivers_demand_torque_percent,
            } => {
                assert_eq!(actual_engine_torque_percent, 0);
                assert_eq!(drivers_demand_torque_percent, 0);
                assert_eq!(engine_speed_rpm, 1024.0);
            }
            _ => panic!("Expected EngineController1"),
        }
    }

    #[test]
    fn test_j1939_bam_vin_reassembly() {
        let mut reassembler = J1939TransportReassembler::new();

        // 1. TP.CM BAM for VIN (PGN 65260 = 0x00FEEC), 17 bytes, 3 packets
        // ID: 0x18ECFF00 (Priority 6, PGN 60416, DA=0xFF Global, SA=0x00)
        let tp_cm_id = 0x18ECFF00;
        let cm_data = [
            0x10, // BAM
            17, 0x00, // Total bytes = 17
            3,    // Total packets = 3
            0xFF, // Reserved
            0xEC, 0xFE, 0x00, // Target PGN 65260 (VIN)
        ];
        assert_eq!(reassembler.ingest_frame(tp_cm_id, &cm_data, 1000), None);

        // 2. TP.DT Packet 1 (7 bytes: "1HGCR2F")
        let tp_dt_id = 0x18EBFF00;
        let dt1 = [1, b'1', b'H', b'G', b'C', b'R', b'2', b'F'];
        assert_eq!(reassembler.ingest_frame(tp_dt_id, &dt1, 2000), None);

        // 3. TP.DT Packet 2 (7 bytes: "83HA000")
        let dt2 = [2, b'8', b'3', b'H', b'A', b'0', b'0', b'0'];
        assert_eq!(reassembler.ingest_frame(tp_dt_id, &dt2, 3000), None);

        // 4. TP.DT Packet 3 (3 remaining bytes: "123*")
        let dt3 = [3, b'1', b'2', b'3', 0xFF, 0xFF, 0xFF, 0xFF];
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

        // TP.DT Packet 1: Lamp status (2 bytes) + 1 DTC (4 bytes: SPN 100 = Engine Oil Pressure, FMI 1)
        // SPN 100 = 0x000064 -> byte 0 = 0x64, byte 1 = 0x00, byte 2: FMI 1 | SPN hi 0 => 0x01, occ = 5
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
