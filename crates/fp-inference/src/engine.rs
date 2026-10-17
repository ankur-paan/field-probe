use std::collections::HashMap;

use fp_core::CanFrame;
use fp_crypto::{
    auto_decrypt_payload, calculate_shannon_entropy, is_high_entropy_payload, KeyRing,
};
use fp_dissectors::{
    dissect_canopen, dissect_j1939, dissect_uds, parse_j1939_header, BacnetMstpFrame,
    CanOpenPayload, Dnp3Frame, IsoTpReassembler, J1939Payload, J1939TransportReassembler,
    ModbusPdu, ModbusRtuAdu, UdsMessage, PGN_COMPONENT_ID, PGN_DM1, PGN_EEC1, PGN_ET1, PGN_TP_CM,
    PGN_TP_DT, PGN_VIN,
};
use serde::{Deserialize, Serialize};

use crate::{
    bus_load::BusLoadEstimator,
    catalog::{InferredRegisterEntry, RegisterCatalog},
    diff_capture::{DiffCaptureReport, DiffCaptureSession},
    histogram::{TimingHistogramEngine, WelfordTracker},
    pairing::{MatchedTransaction, TransactionMatcher},
    plausibility::PlausibilityScorer,
    sniffer::{BitDeltaReport, CanSnifferEngine},
};

/// High-level status snapshot of all inferred bus state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceSummary {
    pub total_discovered_registers: usize,
    pub total_active_can_nodes: usize,
    pub periodic_can_loops: usize,
    pub active_diff_capture: bool,
}

/// Unified Semantic Inference and Delta Engine
#[derive(Debug)]
pub struct InferenceEngine {
    pub catalog: RegisterCatalog,
    pub transaction_matcher: TransactionMatcher,
    pub plausibility_scorer: PlausibilityScorer,
    pub sniffer_engine: CanSnifferEngine,
    pub histogram_engine: TimingHistogramEngine,
    pub bus_load_estimator: BusLoadEstimator,
    pub diff_session: DiffCaptureSession,
    pub modbus_timing_trackers: HashMap<(u8, u16), WelfordTracker>,
    pub keyring: KeyRing,
    pub j1939_reassembler: J1939TransportReassembler,
    pub isotp_reassembler: IsoTpReassembler,
}

impl InferenceEngine {
    pub fn new(nominal_can_bitrate: u32, max_turnaround_timeout_ms: u64) -> Self {
        Self {
            catalog: RegisterCatalog::new(),
            transaction_matcher: TransactionMatcher::new(max_turnaround_timeout_ms),
            plausibility_scorer: PlausibilityScorer::new(),
            sniffer_engine: CanSnifferEngine::new(100),
            histogram_engine: TimingHistogramEngine::new(),
            bus_load_estimator: BusLoadEstimator::new(nominal_can_bitrate, 1000),
            diff_session: DiffCaptureSession::new(),
            modbus_timing_trackers: HashMap::new(),
            keyring: KeyRing::new(),
            j1939_reassembler: J1939TransportReassembler::new(),
            isotp_reassembler: IsoTpReassembler::new(5_000_000),
        }
    }

    /// Process an incoming Modbus RTU frame
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    pub fn ingest_modbus_frame(
        &mut self,
        adu: &ModbusRtuAdu,
        timestamp_us: u64,
    ) -> Option<MatchedTransaction> {
        let node_str = format!("Slave_{}", adu.slave_id);

        // Check for Modbus Device Identification (MEI FC 0x2B / 0x0E)
        if let ModbusPdu::ReadDeviceIdentificationResponse { objects, .. } = &adu.pdu {
            for (obj_id, text) in objects {
                let obj_name = match obj_id {
                    0x00 => "VendorName",
                    0x01 => "ProductCode",
                    0x02 => "MajorMinorRevision",
                    0x03 => "VendorUrl",
                    0x04 => "ProductName",
                    0x05 => "ModelName",
                    0x06 => "UserApplicationName",
                    _ => "DeviceIdObject",
                };
                self.catalog.insert_or_update(InferredRegisterEntry {
                    node_or_slave: node_str.clone(),
                    address: 0x2B00 | (*obj_id as u32),
                    polling_frequency_hz: 1.0,
                    jitter_ms: 0.0,
                    raw_hex: format!("{:02X?}", text.as_bytes()),
                    plausible_type: format!("Modbus Device ID ({}): {}", obj_name, text),
                    confidence: 1.0,
                });
            }
        }

        let mut matched = self
            .transaction_matcher
            .ingest_modbus_frame(adu, timestamp_us)?;

        // Update Welford timing tracker per (slave_id, start_address)
        let timing_tracker = self
            .modbus_timing_trackers
            .entry((matched.slave_id, matched.start_address))
            .or_default();
        timing_tracker.update(timestamp_us);
        let (polling_frequency_hz, jitter_ms) = timing_tracker.rate_and_jitter();

        let mut is_encrypted_block = false;
        // Check Shannon entropy on response payload
        if let ModbusPdu::ReadResponse { data, .. } = &adu.pdu {
            let entropy = calculate_shannon_entropy(data);
            let max_possible = if data.len() < 256 {
                (data.len() as f32).log2().min(8.0)
            } else {
                8.0
            };
            let is_high_entropy =
                entropy >= 7.2 || (data.len() >= 16 && entropy >= max_possible * 0.92);

            if is_high_entropy {
                let decrypted = auto_decrypt_payload(&self.keyring, &node_str, data)
                    .or_else(|| auto_decrypt_payload(&self.keyring, "global", data));

                if let Some(decrypted_bytes) = decrypted {
                    let mut reg_vals = Vec::new();
                    for (idx, chunk) in decrypted_bytes.chunks_exact(2).enumerate() {
                        let addr = (matched.start_address as usize + idx) as u16;
                        let val = u16::from_be_bytes([chunk[0], chunk[1]]);
                        reg_vals.push((addr, val));
                    }
                    if !reg_vals.is_empty() {
                        matched.register_values = reg_vals;
                    }
                } else {
                    is_encrypted_block = true;
                    self.catalog.insert_or_update(InferredRegisterEntry {
                        node_or_slave: node_str.clone(),
                        address: matched.start_address as u32,
                        polling_frequency_hz: polling_frequency_hz as f32,
                        jitter_ms: jitter_ms as f32,
                        raw_hex: format!(
                            "0x{}",
                            data.iter()
                                .map(|b| format!("{:02X}", b))
                                .collect::<String>()
                        ),
                        plausible_type: format!(
                            "Encrypted / High-Entropy (H={:.2} bits/byte - Key Required)",
                            entropy
                        ),
                        confidence: 0.95,
                    });
                }
            }
        }

        if is_encrypted_block {
            return Some(matched);
        }

        // Update register values, catalog, and plausibility
        let mut i = 0;
        while i < matched.register_values.len() {
            let (addr, val) = matched.register_values[i];
            self.diff_session
                .record_register(matched.slave_id, addr, val, timestamp_us);

            let next_addr = addr.wrapping_add(1);
            let next_val = matched
                .register_values
                .iter()
                .find(|(a, _)| *a == next_addr)
                .map(|(_, v)| *v);

            let mut advance_two = false;
            let (plausible_type, confidence) = if let Some(r1) = next_val {
                let candidates =
                    self.plausibility_scorer
                        .evaluate_pair(&node_str, addr as u32, val, r1);
                if let Some(top) = candidates.first() {
                    let is_multi_reg = top.representation_name.starts_with("Float32")
                        || top.representation_name.starts_with("UInt32")
                        || top.representation_name.starts_with("Int32")
                        || top.representation_name.starts_with("Mod10000")
                        || top.representation_name.starts_with("ASCII");
                    if is_multi_reg && top.confidence >= 0.70 {
                        advance_two = true;
                    }
                    (top.representation_name.clone(), top.confidence)
                } else {
                    ("UInt16".to_string(), 0.50)
                }
            } else {
                ("UInt16".to_string(), 0.60)
            };

            if advance_two {
                let r1 = next_val.unwrap();
                self.diff_session
                    .record_register(matched.slave_id, next_addr, r1, timestamp_us);

                self.catalog.insert_or_update(InferredRegisterEntry {
                    node_or_slave: node_str.clone(),
                    address: addr as u32,
                    polling_frequency_hz: polling_frequency_hz as f32,
                    jitter_ms: jitter_ms as f32,
                    raw_hex: format!("0x{:04X}{:04X}", val, r1),
                    plausible_type,
                    confidence,
                });
                i += 2;
            } else {
                self.catalog.insert_or_update(InferredRegisterEntry {
                    node_or_slave: node_str.clone(),
                    address: addr as u32,
                    polling_frequency_hz: polling_frequency_hz as f32,
                    jitter_ms: jitter_ms as f32,
                    raw_hex: format!("0x{:04X}", val),
                    plausible_type,
                    confidence,
                });
                i += 1;
            }
        }

        Some(matched)
    }

    /// Process an incoming CAN frame with entropy inspection and cryptographic unmasking
    pub fn ingest_can_frame(
        &mut self,
        frame: &CanFrame,
        timestamp_us: u64,
    ) -> Option<BitDeltaReport> {
        // Record in histogram engine to detect periodic broadcast loops
        self.histogram_engine.record_frame(frame.id, timestamp_us);

        // Record in bus load estimator
        let _ = self.bus_load_estimator.ingest_frame(frame, timestamp_us);

        // Check if CAN frame has high entropy and attempt auto-decryption
        let is_high_entropy = if frame.data.len() >= 64 {
            is_high_entropy_payload(&frame.data, 7.2)
        } else if frame.data.len() >= 8 {
            let max_possible = (frame.data.len() as f32).log2();
            calculate_shannon_entropy(&frame.data) >= (max_possible * 0.90)
        } else {
            false
        };

        let processed_frame = if is_high_entropy {
            let scope = match frame.id {
                fp_core::CanId::Standard(v) => format!("CAN:0x{:03X}", v),
                fp_core::CanId::Extended(v) => format!("CAN:0x{:08X}", v),
            };

            if let Some(decrypted) = auto_decrypt_payload(&self.keyring, &scope, &frame.data)
                .or_else(|| auto_decrypt_payload(&self.keyring, "global", &frame.data))
            {
                let mut f = frame.clone();
                f.data = decrypted.into();
                f
            } else {
                frame.clone()
            }
        } else {
            frame.clone()
        };

        // Record in diff capture session
        self.diff_session
            .record_can_frame(processed_frame.id, &processed_frame.data, timestamp_us);

        // Dissect higher-layer industrial protocols (J1939, ISO-TP/UDS, CANopen)
        match processed_frame.id {
            fp_core::CanId::Extended(can_id_u32) => {
                let header = parse_j1939_header(can_id_u32);
                let reassembled = if header.pgn == PGN_TP_CM || header.pgn == PGN_TP_DT {
                    self.j1939_reassembler.ingest_frame(
                        can_id_u32,
                        &processed_frame.data,
                        timestamp_us,
                    )
                } else {
                    dissect_j1939(can_id_u32, &processed_frame.data)
                };

                if let Some(msg) = reassembled {
                    let node_str = format!("J1939:0x{:02X}", msg.header.source_address);
                    let (hz, jitter) = self.histogram_engine.get_node_timing(processed_frame.id);
                    match msg.payload {
                        J1939Payload::EngineController1 {
                            engine_speed_rpm,
                            actual_engine_torque_percent,
                            drivers_demand_torque_percent: _,
                        } => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: node_str.clone(),
                                address: PGN_EEC1,
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("{:02X?}", &processed_frame.data[..]),
                                plausible_type: format!(
                                    "EngineSpeed: {:.2} RPM, Torque: {}%",
                                    engine_speed_rpm, actual_engine_torque_percent
                                ),
                                confidence: 1.0,
                            });
                        }
                        J1939Payload::EngineTemperature1 {
                            coolant_temp_deg_c,
                            fuel_temp_deg_c,
                            ..
                        } => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: node_str.clone(),
                                address: PGN_ET1,
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("{:02X?}", &processed_frame.data[..]),
                                plausible_type: format!(
                                    "CoolantTemp: {} °C, FuelTemp: {} °C",
                                    coolant_temp_deg_c, fuel_temp_deg_c
                                ),
                                confidence: 1.0,
                            });
                        }
                        J1939Payload::VehicleIdentificationNumber(vin) => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: node_str.clone(),
                                address: PGN_VIN,
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("{:02X?}", &processed_frame.data[..]),
                                plausible_type: format!("VIN: {}", vin),
                                confidence: 1.0,
                            });
                        }
                        J1939Payload::ActiveDiagnosticTroubleCodes { dtcs, .. } => {
                            for (idx, dtc) in dtcs.iter().enumerate() {
                                self.catalog.insert_or_update(InferredRegisterEntry {
                                    node_or_slave: node_str.clone(),
                                    address: PGN_DM1 + idx as u32,
                                    polling_frequency_hz: hz,
                                    jitter_ms: jitter,
                                    raw_hex: format!("SPN:{} FMI:{}", dtc.spn, dtc.fmi),
                                    plausible_type: format!("DM1 Active DTC: {}", dtc.description),
                                    confidence: 1.0,
                                });
                            }
                        }
                        J1939Payload::ComponentIdentification {
                            make,
                            model,
                            serial_number,
                            ..
                        } => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: node_str.clone(),
                                address: PGN_COMPONENT_ID,
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("{:02X?}", &processed_frame.data[..]),
                                plausible_type: format!(
                                    "Component: Make={}, Model={}, Serial={}",
                                    make, model, serial_number
                                ),
                                confidence: 1.0,
                            });
                        }
                        _ => {}
                    }
                }
            }
            fp_core::CanId::Standard(cob_id) => {
                let (hz, jitter) = self.histogram_engine.get_node_timing(processed_frame.id);

                // A. ISO-TP / UDS Diagnostic Range (0x7DF functional broadcast, 0x7E0..=0x7EF physical)
                if (0x7E0..=0x7EF).contains(&cob_id) || cob_id == 0x7DF {
                    if let Some(Ok(pdu)) = self.isotp_reassembler.ingest_frame(
                        processed_frame.id,
                        &processed_frame.data,
                        timestamp_us,
                    ) {
                        if let Some(uds) = dissect_uds(&pdu) {
                            let node_str = format!("UDS:0x{:03X}", cob_id);
                            match uds {
                                UdsMessage::ReadDataByIdentifierResponse { did, data } => {
                                    self.catalog.insert_or_update(InferredRegisterEntry {
                                        node_or_slave: node_str,
                                        address: did as u32,
                                        polling_frequency_hz: hz,
                                        jitter_ms: jitter,
                                        raw_hex: format!("{:02X?}", data),
                                        plausible_type: format!("UDS DID 0x{:04X} Data", did),
                                        confidence: 1.0,
                                    });
                                }
                                UdsMessage::SecurityAccessResponse {
                                    sub_function,
                                    seed_or_key,
                                } => {
                                    self.catalog.insert_or_update(InferredRegisterEntry {
                                        node_or_slave: node_str,
                                        address: 0x2700 | (sub_function as u32),
                                        polling_frequency_hz: hz,
                                        jitter_ms: jitter,
                                        raw_hex: format!("{:02X?}", seed_or_key),
                                        plausible_type: format!(
                                            "UDS SecurityAccess (SubFunc 0x{:02X}) Challenge",
                                            sub_function
                                        ),
                                        confidence: 1.0,
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // B. CANopen Protocol Dissection
                if let Some(canopen) = dissect_canopen(cob_id, &processed_frame.data) {
                    match canopen.payload {
                        CanOpenPayload::Heartbeat {
                            node_id,
                            state,
                            state_name,
                        } => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: format!("CANopen:{}", node_id),
                                address: 0x700 + (node_id as u32),
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("0x{:02X}", state as u8),
                                plausible_type: format!("CANopen NMT State: {}", state_name),
                                confidence: 1.0,
                            });
                        }
                        CanOpenPayload::Emergency {
                            node_id,
                            error_code,
                            error_register,
                            ..
                        } => {
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: format!("CANopen:{}", node_id),
                                address: 0x080 + (node_id as u32),
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!(
                                    "ErrCode:0x{:04X} ErrReg:0x{:02X}",
                                    error_code, error_register
                                ),
                                plausible_type: format!(
                                    "CANopen EMCY Emergency: Code 0x{:04X}",
                                    error_code
                                ),
                                confidence: 1.0,
                            });
                        }
                        CanOpenPayload::Sdo {
                            is_client_to_server: false,
                            node_id,
                            multiplexer_index: 0x1018,
                            multiplexer_subindex,
                            data,
                            ..
                        } => {
                            let sub_name = match multiplexer_subindex {
                                0 => "Number of Entries",
                                1 => "Vendor ID",
                                2 => "Product Code",
                                3 => "Revision Number",
                                4 => "Serial Number",
                                _ => "Subindex",
                            };
                            self.catalog.insert_or_update(InferredRegisterEntry {
                                node_or_slave: format!("CANopen:{}", node_id),
                                address: ((0x1018u32) << 8) | (multiplexer_subindex as u32),
                                polling_frequency_hz: hz,
                                jitter_ms: jitter,
                                raw_hex: format!("{:02X?}", data),
                                plausible_type: format!(
                                    "CANopen SDO 0x1018 Identity: {}",
                                    sub_name
                                ),
                                confidence: 1.0,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        // Ingest into cansniffer delta/notch engine
        self.sniffer_engine.ingest_frame(&processed_frame)
    }

    /// Ingest a dissected DNP3 frame into the semantic inference catalog
    pub fn ingest_dnp3_frame(&mut self, frame: &Dnp3Frame, _timestamp_us: u64) {
        let node_str = format!("DNP3:{}:{}", frame.source, frame.destination);
        for obj in &frame.objects {
            let addr = ((obj.group as u32) << 8) | (obj.variation as u32);
            self.catalog.insert_or_update(InferredRegisterEntry {
                node_or_slave: node_str.clone(),
                address: addr,
                polling_frequency_hz: 1.0,
                jitter_ms: 0.0,
                raw_hex: format!(
                    "Grp:{} Var:{} Qual:0x{:02X}",
                    obj.group, obj.variation, obj.qualifier
                ),
                plausible_type: format!(
                    "DNP3 Group {} Var {}: {}",
                    obj.group, obj.variation, obj.description
                ),
                confidence: 1.0,
            });
        }
    }

    /// Ingest a dissected BACnet MS/TP frame into the semantic inference catalog
    pub fn ingest_bacnet_frame(&mut self, frame: &BacnetMstpFrame, _timestamp_us: u64) {
        let node_str = format!("BACnet:{}", frame.source_address);
        let addr = ((frame.frame_type as u32) << 8) | (frame.destination_address as u32);
        self.catalog.insert_or_update(InferredRegisterEntry {
            node_or_slave: node_str,
            address: addr,
            polling_frequency_hz: 1.0,
            jitter_ms: 0.0,
            raw_hex: format!(
                "Type:{} Dest:{}",
                frame.frame_type.name(),
                frame.destination_address
            ),
            plausible_type: format!(
                "BACnet MS/TP: {} -> Dest {}",
                frame.frame_type.name(),
                frame.destination_address
            ),
            confidence: 1.0,
        });
    }

    /// Start physical change isolation capture window
    pub fn start_diff_capture(&mut self, timestamp_us: u64) {
        self.diff_session.start(timestamp_us);
    }

    /// Stop physical change capture window and get report
    pub fn stop_diff_capture(&mut self, timestamp_us: u64) -> DiffCaptureReport {
        self.diff_session.stop(timestamp_us)
    }

    /// Generate an inference summary of all discovered bus entities
    pub fn get_summary(&self) -> InferenceSummary {
        InferenceSummary {
            total_discovered_registers: self.catalog.entries.len(),
            total_active_can_nodes: self.sniffer_engine.slots.len(),
            periodic_can_loops: self.histogram_engine.get_periodic_nodes().len(),
            active_diff_capture: self.diff_session.is_active(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fp_crypto::{KeyType, ManagedKey};
    use fp_dissectors::ModbusPdu;

    #[test]
    fn test_inference_engine_modbus_flow() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        let query = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0,
        };
        assert_eq!(engine.ingest_modbus_frame(&query, 1_000_000), None);

        let resp = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 4,
                data: vec![0x99, 0x9A, 0x41, 0xBB],
            },
            crc16: 0,
        };
        let matched = engine
            .ingest_modbus_frame(&resp, 1_015_000)
            .expect("Matched transaction");
        assert_eq!(matched.latency_us, 15_000);

        let summary = engine.get_summary();
        assert_eq!(summary.total_discovered_registers, 1);

        let entry = engine
            .catalog
            .entries
            .get("Slave_1:40001")
            .expect("Catalog entry");
        assert!(entry.plausible_type.contains("Float32 (CDAB"));
        assert!(entry.confidence >= 0.70);
        assert_eq!(entry.raw_hex, "0x999A41BB");
    }

    #[test]
    fn test_inference_engine_high_entropy_detection() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // Generate 32 bytes of pseudorandom high-entropy data (entropy > 7.5)
        let mut high_entropy = Vec::new();
        for i in 0..32 {
            high_entropy.push(((i * 73 + 19) % 256) as u8);
        }

        let query = ModbusRtuAdu {
            slave_id: 2,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40500,
                quantity: 16,
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&query, 1_000_000);

        let resp = ModbusRtuAdu {
            slave_id: 2,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 32,
                data: high_entropy,
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&resp, 1_010_000);

        let entry = engine
            .catalog
            .entries
            .get("Slave_2:40500")
            .expect("Catalog entry");
        assert!(entry.plausible_type.contains("Encrypted / High-Entropy"));
    }

    #[test]
    fn test_inference_engine_can_decryption_with_keyring() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // Register XOR key for CAN:0x123
        engine.keyring.insert_key(ManagedKey {
            key_id: "can123-key".to_string(),
            key_type: KeyType::XorMask,
            target_scope: "CAN:0x123".to_string(),
            secret_bytes: vec![0xAA, 0x55],
        });

        // High entropy encrypted frame (entropy >= 7.2)
        let _original_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut pseudo_high = Vec::new();
        for i in 0..16 {
            pseudo_high.push(((i * 127 + 53) % 256) as u8);
        }

        let f = CanFrame::new_standard(0x123, &pseudo_high);
        engine.ingest_can_frame(&f, 1_000_000);

        let slot = engine
            .sniffer_engine
            .slots
            .get(&fp_core::CanId::Standard(0x123))
            .expect("Slot recorded");
        assert_eq!(slot.frame_count, 1);
    }

    #[test]
    fn test_inference_engine_modbus_decryption_unpacks_registers() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // Plaintext payload starting with IEEE 754 Float32 ABCD (123.45): 0x42F6, 0xE666
        let mut plaintext: Vec<u8> = vec![0x42, 0xF6, 0xE6, 0x66];
        for i in 4..32 {
            plaintext.push(((i * 37 + 11) % 256) as u8);
        }

        // 32 distinct pseudorandom bytes (Shannon entropy = 5.0 bits/byte >= max_possible * 0.92)
        let ciphertext: Vec<u8> = (0..32).map(|i| ((i * 73 + 19) % 256) as u8).collect();

        // Exact XOR key to decrypt ciphertext -> plaintext
        let mut xor_key = Vec::with_capacity(32);
        for i in 0..32 {
            xor_key.push(plaintext[i] ^ ciphertext[i]);
        }

        // Register key for Slave_3
        engine.keyring.insert_key(ManagedKey {
            key_id: "slave3-xor".to_string(),
            key_type: KeyType::XorMask,
            target_scope: "Slave_3".to_string(),
            secret_bytes: xor_key,
        });

        // Query
        let query = ModbusRtuAdu {
            slave_id: 3,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 100,
                quantity: 16,
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&query, 2_000_000);

        // Response with high entropy ciphertext
        let resp = ModbusRtuAdu {
            slave_id: 3,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 32,
                data: ciphertext,
            },
            crc16: 0,
        };
        let matched = engine
            .ingest_modbus_frame(&resp, 2_010_000)
            .expect("Matched transaction");

        // Regression test for Bug 1.2: Register values MUST reflect decrypted plaintext, not raw ciphertext
        assert_eq!(matched.register_values[0], (100, 0x42F6));
        assert_eq!(matched.register_values[1], (101, 0xE666));

        // Catalog entry should be inferred as Float32 rather than encrypted block
        let entry = engine
            .catalog
            .entries
            .get("Slave_3:100")
            .expect("Catalog entry");
        assert!(entry.plausible_type.contains("Float32"));
    }

    #[test]
    fn test_inference_engine_j1939_dissection_populates_catalog() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // EEC1 frame for engine speed = 1024.0 RPM on 29-bit CAN ID 0x0CF00400 (SA 0x00)
        let f = CanFrame::new_extended(
            0x0CF00400,
            &[0x00, 0x7D, 0x7D, 0x00, 0x20, 0x00, 0x00, 0x00],
        );
        engine.ingest_can_frame(&f, 1_000_000);

        let entry = engine
            .catalog
            .entries
            .get("J1939:0x00:61444")
            .expect("EEC1 catalog entry");
        assert!(entry.plausible_type.contains("1024.00 RPM"));
        assert_eq!(entry.confidence, 1.0);

        // Multi-packet BAM VIN reassembly test
        // 1. Connection Management BAM (0x10, Total 17 bytes, 3 packets, PGN 65260 0x00FEEC)
        let bam_can_id = 0x18ECFF00;
        let bam_cm = [0x10, 17, 0x00, 0x03, 0xFF, 0xEC, 0xFE, 0x00];
        engine.ingest_can_frame(&CanFrame::new_extended(bam_can_id, &bam_cm), 1_010_000);

        // 2. Data Transfer Packet 1 (Seq 1, bytes 1..7: "1HGCR2F8")
        let dt_can_id = 0x18EBFF00;
        let dt1 = [1, b'1', b'H', b'G', b'C', b'R', b'2', b'F'];
        engine.ingest_can_frame(&CanFrame::new_extended(dt_can_id, &dt1), 1_020_000);

        // 3. Data Transfer Packet 2 (Seq 2, bytes 8..14: "3HA00000")
        let dt2 = [2, b'8', b'3', b'H', b'A', b'0', b'0', b'0'];
        engine.ingest_can_frame(&CanFrame::new_extended(dt_can_id, &dt2), 1_030_000);

        // 4. Data Transfer Packet 3 (Seq 3, 3 remaining bytes: "123")
        let dt3 = [3, b'1', b'2', b'3', 0xFF, 0xFF, 0xFF, 0xFF];
        engine.ingest_can_frame(&CanFrame::new_extended(dt_can_id, &dt3), 1_040_000);

        let vin_entry = engine
            .catalog
            .entries
            .get("J1939:0x00:65260")
            .expect("VIN catalog entry");
        assert!(vin_entry.plausible_type.contains("VIN: 1HGCR2F83HA000123"));
        assert_eq!(vin_entry.confidence, 1.0);
    }

    #[test]
    fn test_inference_engine_isotp_uds_dissection_populates_catalog() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // UDS ReadDataByIdentifier Positive Response (0x62) for DID 0xF190 (VIN) on CAN ID 0x7E8
        let f = CanFrame::new_standard(0x7E8, &[0x04, 0x62, 0xF1, 0x90, 0x41, 0x00, 0x00, 0x00]);
        engine.ingest_can_frame(&f, 1_000_000);

        let entry = engine
            .catalog
            .entries
            .get("UDS:0x7E8:61840")
            .expect("UDS DID entry");
        assert!(entry.plausible_type.contains("UDS DID 0xF190 Data"));
        assert_eq!(entry.confidence, 1.0);
    }

    #[test]
    fn test_inference_engine_canopen_dissection_populates_catalog() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // CANopen Heartbeat for Node 5, State 0x05 (Operational) on COB-ID 0x705
        let f = CanFrame::new_standard(0x705, &[0x05]);
        engine.ingest_can_frame(&f, 1_000_000);

        let entry = engine
            .catalog
            .entries
            .get("CANopen:5:1797")
            .expect("CANopen NMT entry");
        assert!(entry.plausible_type.contains("Operational"));
        assert_eq!(entry.confidence, 1.0);
    }

    #[test]
    fn test_inference_engine_modbus_device_id_populates_catalog() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        let adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadDeviceIdentificationResponse {
                read_device_id_code: 1,
                conformity_level: 1,
                more_follows: false,
                next_object_id: 0,
                objects: vec![
                    (0x00, "Schneider Electric".to_string()),
                    (0x01, "Modicon M340".to_string()),
                    (0x02, "v3.20".to_string()),
                ],
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&adu, 1_000_000);

        let entry_vendor = engine
            .catalog
            .entries
            .get("Slave_1:11008")
            .expect("Vendor entry");
        assert!(entry_vendor.plausible_type.contains("Schneider Electric"));
        assert_eq!(entry_vendor.confidence, 1.0);

        let entry_prod = engine
            .catalog
            .entries
            .get("Slave_1:11009")
            .expect("Product entry");
        assert!(entry_prod.plausible_type.contains("Modicon M340"));
        assert_eq!(entry_prod.confidence, 1.0);
    }

    #[test]
    fn test_inference_engine_dnp3_and_bacnet_ingestion() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // DNP3 Frame
        let dnp3_frame = Dnp3Frame {
            source: 1,
            destination: 2,
            is_from_master: true,
            is_primary: true,
            function_code: fp_dissectors::Dnp3FunctionCode::Response,
            iin: None,
            transport_seq: 0,
            objects: vec![fp_dissectors::Dnp3ObjectHeader {
                group: 30,
                variation: 1,
                qualifier: 0x06,
                description: "32-Bit Analog Input With Flag".to_string(),
            }],
            app_payload: vec![],
        };
        engine.ingest_dnp3_frame(&dnp3_frame, 1_000_000);

        let dnp3_entry = engine
            .catalog
            .entries
            .get("DNP3:1:2:7681")
            .expect("DNP3 entry");
        assert!(dnp3_entry.plausible_type.contains("Analog Input"));
        assert_eq!(dnp3_entry.confidence, 1.0);

        // BACnet MS/TP Frame
        let bacnet_frame = BacnetMstpFrame {
            frame_type: fp_dissectors::BacnetMstpFrameType::Token,
            destination_address: 10,
            source_address: 5,
            data_length: 0,
            header_crc: 0,
            payload: vec![],
            data_crc: None,
        };
        engine.ingest_bacnet_frame(&bacnet_frame, 1_000_000);

        let bac_entry = engine
            .catalog
            .entries
            .get("BACnet:5:10")
            .expect("BACnet entry");
        assert!(bac_entry.plausible_type.contains("Token Pass"));
        assert_eq!(bac_entry.confidence, 1.0);
    }
}
