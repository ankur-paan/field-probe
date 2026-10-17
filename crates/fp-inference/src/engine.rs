use std::collections::HashMap;

use fp_core::CanFrame;
use fp_crypto::{auto_decrypt_payload, calculate_shannon_entropy, is_high_entropy_payload, KeyRing};
use fp_dissectors::{ModbusPdu, ModbusRtuAdu};
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
        }
    }

    /// Process an incoming Modbus RTU frame
    pub fn ingest_modbus_frame(
        &mut self,
        adu: &ModbusRtuAdu,
        timestamp_us: u64,
    ) -> Option<MatchedTransaction> {
        let matched = self.transaction_matcher.ingest_modbus_frame(adu, timestamp_us)?;

        // Update Welford timing tracker per (slave_id, start_address)
        let timing_tracker = self
            .modbus_timing_trackers
            .entry((matched.slave_id, matched.start_address))
            .or_default();
        timing_tracker.update(timestamp_us);
        let (polling_frequency_hz, jitter_ms) = timing_tracker.rate_and_jitter();

        let node_str = format!("Slave_{}", matched.slave_id);

        let mut is_encrypted_block = false;
        // Check Shannon entropy on response payload
        if let ModbusPdu::ReadResponse { data, .. } = &adu.pdu {
            let entropy = calculate_shannon_entropy(data);
            let max_possible = if data.len() < 256 {
                (data.len() as f32).log2().min(8.0)
            } else {
                8.0
            };
            let is_high_entropy = entropy >= 7.2 || (data.len() >= 16 && entropy >= max_possible * 0.92);

            if is_high_entropy {
                let decrypted = auto_decrypt_payload(&self.keyring, &node_str, data)
                    .or_else(|| auto_decrypt_payload(&self.keyring, "global", data));

                if decrypted.is_none() {
                    is_encrypted_block = true;
                    self.catalog.insert_or_update(InferredRegisterEntry {
                        node_or_slave: node_str.clone(),
                        address: matched.start_address as u32,
                        polling_frequency_hz: polling_frequency_hz as f32,
                        jitter_ms: jitter_ms as f32,
                        raw_hex: format!(
                            "0x{}",
                            data.iter().map(|b| format!("{:02X}", b)).collect::<String>()
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
            self.diff_session.record_register(matched.slave_id, addr, val, timestamp_us);

            let next_addr = addr.wrapping_add(1);
            let next_val = matched
                .register_values
                .iter()
                .find(|(a, _)| *a == next_addr)
                .map(|(_, v)| *v);

            let mut advance_two = false;
            let (plausible_type, confidence) = if let Some(r1) = next_val {
                let candidates = self
                    .plausibility_scorer
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
                self.diff_session.record_register(matched.slave_id, next_addr, r1, timestamp_us);

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

        // Ingest into cansniffer delta/notch engine
        self.sniffer_engine.ingest_frame(&processed_frame)
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
        let matched = engine.ingest_modbus_frame(&resp, 1_015_000).expect("Matched transaction");
        assert_eq!(matched.latency_us, 15_000);

        let summary = engine.get_summary();
        assert_eq!(summary.total_discovered_registers, 1);

        let entry = engine.catalog.entries.get("Slave_1:40001").expect("Catalog entry");
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

        let entry = engine.catalog.entries.get("Slave_2:40500").expect("Catalog entry");
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
}
