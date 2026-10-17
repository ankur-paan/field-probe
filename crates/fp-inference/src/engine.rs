use std::collections::HashMap;

use fp_core::CanFrame;
use fp_dissectors::ModbusRtuAdu;
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

        // Update register values, catalog, and plausibility
        let node_str = format!("Slave_{}", matched.slave_id);

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

            let mut is_32bit_float = false;
            let (plausible_type, confidence) = if let Some(r1) = next_val {
                let candidates = self
                    .plausibility_scorer
                    .evaluate_pair(&node_str, addr as u32, val, r1);
                if let Some(top) = candidates.first() {
                    if top.representation_name.starts_with("Float32") && top.confidence >= 0.70 {
                        is_32bit_float = true;
                    }
                    (top.representation_name.clone(), top.confidence)
                } else {
                    ("UInt16".to_string(), 0.50)
                }
            } else {
                ("UInt16".to_string(), 0.60)
            };

            if is_32bit_float {
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

    /// Process an incoming CAN frame
    pub fn ingest_can_frame(
        &mut self,
        frame: &CanFrame,
        timestamp_us: u64,
    ) -> Option<BitDeltaReport> {
        // Record in histogram engine to detect periodic broadcast loops
        self.histogram_engine.record_frame(frame.id, timestamp_us);

        // Record in bus load estimator
        let _ = self.bus_load_estimator.ingest_frame(frame, timestamp_us);

        // Record in diff capture session
        self.diff_session.record_can_frame(frame.id, &frame.data, timestamp_us);

        // Ingest into cansniffer delta/notch engine
        self.sniffer_engine.ingest_frame(frame)
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
    use fp_dissectors::ModbusPdu;

    #[test]
    fn test_inference_engine_modbus_flow() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        // 1. Query: Slave 1, FC 0x03, Start 40001, Count 2
        let query = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0,
        };
        assert_eq!(engine.ingest_modbus_frame(&query, 1_000_000), None);

        // 2. Response: 23.45 in CDAB (r0 = 0x999A, r1 = 0x41BB)
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
        // Register pair (40001 + 40002) is cataloged as a single Float32 entry, skipping spurious UInt16 for r1
        assert_eq!(summary.total_discovered_registers, 1);

        let entry = engine.catalog.entries.get("Slave_1:40001").expect("Catalog entry");
        assert!(entry.plausible_type.contains("Float32 (CDAB"));
        assert!(entry.confidence >= 0.70);
        assert_eq!(entry.raw_hex, "0x999A41BB");

        // 3. Follow-up query after 100ms (10 Hz nominal rate)
        let query2 = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0,
        };
        assert_eq!(engine.ingest_modbus_frame(&query2, 1_100_000), None);

        let resp2 = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 4,
                data: vec![0x99, 0x9A, 0x41, 0xBB],
            },
            crc16: 0,
        };
        let _ = engine.ingest_modbus_frame(&resp2, 1_115_000).expect("Matched transaction 2");

        let entry2 = engine.catalog.entries.get("Slave_1:40001").expect("Catalog entry");
        // Interval was 100,000 us (100 ms) -> ~10.0 Hz
        assert!((entry2.polling_frequency_hz - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_inference_engine_can_flow() {
        let mut engine = InferenceEngine::new(500_000, 1000);

        let f1 = CanFrame::new_standard(0x300, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(engine.ingest_can_frame(&f1, 1_000_000), None);

        let f2 = CanFrame::new_standard(0x300, &[0x01, 0x00, 0x00, 0x00]);
        let delta = engine.ingest_can_frame(&f2, 1_020_000).expect("Delta detected");
        assert_eq!(delta.active_delta[0], 0x01);
    }
}
