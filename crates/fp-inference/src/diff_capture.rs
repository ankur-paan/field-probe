use fp_core::CanId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Details of a specific register or signal that mutated during a diff capture window
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutatedEntity {
    pub entity_type: String, // "ModbusRegister" or "CanId"
    pub identifier: String,   // "Slave 1 / Reg 40001" or "CAN 0x123"
    pub baseline_value_hex: String,
    pub mutated_value_hex: String,
    pub bitmask_diff: String,
    pub first_change_timestamp_us: u64,
}

/// Report summarizing all mutations observed during an active physical event correlation window
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffCaptureReport {
    pub start_timestamp_us: u64,
    pub stop_timestamp_us: u64,
    pub duration_ms: u64,
    pub total_entities_monitored: usize,
    pub total_mutations_detected: usize,
    pub mutations: Vec<MutatedEntity>,
}

/// Session tracking baseline snapshots and isolating physical deltas
#[derive(Debug, Clone, Default)]
pub struct DiffCaptureSession {
    is_active: bool,
    start_timestamp_us: u64,
    baseline_registers: HashMap<String, u16>, // key: "slave:addr"
    current_registers: HashMap<String, (u16, u64)>, // key -> (value, change_time)
    baseline_can_slots: HashMap<CanId, [u8; 8]>,
    current_can_slots: HashMap<CanId, ([u8; 8], u64)>,
}

impl DiffCaptureSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Start a new physical event capture window, snapshotting current baseline
    pub fn start(&mut self, timestamp_us: u64) {
        self.is_active = true;
        self.start_timestamp_us = timestamp_us;
        // Promote current state to baseline
        self.baseline_registers.clear();
        for (k, (v, _)) in &self.current_registers {
            self.baseline_registers.insert(k.clone(), *v);
        }
        self.baseline_can_slots.clear();
        for (k, (v, _)) in &self.current_can_slots {
            self.baseline_can_slots.insert(*k, *v);
        }
    }

    /// Record an incoming register observation
    pub fn record_register(&mut self, slave: u8, addr: u16, val: u16, timestamp_us: u64) {
        let key = format!("{}:{}", slave, addr);
        if !self.is_active {
            // Update baseline when not in active capture
            self.baseline_registers.insert(key.clone(), val);
        }
        self.current_registers.insert(key, (val, timestamp_us));
    }

    /// Record an incoming CAN frame payload
    pub fn record_can_frame(&mut self, id: CanId, data: &[u8], timestamp_us: u64) {
        let mut bytes = [0u8; 8];
        let len = data.len().min(8);
        bytes[..len].copy_from_slice(&data[..len]);

        if !self.is_active {
            self.baseline_can_slots.insert(id, bytes);
        }
        self.current_can_slots.insert(id, (bytes, timestamp_us));
    }

    /// Stop the capture window and return all isolated deltas
    pub fn stop(&mut self, stop_timestamp_us: u64) -> DiffCaptureReport {
        self.is_active = false;
        let mut mutations = Vec::new();

        // 1. Check Modbus register deltas
        for (key, (current_val, change_time)) in &self.current_registers {
            let baseline_val = self.baseline_registers.get(key).copied().unwrap_or(0);
            if *current_val != baseline_val {
                let diff_bits = current_val ^ baseline_val;
                mutations.push(MutatedEntity {
                    entity_type: "ModbusRegister".to_string(),
                    identifier: format!("Register {}", key),
                    baseline_value_hex: format!("0x{:04X}", baseline_val),
                    mutated_value_hex: format!("0x{:04X}", current_val),
                    bitmask_diff: format!("0x{:04X}", diff_bits),
                    first_change_timestamp_us: *change_time,
                });
            }
        }

        // 2. Check CAN frame deltas
        for (id, (current_bytes, change_time)) in &self.current_can_slots {
            let baseline_bytes = self.baseline_can_slots.get(id).copied().unwrap_or([0; 8]);
            if *current_bytes != baseline_bytes {
                let mut diff = [0u8; 8];
                for i in 0..8 {
                    diff[i] = current_bytes[i] ^ baseline_bytes[i];
                }
                mutations.push(MutatedEntity {
                    entity_type: "CanFrame".to_string(),
                    identifier: format!("CAN ID {:?}", id),
                    baseline_value_hex: hex_str(&baseline_bytes),
                    mutated_value_hex: hex_str(current_bytes),
                    bitmask_diff: hex_str(&diff),
                    first_change_timestamp_us: *change_time,
                });
            }
        }

        let total_entities = self.current_registers.len() + self.current_can_slots.len();
        let total_mutations = mutations.len();
        let duration_ms = stop_timestamp_us.saturating_sub(self.start_timestamp_us) / 1000;

        DiffCaptureReport {
            start_timestamp_us: self.start_timestamp_us,
            stop_timestamp_us,
            duration_ms,
            total_entities_monitored: total_entities,
            total_mutations_detected: total_mutations,
            mutations,
        }
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_capture_isolates_mutated_register() {
        let mut session = DiffCaptureSession::new();

        // Baseline: Register 1:100 is 0x0000, 1:101 is 0x1234
        session.record_register(1, 100, 0x0000, 1_000_000);
        session.record_register(1, 101, 0x1234, 1_000_000);

        // Start physical watch capture
        session.start(2_000_000);

        // Physical action occurs: Register 1:100 flips to 0x0001 (e.g., motor turned on)
        // Register 1:101 stays 0x1234
        session.record_register(1, 100, 0x0001, 2_500_000);
        session.record_register(1, 101, 0x1234, 2_500_000);

        // Stop capture
        let report = session.stop(3_000_000);
        assert_eq!(report.total_mutations_detected, 1);
        assert_eq!(report.mutations[0].identifier, "Register 1:100");
        assert_eq!(report.mutations[0].baseline_value_hex, "0x0000");
        assert_eq!(report.mutations[0].mutated_value_hex, "0x0001");
        assert_eq!(report.mutations[0].bitmask_diff, "0x0001");
    }
}
