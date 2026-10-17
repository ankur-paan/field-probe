use fp_core::CanId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Details of a specific register or signal that mutated during a diff capture window
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutatedEntity {
    pub entity_type: String, // "ModbusRegister" or "CanId"
    pub identifier: String,  // "Slave 1 / Reg 40001" or "CAN 0x123"
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

/// Session tracking baseline snapshots, auto-notching ambient noise, and isolating physical deltas
#[derive(Debug, Clone, Default)]
pub struct DiffCaptureSession {
    is_active: bool,
    start_timestamp_us: u64,
    baseline_registers: HashMap<String, u16>, // key: "slave:addr"
    current_registers: HashMap<String, (u16, u64)>, // key -> (value, change_time)
    register_notches: HashMap<String, u16>,   // ambient fluctuating bitmask per register
    baseline_can_slots: HashMap<CanId, ([u8; 64], usize)>,
    current_can_slots: HashMap<CanId, ([u8; 64], usize, u64)>,
    can_notches: HashMap<CanId, [u8; 64]>, // ambient fluctuating bitmask per CAN ID
}

impl DiffCaptureSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Clear all baseline snapshots and accumulated noise notches
    pub fn clear(&mut self) {
        self.is_active = false;
        self.baseline_registers.clear();
        self.current_registers.clear();
        self.register_notches.clear();
        self.baseline_can_slots.clear();
        self.current_can_slots.clear();
        self.can_notches.clear();
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
        for (k, (v, dlc, _)) in &self.current_can_slots {
            self.baseline_can_slots.insert(*k, (*v, *dlc));
        }
    }

    /// Record an incoming register observation with automatic ambient noise notching
    pub fn record_register(&mut self, slave: u8, addr: u16, val: u16, timestamp_us: u64) {
        let key = format!("{}:{}", slave, addr);
        if !self.is_active {
            // While monitoring baseline, automatically notch any bits that fluctuate on their own
            if let Some(&prev_val) = self.baseline_registers.get(&key) {
                let ambient_diff = val ^ prev_val;
                if ambient_diff != 0 {
                    let entry = self.register_notches.entry(key.clone()).or_insert(0);
                    *entry |= ambient_diff;
                }
            }
            self.baseline_registers.insert(key.clone(), val);
        }
        self.current_registers.insert(key, (val, timestamp_us));
    }

    /// Record an incoming CAN frame payload with automatic ambient noise notching (supports up to 64B CAN-FD)
    pub fn record_can_frame(&mut self, id: CanId, data: &[u8], timestamp_us: u64) {
        let mut bytes = [0u8; 64];
        let len = data.len().min(64);
        bytes[..len].copy_from_slice(&data[..len]);

        if !self.is_active {
            // While monitoring baseline, automatically notch any bits that fluctuate on their own
            if let Some((prev_bytes, _)) = self.baseline_can_slots.get(&id) {
                let notch = self.can_notches.entry(id).or_insert([0u8; 64]);
                for i in 0..len {
                    notch[i] |= bytes[i] ^ prev_bytes[i];
                }
            }
            self.baseline_can_slots.insert(id, (bytes, len));
        }
        self.current_can_slots
            .insert(id, (bytes, len, timestamp_us));
    }

    /// Manually apply a notch mask to suppress noisy ambient bits on a specific register
    pub fn notch_register(&mut self, slave: u8, addr: u16, mask: u16) {
        let key = format!("{}:{}", slave, addr);
        let entry = self.register_notches.entry(key).or_insert(0);
        *entry |= mask;
    }

    /// Manually apply a notch mask to suppress noisy ambient bits on a specific CAN arbitration ID
    pub fn notch_can_id(&mut self, id: CanId, mask: [u8; 8]) {
        let entry = self.can_notches.entry(id).or_insert([0u8; 64]);
        for i in 0..8 {
            entry[i] |= mask[i];
        }
    }

    /// Manually apply a full 64-byte notch mask for CAN-FD arbitration IDs
    pub fn notch_can_id_64(&mut self, id: CanId, mask: [u8; 64]) {
        let entry = self.can_notches.entry(id).or_insert([0u8; 64]);
        for i in 0..64 {
            entry[i] |= mask[i];
        }
    }

    /// Stop the capture window and return all isolated deltas, filtering out notched ambient noise
    pub fn stop(&mut self, stop_timestamp_us: u64) -> DiffCaptureReport {
        self.is_active = false;
        let mut mutations = Vec::new();

        // 1. Check Modbus register deltas with ambient noise suppression
        for (key, (current_val, change_time)) in &self.current_registers {
            let baseline_val = self.baseline_registers.get(key).copied().unwrap_or(0);
            let notch_mask = self.register_notches.get(key).copied().unwrap_or(0);

            let raw_diff = current_val ^ baseline_val;
            let active_diff = raw_diff & !notch_mask;

            if active_diff != 0 {
                mutations.push(MutatedEntity {
                    entity_type: "ModbusRegister".to_string(),
                    identifier: format!("Register {}", key),
                    baseline_value_hex: format!("0x{:04X}", baseline_val),
                    mutated_value_hex: format!("0x{:04X}", current_val),
                    bitmask_diff: format!("0x{:04X}", active_diff),
                    first_change_timestamp_us: *change_time,
                });
            }
        }

        // 2. Check CAN frame deltas with ambient noise suppression
        for (id, (current_bytes, dlc, change_time)) in &self.current_can_slots {
            let (baseline_bytes, base_dlc) = self
                .baseline_can_slots
                .get(id)
                .copied()
                .unwrap_or(([0; 64], *dlc));
            let notch_mask = self.can_notches.get(id).copied().unwrap_or([0u8; 64]);
            let active_len = (*dlc).max(base_dlc);

            let mut raw_diff = [0u8; 64];
            let mut active_diff = [0u8; 64];
            let mut has_active_mutation = false;

            for i in 0..active_len {
                raw_diff[i] = current_bytes[i] ^ baseline_bytes[i];
                active_diff[i] = raw_diff[i] & !notch_mask[i];
                if active_diff[i] != 0 {
                    has_active_mutation = true;
                }
            }

            if has_active_mutation {
                mutations.push(MutatedEntity {
                    entity_type: "CanFrame".to_string(),
                    identifier: match id {
                        CanId::Standard(v) => format!("CAN 0x{:03X}", v),
                        CanId::Extended(v) => format!("CAN 0x{:08X}", v),
                    },
                    baseline_value_hex: hex_str(&baseline_bytes[..active_len]),
                    mutated_value_hex: hex_str(&current_bytes[..active_len]),
                    bitmask_diff: hex_str(&active_diff[..active_len]),
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
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_capture_isolates_mutated_register() {
        let mut session = DiffCaptureSession::new();

        // Baseline: Register 1:40001 = 0x0000
        session.record_register(1, 40001, 0x0000, 1000);
        session.start(2000);

        // Operator flips a physical switch: Register 1:40001 changes to 0x0001
        session.record_register(1, 40001, 0x0001, 2500);

        let report = session.stop(3000);
        assert_eq!(report.total_mutations_detected, 1);
        let m = &report.mutations[0];
        assert_eq!(m.entity_type, "ModbusRegister");
        assert_eq!(m.bitmask_diff, "0x0001");
        assert_eq!(m.mutated_value_hex, "0x0001");
    }

    #[test]
    fn test_diff_capture_auto_notches_ambient_noise() {
        let mut session = DiffCaptureSession::new();

        // Simulate ambient sensor noise prior to start() on Reg 1:40001 (e.g. low nibble jitter 0x0002 <-> 0x0003)
        session.record_register(1, 40001, 0x0002, 100);
        session.record_register(1, 40001, 0x0003, 200); // Bit 0 jittered!
        session.record_register(1, 40001, 0x0002, 300);

        // Start capture window
        session.start(1000);

        // Scenario A: Jitter on bit 0 continues (0x0002 -> 0x0003)
        // Scenario B: Operator flips switch connected to bit 8 (0x0002 -> 0x0103)
        session.record_register(1, 40001, 0x0103, 1500);

        let report = session.stop(2000);
        assert_eq!(report.total_mutations_detected, 1);
        let m = &report.mutations[0];
        // Jitter on bit 0 was auto-notched, only bit 8 (0x0100) is reported!
        assert_eq!(m.bitmask_diff, "0x0100");
    }

    #[test]
    fn test_diff_capture_can_auto_notching() {
        let mut session = DiffCaptureSession::new();
        let id = CanId::Standard(0x200);

        // Rolling counter in Byte 0 prior to capture
        session.record_can_frame(id, &[0x01, 0x00, 0x00, 0x00], 100);
        session.record_can_frame(id, &[0x02, 0x00, 0x00, 0x00], 200);

        session.start(1000);

        // Rolling counter continues to Byte 0 = 0x03, but operator activates actuator on Byte 2 = 0x80
        session.record_can_frame(id, &[0x03, 0x00, 0x80, 0x00], 1500);

        let report = session.stop(2000);
        assert_eq!(report.total_mutations_detected, 1);
        let m = &report.mutations[0];
        // Byte 0 was auto-notched, so active diff only reports Byte 2 (0x80)
        assert!(m.bitmask_diff.contains("80"));
    }
}
