use fp_core::{CanFrame, CanId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Delta report for changed bits within a CAN arbitration ID slot
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitDeltaReport {
    pub can_id: CanId,
    pub dlc: usize,
    /// Bitwise XOR change between current and previous frame
    pub raw_delta: [u8; 8],
    /// Active change after suppressing notched (noisy) bits
    pub active_delta: [u8; 8],
    /// Mask of currently notched bits
    pub notch_mask: [u8; 8],
    /// Current raw frame payload
    pub current_data: [u8; 8],
    /// Visual hold ticks remaining
    pub hold_ticks: u32,
}

/// Slot tracking frame history, bit notches, and decay counters for a single CAN ID
/// (Ported from linux-can / can-utils `cansniffer.c`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnifferSlot {
    pub can_id: CanId,
    pub last_data: [u8; 8],
    pub current_data: [u8; 8],
    pub dlc: usize,
    /// Mutated bits (current ^ last)
    pub marker: [u8; 8],
    /// Suppressed noisy bits (rolling counters, time-of-day bytes)
    pub notch: [u8; 8],
    /// Persistence ticks for visual delta decay
    pub hold_ticks: u32,
    /// Count of times this ID was received
    pub frame_count: u64,
}

impl SnifferSlot {
    pub fn new(can_id: CanId) -> Self {
        Self {
            can_id,
            last_data: [0; 8],
            current_data: [0; 8],
            dlc: 0,
            marker: [0; 8],
            notch: [0; 8],
            hold_ticks: 0,
            frame_count: 0,
        }
    }

    /// Process a newly received CAN frame for this arbitration slot.
    /// Returns BitDeltaReport if any unnotched bit changed.
    pub fn update(&mut self, frame: &CanFrame, initial_hold_ticks: u32) -> Option<BitDeltaReport> {
        self.frame_count += 1;
        let dlc = frame.data.len().min(8);
        self.dlc = dlc;

        let mut new_data = [0u8; 8];
        new_data[..dlc].copy_from_slice(&frame.data[..dlc]);

        // First frame: initialize baseline without delta
        if self.frame_count == 1 {
            self.current_data = new_data;
            self.last_data = new_data;
            return None;
        }

        self.last_data = self.current_data;
        self.current_data = new_data;

        // Step 1: Compute raw bitwise change (delta = current ^ last)
        let mut raw_delta = [0u8; 8];
        let mut active_delta = [0u8; 8];
        let mut has_active_change = false;

        for i in 0..dlc {
            raw_delta[i] = self.current_data[i] ^ self.last_data[i];
            // Step 2: Apply notch filter (active_delta = raw_delta & ~notch)
            active_delta[i] = raw_delta[i] & (!self.notch[i]);
            if active_delta[i] != 0 {
                has_active_change = true;
            }
        }

        self.marker = active_delta;

        if has_active_change {
            self.hold_ticks = initial_hold_ticks;
            Some(BitDeltaReport {
                can_id: self.can_id,
                dlc,
                raw_delta,
                active_delta,
                notch_mask: self.notch,
                current_data: self.current_data,
                hold_ticks: self.hold_ticks,
            })
        } else {
            // Decay hold ticks
            if self.hold_ticks > 0 {
                self.hold_ticks -= 1;
            }
            None
        }
    }

    /// Suppress all currently changing bits by incorporating them into the notch filter
    pub fn notch_active_bits(&mut self) {
        for i in 0..8 {
            self.notch[i] |= self.marker[i];
            self.marker[i] = 0;
        }
    }

    /// Clear all notches on this slot
    pub fn clear_notches(&mut self) {
        self.notch = [0; 8];
    }
}

/// Global tracker holding sniffer slots for all observed arbitration IDs
#[derive(Debug, Clone, Default)]
pub struct CanSnifferEngine {
    pub slots: HashMap<CanId, SnifferSlot>,
    pub default_hold_ticks: u32,
}

impl CanSnifferEngine {
    pub fn new(default_hold_ticks: u32) -> Self {
        Self {
            slots: HashMap::new(),
            default_hold_ticks,
        }
    }

    /// Ingest a frame and return delta report if relevant bits changed
    pub fn ingest_frame(&mut self, frame: &CanFrame) -> Option<BitDeltaReport> {
        let slot = self
            .slots
            .entry(frame.id)
            .or_insert_with(|| SnifferSlot::new(frame.id));
        slot.update(frame, self.default_hold_ticks)
    }

    /// Add notch mask to a specific CAN ID
    pub fn notch_id(&mut self, can_id: CanId) {
        if let Some(slot) = self.slots.get_mut(&can_id) {
            slot.notch_active_bits();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cansniffer_delta_and_notch() {
        let mut engine = CanSnifferEngine::new(10);
        let id = CanId::Standard(0x123);

        // Frame 1: baseline
        let f1 = CanFrame::new_standard(0x123, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(engine.ingest_frame(&f1), None);

        // Frame 2: Byte 0 changes from 0x00 to 0x01 (bit 0 changed)
        let f2 = CanFrame::new_standard(0x123, &[0x01, 0x00, 0x00, 0x00]);
        let rep = engine.ingest_frame(&f2).expect("Delta expected");
        assert_eq!(rep.active_delta[0], 0x01);
        assert_eq!(rep.hold_ticks, 10);

        // Apply notch to suppress bit 0 changes
        engine.notch_id(id);

        // Frame 3: Byte 0 changes from 0x01 to 0x00 (notched, should NOT trigger active delta)
        let f3 = CanFrame::new_standard(0x123, &[0x00, 0x00, 0x00, 0x00]);
        let rep3 = engine.ingest_frame(&f3);
        assert_eq!(rep3, None);

        // Frame 4: Byte 1 changes from 0x00 to 0x80 (unnotched bit, should trigger)
        let f4 = CanFrame::new_standard(0x123, &[0x00, 0x80, 0x00, 0x00]);
        let rep4 = engine
            .ingest_frame(&f4)
            .expect("Delta expected on unnotched byte");
        assert_eq!(rep4.active_delta[1], 0x80);
    }
}
