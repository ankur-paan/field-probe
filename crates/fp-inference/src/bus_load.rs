use fp_core::{CanFrame, CanId};
use serde::{Deserialize, Serialize};

/// Accurate CAN bus load estimator based on CaringCaribou physical bit-length calculations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusLoadReport {
    pub bitrate: u32,
    pub sample_window_ms: u64,
    pub total_frames_in_window: u64,
    pub total_bits_in_window: u64,
    /// Bus load percentage (0.0 to 100.0%)
    pub bus_load_percent: f32,
    pub is_overloaded: bool,
}

/// Calculate nominal on-wire bit count for a CAN 2.0 or CAN-FD frame including bit-stuffing approximation (ISO 11898-1:2015)
pub fn calculate_frame_bit_length(frame: &CanFrame) -> u32 {
    let payload_bytes = if frame.is_fd {
        frame.data.len().min(64) as u32
    } else {
        frame.data.len().min(8) as u32
    };

    if frame.is_fd {
        // CAN-FD uses 17-bit CRC for payloads <= 16B, and 21-bit CRC for 20..=64B
        let crc_bits = if payload_bytes <= 16 { 17 } else { 21 };
        let fixed_stuff_in_crc = (crc_bits / 4) + 1;
        let arb_bits = match frame.id {
            CanId::Standard(_) => 29,
            CanId::Extended(_) => 49,
        };
        let data_bits = payload_bytes * 8;
        let dynamic_stuff = (arb_bits + data_bits) / 5;
        arb_bits + data_bits + crc_bits + fixed_stuff_in_crc + dynamic_stuff + 11
    } else {
        match frame.id {
            CanId::Standard(_) => {
                let stuffed_base = 34 + (8 * payload_bytes);
                stuffed_base + (stuffed_base / 5) + 13
            }
            CanId::Extended(_) => {
                let stuffed_base = 54 + (8 * payload_bytes);
                stuffed_base + (stuffed_base / 5) + 13
            }
        }
    }
}

/// Rolling window bus load tracker
#[derive(Debug, Clone)]
pub struct BusLoadEstimator {
    pub nominal_bitrate: u32,
    pub window_duration_us: u64,
    pub window_start_us: Option<u64>,
    pub accumulated_bits: u64,
    pub accumulated_frames: u64,
}

impl BusLoadEstimator {
    pub fn new(nominal_bitrate: u32, window_duration_ms: u64) -> Self {
        Self {
            nominal_bitrate,
            window_duration_us: window_duration_ms * 1000,
            window_start_us: None,
            accumulated_bits: 0,
            accumulated_frames: 0,
        }
    }

    /// Ingest a frame with its timestamp in microseconds.
    /// If the window duration has elapsed, returns the computed BusLoadReport and resets the window.
    pub fn ingest_frame(&mut self, frame: &CanFrame, timestamp_us: u64) -> Option<BusLoadReport> {
        let start = match self.window_start_us {
            Some(s) => s,
            None => {
                self.window_start_us = Some(timestamp_us);
                timestamp_us
            }
        };

        let bits = calculate_frame_bit_length(frame);
        self.accumulated_bits += bits as u64;
        self.accumulated_frames += 1;

        let elapsed_us = timestamp_us.saturating_sub(start);
        if elapsed_us >= self.window_duration_us {
            let elapsed_sec = (elapsed_us as f64) / 1_000_000.0;
            let max_possible_bits = (self.nominal_bitrate as f64) * elapsed_sec;

            let bus_load_percent = if max_possible_bits > 0.0 {
                ((self.accumulated_bits as f64 / max_possible_bits) * 100.0) as f32
            } else {
                0.0
            };

            let report = BusLoadReport {
                bitrate: self.nominal_bitrate,
                sample_window_ms: elapsed_us / 1000,
                total_frames_in_window: self.accumulated_frames,
                total_bits_in_window: self.accumulated_bits,
                bus_load_percent: bus_load_percent.min(100.0),
                is_overloaded: bus_load_percent > 70.0, // Standard CAN rule: >70% causes arbitration delays
            };

            // Reset window
            self.window_start_us = Some(timestamp_us);
            self.accumulated_bits = 0;
            self.accumulated_frames = 0;

            Some(report)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_frame_bit_calculation() {
        let frame = CanFrame::new_standard(0x123, &[0x00; 8]);
        let bits = calculate_frame_bit_length(&frame);
        // Base: 34 + 64 = 98. Stuff: 98/5 = 19. Fixed: 13. Total = 130
        assert_eq!(bits, 130);
    }

    #[test]
    fn test_bus_load_estimation_report() {
        let mut estimator = BusLoadEstimator::new(500_000, 1000); // 500 kbps, 1000ms window
        let frame = CanFrame::new_standard(0x100, &[0xAA; 8]); // ~130 bits

        // Feed 1000 frames over 1 second (1000 * 130 = 130,000 bits / 500,000 = 26%)
        let mut report = None;
        for i in 0..=1000 {
            let ts = i * 1000; // 1ms intervals
            report = estimator.ingest_frame(&frame, ts);
        }

        let rep = report.expect("Window report generated");
        assert_eq!(rep.bitrate, 500_000);
        assert!((rep.bus_load_percent - 26.0).abs() < 2.0);
        assert!(!rep.is_overloaded);
    }

    #[test]
    fn test_can_fd_frame_bit_calculation() {
        let fd_frame_64 = CanFrame::new_standard_fd(0x100, &[0xAA; 64]).with_brs_esi(true, false);
        let bits = calculate_frame_bit_length(&fd_frame_64);
        // arb(29) + data(512) + crc(21) + fixed_stuff(6) + dyn_stuff(108) + 11 = 687
        assert!(bits > 600 && bits < 750);

        let fd_frame_16 = CanFrame::new_standard_fd(0x100, &[0x55; 16]);
        let bits_16 = calculate_frame_bit_length(&fd_frame_16);
        assert!(bits_16 > 150 && bits_16 < 300);
    }
}
