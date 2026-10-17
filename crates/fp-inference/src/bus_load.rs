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

/// Calculate nominal on-wire bit count for a CAN frame including bit-stuffing approximation
pub fn calculate_frame_bit_length(frame: &CanFrame) -> u32 {
    let dlc = frame.data.len().min(8) as u32;

    match frame.id {
        CanId::Standard(_) => {
            // Standard frame: 47 fixed/overhead bits + 8 * DLC data bits
            // Stuffed bits: SOF(1) + ID(11) + RTR(1) + IDE(1) + r0(1) + DLC(4) + Data(8*DLC) + CRC(15) = 34 + 8*DLC
            // Approximate worst-case stuffing adds up to ~20%
            let stuffed_base = 34 + (8 * dlc);
            let estimated_stuff_bits = stuffed_base / 5;
            let fixed_bits = 13; // CRC del(1), ACK(2), EOF(7), Intermission(3)
            stuffed_base + estimated_stuff_bits + fixed_bits
        }
        CanId::Extended(_) => {
            // Extended frame: 67 fixed/overhead bits + 8 * DLC data bits
            let stuffed_base = 54 + (8 * dlc);
            let estimated_stuff_bits = stuffed_base / 5;
            let fixed_bits = 13;
            stuffed_base + estimated_stuff_bits + fixed_bits
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
}
