use fp_core::CanId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Periodic broadcast classification for a CAN ID
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeriodicStats {
    pub can_id: CanId,
    pub frame_count: u64,
    /// Mean inter-arrival interval in milliseconds
    pub mean_interval_ms: f64,
    /// Standard deviation of inter-arrival interval in milliseconds
    pub std_dev_ms: f64,
    /// Coefficient of variation (std_dev / mean). Values < 0.05 (5%) indicate periodic broadcast
    pub jitter_ratio: f64,
    /// True if standard deviation is below 5% threshold
    pub is_periodic: bool,
    /// Estimated nominal broadcast frequency in Hertz (Hz)
    pub estimated_freq_hz: f64,
}

/// Online statistical tracker using Welford's algorithm for running mean, variance, and jitter
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WelfordTracker {
    pub last_timestamp_us: Option<u64>,
    pub sample_count: u64,
    mean_us: f64,
    m2_us: f64,
}

impl WelfordTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update with incoming observation timestamp (in microseconds)
    pub fn update(&mut self, timestamp_us: u64) {
        self.sample_count += 1;

        if let Some(prev) = self.last_timestamp_us {
            if timestamp_us > prev {
                let delta_us = (timestamp_us - prev) as f64;
                let count = self.sample_count.saturating_sub(1) as f64;
                let delta = delta_us - self.mean_us;
                self.mean_us += delta / count;
                let delta2 = delta_us - self.mean_us;
                self.m2_us += delta * delta2;
            }
        }

        self.last_timestamp_us = Some(timestamp_us);
    }

    /// Calculate polling rate in Hz and jitter in milliseconds
    pub fn rate_and_jitter(&self) -> (f64, f64) {
        if self.sample_count < 2 {
            return (1.0, 0.0);
        }

        let n = (self.sample_count - 1) as f64;
        let variance_us = if n > 1.0 { self.m2_us / (n - 1.0) } else { 0.0 };
        let std_dev_us = variance_us.sqrt();

        let mean_ms = self.mean_us / 1000.0;
        let jitter_ms = std_dev_us / 1000.0;

        let freq_hz = if mean_ms > 0.001 {
            1000.0 / mean_ms
        } else {
            0.0
        };

        (freq_hz, jitter_ms)
    }
}

/// Online statistical tracker for a single CAN arbitration ID
/// (Ported from SavvyCAN interval histogram and timing logic)
#[derive(Debug, Clone)]
pub struct IdTimingTracker {
    pub can_id: CanId,
    pub last_timestamp_us: Option<u64>,
    pub frame_count: u64,
    // Welford's algorithm state for online mean and variance
    mean_us: f64,
    m2_us: f64,
    // Histogram bins (intervals in ms): <15ms, 15-25ms, 40-60ms, 90-110ms, 230-270ms, 900-1100ms, other
    pub bin_10ms: u64,
    pub bin_20ms: u64,
    pub bin_50ms: u64,
    pub bin_100ms: u64,
    pub bin_250ms: u64,
    pub bin_1000ms: u64,
    pub bin_other: u64,
}

impl IdTimingTracker {
    pub fn new(can_id: CanId) -> Self {
        Self {
            can_id,
            last_timestamp_us: None,
            frame_count: 0,
            mean_us: 0.0,
            m2_us: 0.0,
            bin_10ms: 0,
            bin_20ms: 0,
            bin_50ms: 0,
            bin_100ms: 0,
            bin_250ms: 0,
            bin_1000ms: 0,
            bin_other: 0,
        }
    }

    /// Update with incoming frame timestamp (in microseconds)
    pub fn update(&mut self, timestamp_us: u64) {
        self.frame_count += 1;

        if let Some(prev) = self.last_timestamp_us {
            if timestamp_us > prev {
                let delta_us = (timestamp_us - prev) as f64;
                let delta_ms = delta_us / 1000.0;

                // Update Welford's running mean and variance
                let count = self.frame_count.saturating_sub(1) as f64;
                let delta = delta_us - self.mean_us;
                self.mean_us += delta / count;
                let delta2 = delta_us - self.mean_us;
                self.m2_us += delta * delta2;

                // Classify into histogram bin
                if (8.0..=12.0).contains(&delta_ms) {
                    self.bin_10ms += 1;
                } else if (17.0..=23.0).contains(&delta_ms) {
                    self.bin_20ms += 1;
                } else if (45.0..=55.0).contains(&delta_ms) {
                    self.bin_50ms += 1;
                } else if (90.0..=110.0).contains(&delta_ms) {
                    self.bin_100ms += 1;
                } else if (230.0..=270.0).contains(&delta_ms) {
                    self.bin_250ms += 1;
                } else if (900.0..=1100.0).contains(&delta_ms) {
                    self.bin_1000ms += 1;
                } else {
                    self.bin_other += 1;
                }
            }
        }

        self.last_timestamp_us = Some(timestamp_us);
    }

    /// Calculate summary statistics and detect periodicity
    pub fn stats(&self) -> Option<PeriodicStats> {
        if self.frame_count < 3 {
            return None;
        }

        let n = (self.frame_count - 1) as f64;
        let variance_us = if n > 1.0 { self.m2_us / (n - 1.0) } else { 0.0 };
        let std_dev_us = variance_us.sqrt();

        let mean_ms = self.mean_us / 1000.0;
        let std_dev_ms = std_dev_us / 1000.0;

        let jitter_ratio = if mean_ms > 0.001 {
            std_dev_ms / mean_ms
        } else {
            1.0
        };

        // SavvyCAN periodicity rule: jitter ratio < 5%
        let is_periodic = jitter_ratio < 0.05 && self.frame_count >= 5;
        let estimated_freq_hz = if mean_ms > 0.001 {
            1000.0 / mean_ms
        } else {
            0.0
        };

        Some(PeriodicStats {
            can_id: self.can_id,
            frame_count: self.frame_count,
            mean_interval_ms: mean_ms,
            std_dev_ms,
            jitter_ratio,
            is_periodic,
            estimated_freq_hz,
        })
    }
}

/// High-level timing engine tracking all arbitration IDs
#[derive(Debug, Clone, Default)]
pub struct TimingHistogramEngine {
    pub trackers: HashMap<CanId, IdTimingTracker>,
}

impl TimingHistogramEngine {
    pub fn new() -> Self {
        Self {
            trackers: HashMap::new(),
        }
    }

    pub fn record_frame(&mut self, can_id: CanId, timestamp_us: u64) {
        let tracker = self
            .trackers
            .entry(can_id)
            .or_insert_with(|| IdTimingTracker::new(can_id));
        tracker.update(timestamp_us);
    }

    pub fn get_periodic_nodes(&self) -> Vec<PeriodicStats> {
        self.trackers
            .values()
            .filter_map(|t| t.stats())
            .filter(|s| s.is_periodic)
            .collect()
    }

    /// Retrieve estimated frequency in Hz and jitter in milliseconds for a CAN ID
    pub fn get_node_timing(&self, can_id: CanId) -> (f32, f32) {
        if let Some(tracker) = self.trackers.get(&can_id) {
            if let Some(stats) = tracker.stats() {
                return (stats.estimated_freq_hz as f32, stats.std_dev_ms as f32);
            }
        }
        (1.0, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_savvycan_periodic_rate_detection() {
        let mut tracker = IdTimingTracker::new(CanId::Standard(0x300));
        // Simulate 20ms periodic transmission with 0.1ms jitter
        let base_interval = 20_000; // 20ms = 20,000 us
        let mut current_time = 1_000_000; // 1 second

        for i in 0..30 {
            let jitter = if i % 2 == 0 { 50 } else { -50 };
            current_time += (base_interval + jitter) as u64;
            tracker.update(current_time);
        }

        let stats = tracker.stats().expect("Stats calculated");
        assert!(stats.is_periodic);
        assert!((stats.mean_interval_ms - 20.0).abs() < 0.5);
        assert!(stats.jitter_ratio < 0.05);
        assert!((stats.estimated_freq_hz - 50.0).abs() < 1.0);
    }
}
