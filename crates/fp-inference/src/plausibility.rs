use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::decoder::{decode_float32, WordOrder};

/// Rated candidate representation with confidence score
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlausibilityCandidate {
    pub representation_name: String,
    pub current_value_str: String,
    pub confidence: f32,
    pub rationale: String,
}

/// Ring of recent register observations at a specific address
#[derive(Debug, Clone)]
struct SampleHistory {
    samples: Vec<(u16, u16)>, // pairs of adjacent 16-bit registers (r0, r1)
}

impl SampleHistory {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(16),
        }
    }

    fn push(&mut self, pair: (u16, u16)) {
        if self.samples.len() >= 16 {
            self.samples.remove(0);
        }
        self.samples.push(pair);
    }
}

/// Engine that ranks candidate data representations based on physical plausibility and temporal smoothness
#[derive(Debug, Clone, Default)]
pub struct PlausibilityScorer {
    history: HashMap<String, SampleHistory>, // key: "slave_or_node:addr"
}

impl PlausibilityScorer {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
        }
    }

    /// Record a newly observed pair of 16-bit registers [r0, r1] and evaluate plausibility
    pub fn evaluate_pair(
        &mut self,
        node: &str,
        address: u32,
        r0: u16,
        r1: u16,
    ) -> Vec<PlausibilityCandidate> {
        let key = format!("{}:{}", node, address);
        let hist = self.history.entry(key).or_insert_with(SampleHistory::new);
        hist.push((r0, r1));

        let mut candidates = Vec::new();

        // 1. Evaluate Float32 Word Orders
        let orders = [
            (WordOrder::Cdab, "Float32 (CDAB - Modbus standard)"),
            (WordOrder::Abcd, "Float32 (ABCD - Big-Endian)"),
            (WordOrder::Badc, "Float32 (BADC - Mid-Big Endian)"),
            (WordOrder::Dcba, "Float32 (DCBA - Little-Endian)"),
        ];

        for (order, name) in orders {
            let current_val = decode_float32(r0, r1, order);
            let (conf, rationale) = score_float_sequence(hist, order, current_val);
            if conf > 0.05 {
                candidates.push(PlausibilityCandidate {
                    representation_name: name.to_string(),
                    current_value_str: format!("{:.4}", current_val),
                    confidence: conf,
                    rationale,
                });
            }
        }

        // 2. Evaluate UInt32 (ABCD vs CDAB)
        let u32_abcd = ((r0 as u32) << 16) | (r1 as u32);
        let u32_cdab = ((r1 as u32) << 16) | (r0 as u32);
        candidates.push(PlausibilityCandidate {
            representation_name: "UInt32 (ABCD)".to_string(),
            current_value_str: u32_abcd.to_string(),
            confidence: 0.50,
            rationale: "Unsigned 32-bit counter or accumulator".to_string(),
        });
        candidates.push(PlausibilityCandidate {
            representation_name: "UInt32 (CDAB)".to_string(),
            current_value_str: u32_cdab.to_string(),
            confidence: 0.50,
            rationale: "Unsigned 32-bit word-swapped counter".to_string(),
        });

        // 3. Evaluate 16-bit integers on r0
        candidates.push(PlausibilityCandidate {
            representation_name: "UInt16 (r0)".to_string(),
            current_value_str: r0.to_string(),
            confidence: 0.65,
            rationale: "Single 16-bit unsigned register".to_string(),
        });
        candidates.push(PlausibilityCandidate {
            representation_name: "Int16 (r0)".to_string(),
            current_value_str: (r0 as i16).to_string(),
            confidence: 0.60,
            rationale: "Single 16-bit signed register".to_string(),
        });

        // Sort descending by confidence
        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }
}

/// Score Float32 sequence for non-finiteness, astronomical exponents, and temporal stability
fn score_float_sequence(hist: &SampleHistory, order: WordOrder, current: f32) -> (f32, String) {
    // Immediate rejection of non-finite floats
    if !current.is_finite() {
        return (0.0, "Invalid IEEE 754 value (NaN or Inf)".to_string());
    }

    let abs_val = current.abs();

    // Rejection of subnormals and astronomical values typical of misaligned byte encodings
    if abs_val > 0.0 && !(1e-12..=1e12).contains(&abs_val) {
        return (0.01, format!("Astronomical magnitude ({:.2e}) typical of misaligned bytes", current));
    }

    // Typical physical engineering sensor values fall between 0.001 and 100,000 (temp, pressure, flow, rpm, voltage)
    let is_typical_sensor_range = (0.01..=100_000.0).contains(&abs_val);

    if hist.samples.len() < 2 {
        let base_score = if is_typical_sensor_range { 0.70 } else { 0.30 };
        return (base_score, "Single sample within sensor range".to_string());
    }

    // Temporal smoothness evaluation across history
    let mut deltas = Vec::new();
    let mut prev_val = decode_float32(hist.samples[0].0, hist.samples[0].1, order);

    for s in &hist.samples[1..] {
        let val = decode_float32(s.0, s.1, order);
        if !val.is_finite() {
            return (0.0, "Historical sample yielded NaN or Inf".to_string());
        }
        let delta = (val - prev_val).abs();
        deltas.push(delta);
        prev_val = val;
    }

    let max_delta = deltas.iter().copied().fold(0.0f32, f32::max);
    let avg_delta = deltas.iter().sum::<f32>() / (deltas.len() as f32);

    if max_delta < 5.0 && is_typical_sensor_range {
        (0.95, format!("High temporal stability (avg delta {:.3}) in sensor range", avg_delta))
    } else if max_delta < 50.0 && is_typical_sensor_range {
        (0.85, format!("Smoothly varying physical value (avg delta {:.2})", avg_delta))
    } else if is_typical_sensor_range {
        (0.65, "Valid sensor magnitude with fluctuating readings".to_string())
    } else {
        (0.25, "Finite float outside common industrial sensor ranges".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plausibility_scores_smooth_temperature_cdab() {
        let mut scorer = PlausibilityScorer::new();

        // Simulate 4 samples of temperature ~23.4 °C in CDAB representation
        // 23.41 in IEEE 754: 0x41BB47AE => CDAB: r0=0x47AE, r1=0x41BB
        // 23.45 in IEEE 754: 0x41BB999A => CDAB: r0=0x999A, r1=0x41BB
        // 23.48 in IEEE 754: 0x41BBD70A => CDAB: r0=0xD70A, r1=0x41BB
        let samples = [
            (0x47AE, 0x41BB),
            (0x999A, 0x41BB),
            (0xD70A, 0x41BB),
        ];

        let mut ranked = Vec::new();
        for s in samples {
            ranked = scorer.evaluate_pair("1", 40001, s.0, s.1);
        }

        assert!(!ranked.is_empty());
        let top = &ranked[0];
        assert_eq!(top.representation_name, "Float32 (CDAB - Modbus standard)");
        assert!(top.confidence >= 0.90);
        assert!((top.current_value_str.parse::<f32>().unwrap() - 23.48).abs() < 0.05);
    }
}
