use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::decoder::{
    decode_ascii_string, decode_float32, decode_mod10000, decode_uint32, WordOrder,
};

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

        // 1. Evaluate ASCII Model / Serial String
        if let Some(ascii_str) = decode_ascii_string(&[r0, r1]) {
            if ascii_str.chars().all(|c| c.is_ascii_graphic() || c == ' ') && ascii_str.len() >= 2 {
                candidates.push(PlausibilityCandidate {
                    representation_name: "ASCII String".to_string(),
                    current_value_str: format!("\"{}\"", ascii_str),
                    confidence: 0.95,
                    rationale: "All bytes in 0x20..=0x7E printable ASCII range".to_string(),
                });
            }
        }

        // 2. Evaluate Float32 Word Orders
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

        // 3. Evaluate Monotonic UInt32 Accumulators / Totalizers (ABCD vs CDAB)
        let (u32_abcd_conf, u32_abcd_val) = score_monotonic_uint32(hist, WordOrder::Abcd);
        candidates.push(PlausibilityCandidate {
            representation_name: "UInt32 (ABCD)".to_string(),
            current_value_str: u32_abcd_val.to_string(),
            confidence: u32_abcd_conf,
            rationale: if u32_abcd_conf >= 0.90 {
                "Monotonically increasing accumulator (Delta >= 0)".to_string()
            } else {
                "Unsigned 32-bit counter or accumulator".to_string()
            },
        });

        let (u32_cdab_conf, u32_cdab_val) = score_monotonic_uint32(hist, WordOrder::Cdab);
        candidates.push(PlausibilityCandidate {
            representation_name: "UInt32 (CDAB)".to_string(),
            current_value_str: u32_cdab_val.to_string(),
            confidence: u32_cdab_conf,
            rationale: if u32_cdab_conf >= 0.90 {
                "Monotonically increasing word-swapped accumulator (Delta >= 0)".to_string()
            } else {
                "Unsigned 32-bit word-swapped counter".to_string()
            },
        });

        // 4. Evaluate Mod10000 Energy / Flow Totalizers
        let mod10k_val = decode_mod10000(r0, r1);
        if r0 < 10000 {
            let mod10k_conf = if hist.samples.len() >= 2 {
                let prev = hist.samples[hist.samples.len() - 2];
                let prev_total = decode_mod10000(prev.0, prev.1);
                if mod10k_val >= prev_total && mod10k_val - prev_total <= 50000 {
                    0.92
                } else {
                    0.75
                }
            } else {
                0.75
            };
            candidates.push(PlausibilityCandidate {
                representation_name: "Mod10000 Totalizer".to_string(),
                current_value_str: mod10k_val.to_string(),
                confidence: mod10k_conf,
                rationale: "Modulo-10,000 register pair standard in energy/flow meters".to_string(),
            });
        }

        // 5. Evaluate Fixed-Point Scaled Integers on r0
        if let Some((name, val_str, conf, rat)) = score_fixed_point_integer(r0) {
            candidates.push(PlausibilityCandidate {
                representation_name: name,
                current_value_str: val_str,
                confidence: conf,
                rationale: rat,
            });
        }

        // 6. Evaluate Standard 16-bit integers on r0
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
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates
    }
}

/// Score UInt32 sequence for monotonic increments typical of flow/energy/hour counters
fn score_monotonic_uint32(hist: &SampleHistory, order: WordOrder) -> (f32, u32) {
    let current_pair = hist.samples.last().copied().unwrap_or((0, 0));
    let current_val = decode_uint32(current_pair.0, current_pair.1, order);

    if hist.samples.len() < 2 {
        return (0.50, current_val);
    }

    let mut is_monotonic = true;
    let mut prev_val = decode_uint32(hist.samples[0].0, hist.samples[0].1, order);

    for s in &hist.samples[1..] {
        let val = decode_uint32(s.0, s.1, order);
        if val >= prev_val && (val - prev_val) <= 50_000 {
            // Valid monotonic delta
            prev_val = val;
        } else {
            is_monotonic = false;
            break;
        }
    }

    if is_monotonic && current_val > 0 {
        (0.95, current_val)
    } else {
        (0.50, current_val)
    }
}

/// Evaluate 16-bit integer for fixed-point industrial ranges (mains voltage, grid frequency, temperature)
fn score_fixed_point_integer(r0: u16) -> Option<(String, String, f32, String)> {
    // 1. Grid Frequency: 4950..=5050 (50.00 Hz) or 5950..=6050 (60.00 Hz) with scale = 0.01
    if (4950..=5050).contains(&r0) {
        let freq = (r0 as f32) * 0.01;
        return Some((
            "Fixed-Point (Grid Frequency 50Hz)".to_string(),
            format!("{:.2} Hz", freq),
            0.95,
            format!("16-bit scaled by 0.01 matching 50 Hz grid frequency ({:.2} Hz)", freq),
        ));
    }
    if (5950..=6050).contains(&r0) {
        let freq = (r0 as f32) * 0.01;
        return Some((
            "Fixed-Point (Grid Frequency 60Hz)".to_string(),
            format!("{:.2} Hz", freq),
            0.95,
            format!("16-bit scaled by 0.01 matching 60 Hz grid frequency ({:.2} Hz)", freq),
        ));
    }

    // 2. Mains / Line Voltage: 1900..=2600 (scale 0.1 = 190.0V..260.0V) or 24V supply (scale 0.01 = 24.00V)
    if (1900..=2600).contains(&r0) {
        let volts = (r0 as f32) * 0.1;
        return Some((
            "Fixed-Point (Line Voltage)".to_string(),
            format!("{:.1} V", volts),
            0.92,
            format!("16-bit scaled by 0.1 matching nominal 230V mains ({:.1} V)", volts),
        ));
    }

    // 3. Signed temperature: e.g. -400..=1250 as i16 (scale 0.1 = -40.0°C .. +125.0°C)
    let s0 = r0 as i16;
    if (-400..=1250).contains(&s0) && s0 != 0 {
        let temp = (s0 as f32) * 0.1;
        return Some((
            "Fixed-Point (Temperature x0.1)".to_string(),
            format!("{:.1} °C", temp),
            0.82,
            format!("16-bit signed integer scaled by 0.1 within industrial temp range ({:.1} °C)", temp),
        ));
    }

    None
}

/// Score Float32 sequence for non-finiteness, astronomical exponents, and temporal stability
fn score_float_sequence(hist: &SampleHistory, order: WordOrder, current: f32) -> (f32, String) {
    if !current.is_finite() {
        return (0.0, "Invalid IEEE 754 value (NaN or Inf)".to_string());
    }

    let abs_val = current.abs();

    if abs_val > 0.0 && !(1e-12..=1e12).contains(&abs_val) {
        return (
            0.01,
            format!("Astronomical magnitude ({:.2e}) typical of misaligned bytes", current),
        );
    }

    let is_typical_sensor_range = (0.01..=100_000.0).contains(&abs_val);

    if hist.samples.len() < 2 {
        let base_score = if is_typical_sensor_range { 0.70 } else { 0.30 };
        return (base_score, "Single sample within sensor range".to_string());
    }

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
        (
            0.95,
            format!("High temporal stability (avg delta {:.3}) in sensor range", avg_delta),
        )
    } else if max_delta < 50.0 && is_typical_sensor_range {
        (
            0.85,
            format!("Smoothly varying physical value (avg delta {:.2})", avg_delta),
        )
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

    #[test]
    fn test_plausibility_scores_monotonic_accumulator() {
        let mut scorer = PlausibilityScorer::new();

        // Simulate 4 samples of monotonically increasing kWh totalizer
        let samples = [
            (0x0001, 0x0000), // 65536
            (0x0001, 0x000A), // 65546 (+10)
            (0x0001, 0x0014), // 65556 (+10)
        ];

        let mut ranked = Vec::new();
        for s in samples {
            ranked = scorer.evaluate_pair("1", 40100, s.0, s.1);
        }

        let accumulator = ranked
            .iter()
            .find(|c| c.representation_name == "UInt32 (ABCD)")
            .expect("UInt32 candidate present");
        assert_eq!(accumulator.confidence, 0.95);
    }

    #[test]
    fn test_plausibility_scores_ascii_serial_string() {
        let mut scorer = PlausibilityScorer::new();
        // "INV1" -> 'I'=0x49, 'N'=0x4E, 'V'=0x56, '1'=0x31
        let r0 = 0x494E;
        let r1 = 0x5631;

        let ranked = scorer.evaluate_pair("1", 40050, r0, r1);
        let ascii_cand = ranked
            .iter()
            .find(|c| c.representation_name == "ASCII String")
            .expect("ASCII candidate found");
        assert_eq!(ascii_cand.confidence, 0.95);
        assert_eq!(ascii_cand.current_value_str, "\"INV1\"");
    }

    #[test]
    fn test_plausibility_scores_fixed_point_grid_frequency() {
        let mut scorer = PlausibilityScorer::new();
        // 5002 in register => 50.02 Hz
        let ranked = scorer.evaluate_pair("1", 40020, 5002, 0);
        let freq_cand = ranked
            .iter()
            .find(|c| c.representation_name.contains("Grid Frequency"))
            .expect("Grid frequency candidate found");
        assert_eq!(freq_cand.confidence, 0.95);
        assert_eq!(freq_cand.current_value_str, "50.02 Hz");
    }
}
