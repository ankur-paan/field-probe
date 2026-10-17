use fp_core::TimestampedChunk;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Inferred field semantic category in an unknown binary protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    /// Constant sync or preamble header bytes
    SyncPreamble,
    /// Low-cardinality node address, command ID, or function code
    NodeOrCommandId,
    /// Strictly monotonic sequence or packet counter
    SequenceCounter,
    /// High-entropy or variable telemetry / engineering payload
    TelemetryPayload,
    /// Trailing error-detection block (Checksum, CRC-8, or CRC-16)
    ChecksumOrCrc,
}

impl FieldType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SyncPreamble => "Sync / Preamble",
            Self::NodeOrCommandId => "Node / Command ID",
            Self::SequenceCounter => "Sequence Counter",
            Self::TelemetryPayload => "Telemetry Payload",
            Self::ChecksumOrCrc => "Checksum / CRC",
        }
    }
}

/// Discovered field span within an aligned frame structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferredField {
    pub start_byte: usize,
    pub length: usize,
    pub field_type: FieldType,
    pub entropy: f32,
    pub distinct_values: usize,
    pub description: String,
}

/// Structural hypothesis for an unknown proprietary binary protocol
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameStructureHypothesis {
    pub frame_length: usize,
    pub frame_count: usize,
    pub fields: Vec<InferredField>,
    pub confidence: f32,
    pub sample_preamble: Vec<u8>,
    pub detected_crc_type: Option<String>,
}

/// Reverse-engineering engine for unknown binary protocols
#[derive(Debug, Clone, Default)]
pub struct UnknownFramer {
    pub min_frames_required: usize,
}

impl UnknownFramer {
    pub fn new() -> Self {
        Self {
            min_frames_required: 3,
        }
    }

    /// Cluster a stream of timestamped chunks into candidate frames based on inter-frame silence gaps.
    /// Inter-frame delimiter rule: gap > 3.0 * median_delta.
    pub fn cluster_by_silence(&self, chunks: &[TimestampedChunk]) -> Vec<Vec<u8>> {
        if chunks.is_empty() {
            return Vec::new();
        }

        // Collect all positive inter-frame gaps
        let mut gaps: Vec<u64> = chunks
            .iter()
            .filter_map(|c| c.inter_frame_gap_us)
            .filter(|&g| g > 0)
            .collect();

        let threshold_us = if gaps.len() >= 2 {
            gaps.sort_unstable();
            let median_gap = gaps[gaps.len() / 2];
            (median_gap * 3).max(1500) // Minimum 1.5ms threshold
        } else {
            3500 // Default Modbus-style 3.5-character silence equivalent (~3.5ms at 9600 baud)
        };

        let mut frames = Vec::new();
        let mut current_frame = Vec::new();

        for chunk in chunks {
            if let Some(gap) = chunk.inter_frame_gap_us {
                if gap >= threshold_us && !current_frame.is_empty() {
                    frames.push(std::mem::take(&mut current_frame));
                }
            }
            current_frame.extend_from_slice(&chunk.data);
        }

        if !current_frame.is_empty() {
            frames.push(current_frame);
        }

        frames
    }

    /// Analyze an aligned matrix of frames to reverse-engineer field boundaries and semantics
    pub fn analyze_frame_matrix(&self, raw_frames: &[Vec<u8>]) -> Option<FrameStructureHypothesis> {
        if raw_frames.len() < self.min_frames_required {
            return None;
        }

        // Find modal frame length
        let mut length_counts = HashMap::new();
        for f in raw_frames {
            if f.len() >= 4 {
                *length_counts.entry(f.len()).or_insert(0usize) += 1;
            }
        }

        let (&modal_len, &count) = length_counts.iter().max_by_key(|&(_, count)| count)?;

        if count < self.min_frames_required {
            return None;
        }

        // Filter to all frames matching the modal length
        let matrix: Vec<&[u8]> = raw_frames
            .iter()
            .filter(|f| f.len() == modal_len)
            .map(|f| f.as_slice())
            .collect();

        let num_frames = matrix.len();
        let frame_len = modal_len;

        // Columnar statistical inspection
        let mut col_distinct = Vec::with_capacity(frame_len);
        let mut col_entropy = Vec::with_capacity(frame_len);
        let mut col_is_seq = Vec::with_capacity(frame_len);
        let mut col_is_const = Vec::with_capacity(frame_len);

        for c in 0..frame_len {
            let mut counts = [0usize; 256];
            for row in &matrix {
                counts[row[c] as usize] += 1;
            }

            let distinct = counts.iter().filter(|&&cnt| cnt > 0).count();
            let mut entropy = 0.0f32;
            let total = num_frames as f32;
            for &cnt in &counts {
                if cnt > 0 {
                    let p = cnt as f32 / total;
                    entropy -= p * p.log2();
                }
            }

            // Check if column exhibits strictly monotonic sequential increment modulo 256
            let mut is_seq = true;
            for r in 1..num_frames {
                let prev = matrix[r - 1][c];
                let curr = matrix[r][c];
                if curr != prev.wrapping_add(1) {
                    is_seq = false;
                    break;
                }
            }

            // Check if column is constant (or >= 95% constant)
            let max_count = counts.iter().copied().max().unwrap_or(0);
            let is_const = (max_count as f32 / total) >= 0.95;

            col_distinct.push(distinct);
            col_entropy.push(entropy);
            col_is_seq.push(is_seq);
            col_is_const.push(is_const);
        }

        // Test trailing checksum / CRC hypotheses across all frames
        let detected_crc = detect_trailing_checksum(&matrix);

        // Track preamble length (continuous constant prefix)
        let mut preamble_len = 0;
        while preamble_len < frame_len && col_is_const[preamble_len] {
            preamble_len += 1;
        }

        // Assign field type per column
        let mut col_types = Vec::with_capacity(frame_len);

        for c in 0..frame_len {
            if c < preamble_len {
                col_types.push(FieldType::SyncPreamble);
            } else {
                // Check trailing checksums / CRCs
                if let Some(ref crc_info) = detected_crc {
                    if (c >= frame_len - 1 && crc_info.width == 1)
                        || (c >= frame_len - 2 && crc_info.width == 2)
                    {
                        col_types.push(FieldType::ChecksumOrCrc);
                        continue;
                    }
                }

                if col_is_seq[c] {
                    col_types.push(FieldType::SequenceCounter);
                } else if c < preamble_len + 2
                    && col_distinct[c] <= 8
                    && (col_distinct[c] as f32 / num_frames as f32) <= 0.6
                {
                    col_types.push(FieldType::NodeOrCommandId);
                } else if c >= frame_len - 2 && col_entropy[c] >= 2.0 {
                    col_types.push(FieldType::ChecksumOrCrc);
                } else {
                    col_types.push(FieldType::TelemetryPayload);
                }
            }
        }

        // Group adjacent columns of the same field type into composite fields
        let mut fields: Vec<InferredField> = Vec::new();
        let mut curr_start = 0;

        while curr_start < frame_len {
            let curr_type = col_types[curr_start];
            let mut end = curr_start + 1;
            while end < frame_len && col_types[end] == curr_type {
                end += 1;
            }

            let len = end - curr_start;
            let avg_entropy: f32 = col_entropy[curr_start..end].iter().sum::<f32>() / (len as f32);
            let max_distinct = col_distinct[curr_start..end]
                .iter()
                .copied()
                .max()
                .unwrap_or(1);

            let description = match curr_type {
                FieldType::SyncPreamble => {
                    let hex_bytes: Vec<String> = matrix[0][curr_start..end]
                        .iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect();
                    format!("Preamble / Magic ({})", hex_bytes.join(" "))
                }
                FieldType::NodeOrCommandId => {
                    format!("Address / Command Code ({} distinct values)", max_distinct)
                }
                FieldType::SequenceCounter => {
                    "Monotonic Rolling Counter (b_n = b_{n-1} + 1 mod 256)".to_string()
                }
                FieldType::TelemetryPayload => {
                    format!(
                        "Variable Payload ({} bytes, H={:.2} bits/byte)",
                        len, avg_entropy
                    )
                }
                FieldType::ChecksumOrCrc => {
                    if let Some(ref crc) = detected_crc {
                        format!("Verified {} ({}-bit)", crc.name, crc.width * 8)
                    } else {
                        format!("Trailing Error Check ({}-bit)", len * 8)
                    }
                }
            };

            fields.push(InferredField {
                start_byte: curr_start,
                length: len,
                field_type: curr_type,
                entropy: avg_entropy,
                distinct_values: max_distinct,
                description,
            });

            curr_start = end;
        }

        // Compute overall hypothesis confidence
        let mut confidence = 0.5f32;
        if fields
            .iter()
            .any(|f| f.field_type == FieldType::SyncPreamble)
        {
            confidence += 0.20;
        }
        if fields
            .iter()
            .any(|f| f.field_type == FieldType::SequenceCounter)
        {
            confidence += 0.15;
        }
        if detected_crc.is_some() {
            confidence += 0.15;
        }

        let sample_preamble = if let Some(preamble_field) = fields
            .first()
            .filter(|f| f.field_type == FieldType::SyncPreamble)
        {
            matrix[0][0..preamble_field.length].to_vec()
        } else {
            Vec::new()
        };

        Some(FrameStructureHypothesis {
            frame_length: frame_len,
            frame_count: num_frames,
            fields,
            confidence: confidence.min(1.0),
            sample_preamble,
            detected_crc_type: detected_crc.map(|c| c.name),
        })
    }

    /// Full pipeline: Cluster incoming chunks by silence and infer the frame layout
    pub fn reverse_engineer_stream(
        &self,
        chunks: &[TimestampedChunk],
    ) -> Option<FrameStructureHypothesis> {
        let frames = self.cluster_by_silence(chunks);
        self.analyze_frame_matrix(&frames)
    }

    /// Reverse-engineer repeating fixed-size frames directly from a raw contiguous byte buffer
    /// by scanning candidate frame lengths (4..=64).
    pub fn infer_from_raw_stream(&self, buffer: &[u8]) -> Option<FrameStructureHypothesis> {
        if buffer.len() < 12 {
            return None;
        }

        let mut best_hypothesis: Option<FrameStructureHypothesis> = None;
        let mut best_conf = 0.0f32;

        let max_len = 64.min(buffer.len() / self.min_frames_required);
        for candidate_len in 4..=max_len {
            let num_frames = buffer.len() / candidate_len;
            if num_frames < self.min_frames_required {
                continue;
            }

            let frames: Vec<Vec<u8>> = (0..num_frames)
                .map(|i| buffer[i * candidate_len..(i + 1) * candidate_len].to_vec())
                .collect();

            if let Some(hyp) = self.analyze_frame_matrix(&frames) {
                if hyp.confidence > best_conf {
                    best_conf = hyp.confidence;
                    best_hypothesis = Some(hyp);
                }
            }
        }

        best_hypothesis
    }
}

struct CrcMatchResult {
    name: String,
    width: usize, // in bytes (1 or 2)
}

/// Probe trailing bytes against 8 common industrial checksum and CRC algorithms
fn detect_trailing_checksum(matrix: &[&[u8]]) -> Option<CrcMatchResult> {
    if matrix.is_empty() || matrix[0].len() < 4 {
        return None;
    }
    let len = matrix[0].len();

    // 1. 8-bit Additive Sum (sum of 0..len-1 % 256 == last byte)
    let sum_matched = matrix.iter().all(|row| {
        let sum: u8 = row[..len - 1]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == row[len - 1]
    });
    if sum_matched {
        return Some(CrcMatchResult {
            name: "Additive Checksum-8".to_string(),
            width: 1,
        });
    }

    // 2. 8-bit Two's Complement LRC (Modbus ASCII style: (!sum) + 1 == last byte)
    let lrc_twos_matched = matrix
        .iter()
        .all(|row| crate::crc::modbus_ascii_lrc(&row[..len - 1]) == row[len - 1]);
    if lrc_twos_matched {
        return Some(CrcMatchResult {
            name: "Two's Complement LRC-8".to_string(),
            width: 1,
        });
    }

    // 3. 8-bit XOR Checksum (XOR of 0..len-1 == last byte)
    let xor_matched = matrix.iter().all(|row| {
        let xor: u8 = row[..len - 1].iter().fold(0u8, |acc, &b| acc ^ b);
        xor == row[len - 1]
    });
    if xor_matched {
        return Some(CrcMatchResult {
            name: "XOR Checksum-8 (LRC)".to_string(),
            width: 1,
        });
    }

    // 4. BACnet MS/TP CRC-8 (polynomial 0x11D reflected 0x8C)
    let bacnet_crc8_matched = matrix
        .iter()
        .all(|row| crate::crc::bacnet_crc8(&row[..len - 1]) == row[len - 1]);
    if bacnet_crc8_matched {
        return Some(CrcMatchResult {
            name: "CRC-8/BACnet (0x8C)".to_string(),
            width: 1,
        });
    }

    // 5. Modbus RTU CRC-16 (reflected 0xA001, Little-Endian trailer)
    let modbus_crc_matched = matrix
        .iter()
        .all(|row| crate::crc::verify_modbus_rtu_crc16(row));
    if modbus_crc_matched {
        return Some(CrcMatchResult {
            name: "CRC-16/Modbus (0xA001)".to_string(),
            width: 2,
        });
    }

    // 6. DNP3 CRC-16 (IEEE 1815 reflected 0xA6BC, Little-Endian trailer)
    let dnp3_crc_matched = matrix.iter().all(|row| crate::crc::verify_dnp3_crc16(row));
    if dnp3_crc_matched {
        return Some(CrcMatchResult {
            name: "CRC-16/DNP3 (0xA6BC LE)".to_string(),
            width: 2,
        });
    }

    // 7. CCITT CRC-16 Big-Endian (polynomial 0x1021, init 0xFFFF)
    let ccitt_be_matched = matrix.iter().all(|row| {
        let expected = compute_crc16_ccitt(&row[..len - 2]);
        let actual = u16::from_be_bytes([row[len - 2], row[len - 1]]);
        expected == actual
    });
    if ccitt_be_matched {
        return Some(CrcMatchResult {
            name: "CRC-16/CCITT (0x1021)".to_string(),
            width: 2,
        });
    }

    // 8. CCITT CRC-16 Little-Endian (polynomial 0x1021, init 0xFFFF)
    let ccitt_le_matched = matrix.iter().all(|row| {
        let expected = compute_crc16_ccitt(&row[..len - 2]);
        let actual = u16::from_le_bytes([row[len - 2], row[len - 1]]);
        expected == actual
    });
    if ccitt_le_matched {
        return Some(CrcMatchResult {
            name: "CRC-16/CCITT (0x1021 LE)".to_string(),
            width: 2,
        });
    }

    None
}

/// Compute standard CRC-16/CCITT (polynomial 0x1021, init 0xFFFF)
pub fn compute_crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_framer_reverse_engineers_proprietary_protocol() {
        let framer = UnknownFramer::new();

        // Synthetic proprietary protocol:
        // Byte 0-1: Constant Sync [0xAA, 0x55]
        // Byte 2: Node Address (0x01 or 0x02)
        // Byte 3: Sequence Counter (0, 1, 2, 3...)
        // Byte 4-5: Telemetry data (e.g. pressure sensor)
        // Byte 6-7: Modbus-style CRC-16 (computed over bytes 0..6)
        let mut frames = Vec::new();

        for i in 0..8u8 {
            let node = if i % 2 == 0 { 0x01 } else { 0x02 };
            let seq = i;
            let val = (1000 + (i as u16) * 25).to_be_bytes();

            let mut frame_data = vec![0xAA, 0x55, node, seq, val[0], val[1]];
            let crc = crate::crc::modbus_rtu_crc16(&frame_data);
            frame_data.extend_from_slice(&crc.to_le_bytes()); // Little-endian Modbus CRC

            frames.push(frame_data);
        }

        let hypothesis = framer
            .analyze_frame_matrix(&frames)
            .expect("Inferred hypothesis");

        assert_eq!(hypothesis.frame_length, 8);
        assert_eq!(hypothesis.frame_count, 8);
        assert_eq!(hypothesis.sample_preamble, vec![0xAA, 0x55]);
        assert_eq!(
            hypothesis.detected_crc_type,
            Some("CRC-16/Modbus (0xA001)".to_string())
        );
        assert!(hypothesis.confidence >= 0.95);

        // Verify discovered fields:
        // 0: SyncPreamble (length 2)
        assert_eq!(hypothesis.fields[0].field_type, FieldType::SyncPreamble);
        assert_eq!(hypothesis.fields[0].length, 2);

        // 1: NodeOrCommandId (length 1)
        assert_eq!(hypothesis.fields[1].field_type, FieldType::NodeOrCommandId);
        assert_eq!(hypothesis.fields[1].length, 1);

        // 2: SequenceCounter (length 1)
        assert_eq!(hypothesis.fields[2].field_type, FieldType::SequenceCounter);
        assert_eq!(hypothesis.fields[2].length, 1);

        // 3: TelemetryPayload (length 2)
        assert_eq!(hypothesis.fields[3].field_type, FieldType::TelemetryPayload);
        assert_eq!(hypothesis.fields[3].length, 2);

        // 4: ChecksumOrCrc (length 2)
        assert_eq!(hypothesis.fields[4].field_type, FieldType::ChecksumOrCrc);
        assert_eq!(hypothesis.fields[4].length, 2);
    }

    #[test]
    fn test_unknown_framer_clustering_by_silence() {
        let framer = UnknownFramer::new();

        // 3 frames separated by 5000us (>3x median gap)
        let chunk1 = TimestampedChunk::new(vec![0xAA, 0x55, 0x01, 0x02], Some(100));
        let chunk2 = TimestampedChunk::new(vec![0x03, 0x04], Some(100));
        // End of frame 1 -> 5000us gap
        let chunk3 = TimestampedChunk::new(vec![0xAA, 0x55, 0x01, 0x03], Some(5000));
        let chunk4 = TimestampedChunk::new(vec![0x05, 0x06], Some(100));

        let frames = framer.cluster_by_silence(&[chunk1, chunk2, chunk3, chunk4]);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], vec![0xAA, 0x55, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(frames[1], vec![0xAA, 0x55, 0x01, 0x03, 0x05, 0x06]);
    }

    #[test]
    fn test_unknown_framer_detects_all_checksum_types() {
        // 1. Two's Complement LRC-8
        let mut lrc_frames = Vec::new();
        for i in 0..4u8 {
            let mut f = vec![0x3A, 0x01, 0x03, i, 0x10];
            let lrc = crate::crc::modbus_ascii_lrc(&f);
            f.push(lrc);
            lrc_frames.push(f);
        }
        let refs: Vec<&[u8]> = lrc_frames.iter().map(|v| v.as_slice()).collect();
        let res = detect_trailing_checksum(&refs).unwrap();
        assert_eq!(res.name, "Two's Complement LRC-8");
        assert_eq!(res.width, 1);

        // 2. BACnet CRC-8
        let mut bacnet_frames = Vec::new();
        for i in 0..4u8 {
            let mut f = vec![0x55, 0xFF, 0x01, i];
            let crc = crate::crc::bacnet_crc8(&f);
            f.push(crc);
            bacnet_frames.push(f);
        }
        let refs: Vec<&[u8]> = bacnet_frames.iter().map(|v| v.as_slice()).collect();
        let res = detect_trailing_checksum(&refs).unwrap();
        assert_eq!(res.name, "CRC-8/BACnet (0x8C)");
        assert_eq!(res.width, 1);

        // 3. DNP3 CRC-16
        let mut dnp3_frames = Vec::new();
        for i in 0..4u8 {
            let mut f = vec![0x05, 0x64, 0x05, i];
            let crc = crate::crc::dnp3_crc16(&f);
            f.extend_from_slice(&crc.to_le_bytes());
            dnp3_frames.push(f);
        }
        let refs: Vec<&[u8]> = dnp3_frames.iter().map(|v| v.as_slice()).collect();
        let res = detect_trailing_checksum(&refs).unwrap();
        assert_eq!(res.name, "CRC-16/DNP3 (0xA6BC LE)");
        assert_eq!(res.width, 2);

        // 4. CCITT CRC-16 Little-Endian
        let mut ccitt_le_frames = Vec::new();
        for i in 0..4u8 {
            let mut f = vec![0x12, 0x34, 0x56, i];
            let crc = compute_crc16_ccitt(&f);
            f.extend_from_slice(&crc.to_le_bytes());
            ccitt_le_frames.push(f);
        }
        let refs: Vec<&[u8]> = ccitt_le_frames.iter().map(|v| v.as_slice()).collect();
        let res = detect_trailing_checksum(&refs).unwrap();
        assert_eq!(res.name, "CRC-16/CCITT (0x1021 LE)");
        assert_eq!(res.width, 2);
    }
}
