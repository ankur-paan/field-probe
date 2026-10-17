use serde::{Deserialize, Serialize};

use crate::crc::{bacnet_crc8, modbus_ascii_lrc, verify_dnp3_crc16, verify_modbus_rtu_crc16};

/// Candidate serial protocol detected on the bus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SerialProtocolCandidate {
    ModbusRtu,
    ModbusAscii,
    BacnetMstp,
    Dnp3,
    ProfibusDp,
    Hart,
    Unknown,
}

/// Standard baud rates evaluated during auto-detection scan
pub const CANDIDATE_BAUD_RATES: [u32; 8] = [9600, 19200, 38400, 57600, 115200, 230400, 4800, 2400];

pub use fp_core::params::{calculate_silence_intervals, SerialSilenceIntervals};

/// Result of auto-detecting a serial bus stream
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerialDetectionScore {
    pub candidate_protocol: SerialProtocolCandidate,
    pub baud_rate: u32,
    pub confidence: f32,
    pub valid_crc_count: usize,
    pub total_frames_scanned: usize,
    pub unknown_hypothesis: Option<crate::unknown_framer::FrameStructureHypothesis>,
}

/// Sliding window CRC-16 scanner across raw byte buffers with byte-level resynchronization
pub fn scan_modbus_rtu_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 4 {
        return detected;
    }

    let mut start = 0;
    while start + 4 <= buffer.len() {
        let slave = buffer[start];
        let fc = buffer[start + 1];

        // Valid Modbus Slave address: 1..=247 (or 0 for broadcast)
        if slave > 247 {
            start += 1;
            continue;
        }

        // Exception response: exactly 5 bytes (slave, fc | 0x80, exception_code, crc_l, crc_h)
        if (fc & 0x80) != 0
            && start + 5 <= buffer.len()
            && verify_modbus_rtu_crc16(&buffer[start..start + 5])
        {
            detected.push((start, 5));
            start += 5;
            continue;
        }

        let mut matched = false;
        let candidate_lens = smallvec_inline_candidates(buffer, start);

        for len in candidate_lens {
            let slice = &buffer[start..start + len];
            if verify_modbus_rtu_crc16(slice) {
                detected.push((start, len));
                start += len;
                matched = true;
                break;
            }
        }

        if !matched {
            start += 1;
        }
    }
    detected
}

fn smallvec_inline_candidates(buffer: &[u8], start: usize) -> Vec<usize> {
    let mut lens = Vec::with_capacity(3);

    // Standard fixed 8-byte queries and single register writes
    if start + 8 <= buffer.len() {
        lens.push(8);
    }

    // Read response candidate: byte_count at start + 2
    if start + 3 <= buffer.len() {
        let byte_count = buffer[start + 2] as usize;
        let resp_len = 5 + byte_count;
        if (5..=256).contains(&resp_len) && resp_len != 8 && start + resp_len <= buffer.len() {
            lens.push(resp_len);
        }
    }

    // Write multiple query candidate: byte_count at start + 6
    if start + 7 <= buffer.len() {
        let byte_count = buffer[start + 6] as usize;
        let write_len = 9 + byte_count;
        if (9..=256).contains(&write_len) && write_len != 8 && start + write_len <= buffer.len() {
            lens.push(write_len);
        }
    }

    lens
}

/// Sliding window scanner for Modbus ASCII frames (starts with ':', ends with "\r\n", validates LRC)
pub fn scan_modbus_ascii_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 5 {
        return detected;
    }

    let mut i = 0;
    while i < buffer.len() {
        if buffer[i] == b':' {
            // Find closing CRLF
            if let Some(end_offset) = buffer[i..].windows(2).position(|w| w == b"\r\n") {
                let frame_len = end_offset + 2;
                let frame = &buffer[i..i + frame_len];
                // ASCII frame payload (between ':' and CRLF) is hex characters
                let hex_slice = &frame[1..frame_len - 2];
                if hex_slice.len() >= 2 && hex_slice.len().is_multiple_of(2) {
                    // Try to decode hex and verify LRC
                    if let Ok(raw_bytes) = hex::decode(hex_slice) {
                        if raw_bytes.len() >= 2 {
                            let data_slice = &raw_bytes[..raw_bytes.len() - 1];
                            let expected_lrc = raw_bytes[raw_bytes.len() - 1];
                            if modbus_ascii_lrc(data_slice) == expected_lrc {
                                detected.push((i, frame_len));
                                i += frame_len;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    detected
}

/// Sliding window scanner for BACnet MS/TP headers (Preamble 0x55 0xFF, validates Header CRC-8)
pub fn scan_bacnet_mstp_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 8 {
        return detected;
    }

    let mut i = 0;
    while i + 8 <= buffer.len() {
        if buffer[i] == 0x55 && buffer[i + 1] == 0xFF {
            let header_crc = buffer[i + 7];
            if bacnet_crc8(&buffer[i + 2..i + 7]) == header_crc {
                let data_len = u16::from_be_bytes([buffer[i + 5], buffer[i + 6]]) as usize;
                let total_frame_len = if data_len > 0 { 8 + data_len + 2 } else { 8 };
                if i + total_frame_len <= buffer.len() {
                    detected.push((i, total_frame_len));
                    i += total_frame_len;
                    continue;
                }
            }
        }
        i += 1;
    }
    detected
}

/// Sliding window scanner for DNP3 headers (Preamble 0x05 0x64, validates DNP3 CRC-16)
pub fn scan_dnp3_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 10 {
        return detected;
    }

    let mut i = 0;
    while i + 10 <= buffer.len() {
        if buffer[i] == 0x05 && buffer[i + 1] == 0x64 && verify_dnp3_crc16(&buffer[i..i + 10]) {
            let len = buffer[i + 2] as usize; // length of user data + 5
            let total_len = (10 + len).min(292);
            detected.push((i, total_len.min(buffer.len() - i)));
            i += 10;
            continue;
        }
        i += 1;
    }
    detected
}

/// Sliding window scanner for PROFIBUS DP frames (SD1, SD2, SD3)
pub fn scan_profibus_dp_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 6 {
        return detected;
    }

    let mut i = 0;
    while i + 6 <= buffer.len() {
        let b0 = buffer[i];

        // SD1: Short Frame / Poll (6 bytes): [0x10, DA, SA, FC, FCS, 0x16]
        if b0 == 0x10 && buffer[i + 5] == 0x16 {
            let fcs =
                ((buffer[i + 1] as u32 + buffer[i + 2] as u32 + buffer[i + 3] as u32) % 256) as u8;
            if buffer[i + 4] == fcs {
                detected.push((i, 6));
                i += 6;
                continue;
            }
        }

        // SD2: Variable Length Data Frame: [0x68, L, L, 0x68, DA, SA, FC, PDU..., FCS, 0x16]
        if b0 == 0x68 && i + 6 <= buffer.len() {
            let l1 = buffer[i + 1];
            let l2 = buffer[i + 2];
            let b3 = buffer[i + 3];

            if l1 == l2 && b3 == 0x68 {
                let l = l1 as usize;
                // Minimum L is 3 (DA, SA, FC), max 246
                if (3..=246).contains(&l) {
                    let total_len = l + 6;
                    if i + total_len <= buffer.len() && buffer[i + total_len - 1] == 0x16 {
                        // FCS = sum(DA..PDU) % 256
                        let sum: u32 = buffer[i + 4..i + 4 + l].iter().map(|&b| b as u32).sum();
                        let fcs = (sum % 256) as u8;
                        if buffer[i + 4 + l] == fcs {
                            detected.push((i, total_len));
                            i += total_len;
                            continue;
                        }
                    }
                }
            }
        }

        // SD3: Fixed 5-byte Data Frame (11 bytes): [0xA2, DA, SA, FC, D1..D5, FCS, 0x16]
        if b0 == 0xA2 && i + 11 <= buffer.len() && buffer[i + 10] == 0x16 {
            let sum: u32 = buffer[i + 1..i + 9].iter().map(|&b| b as u32).sum();
            let fcs = (sum % 256) as u8;
            if buffer[i + 9] == fcs {
                detected.push((i, 11));
                i += 11;
                continue;
            }
        }

        i += 1;
    }
    detected
}

/// Sliding window scanner for HART frames (Bell 202 / RS-485 FSK)
pub fn scan_hart_frames(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut detected = Vec::new();
    if buffer.len() < 5 {
        return detected;
    }

    let mut i = 0;
    while i < buffer.len() {
        // Look for preamble of at least 2 consecutive 0xFF bytes
        if buffer[i] == 0xFF && i + 1 < buffer.len() && buffer[i + 1] == 0xFF {
            let preamble_start = i;
            let mut delim_idx = i;
            while delim_idx < buffer.len() && buffer[delim_idx] == 0xFF {
                delim_idx += 1;
            }

            if delim_idx < buffer.len() {
                let delim = buffer[delim_idx];
                // Recognized delimiters:
                // 0x02: Master to Slave (short)
                // 0x82: Master to Slave (long)
                // 0x06: Slave to Master (short)
                // 0x86: Slave to Master (long)
                // 0x01: Burst (short)
                // 0x81: Burst (long)
                let is_valid_delim = matches!(delim, 0x01 | 0x02 | 0x06 | 0x81 | 0x82 | 0x86);
                if is_valid_delim {
                    let addr_len = if (delim & 0x80) != 0 { 5 } else { 1 };
                    let cmd_idx = delim_idx + 1 + addr_len;
                    let byte_count_idx = cmd_idx + 1;

                    if byte_count_idx < buffer.len() {
                        let byte_count = buffer[byte_count_idx] as usize;
                        let body_len = 1 + addr_len + 1 + 1 + byte_count; // from delim to last data byte
                        let total_frame_len = delim_idx - preamble_start + body_len + 1; // + 1 for checksum

                        if delim_idx + body_len < buffer.len() {
                            let expected_lrc = buffer[delim_idx + body_len];
                            // LRC is XOR of all bytes from delimiter through last data byte
                            let lrc = buffer[delim_idx..delim_idx + body_len]
                                .iter()
                                .fold(0u8, |acc, &b| acc ^ b);

                            if lrc == expected_lrc {
                                detected.push((preamble_start, total_frame_len));
                                i = delim_idx + body_len + 1;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    detected
}

/// Score a raw serial buffer against candidate protocols
pub fn score_serial_stream(buffer: &[u8], baud_rate: u32) -> SerialDetectionScore {
    let rtu_matches = scan_modbus_rtu_frames(buffer);
    let ascii_matches = scan_modbus_ascii_frames(buffer);
    let mstp_matches = scan_bacnet_mstp_frames(buffer);
    let dnp3_matches = scan_dnp3_frames(buffer);
    let profibus_matches = scan_profibus_dp_frames(buffer);
    let hart_matches = scan_hart_frames(buffer);

    let candidates = [
        (SerialProtocolCandidate::ModbusRtu, rtu_matches.len()),
        (SerialProtocolCandidate::ModbusAscii, ascii_matches.len()),
        (SerialProtocolCandidate::BacnetMstp, mstp_matches.len()),
        (SerialProtocolCandidate::Dnp3, dnp3_matches.len()),
        (SerialProtocolCandidate::ProfibusDp, profibus_matches.len()),
        (SerialProtocolCandidate::Hart, hart_matches.len()),
    ];

    let mut best_proto = SerialProtocolCandidate::Unknown;
    let mut best_count = 0;

    for (proto, count) in candidates {
        if count > best_count {
            best_count = count;
            best_proto = proto;
        }
    }

    let (confidence, unknown_hypothesis) = if best_count > 0 {
        ((best_count as f32 * 0.35).min(1.0), None)
    } else {
        let framer = crate::unknown_framer::UnknownFramer::new();
        if let Some(hyp) = framer.infer_from_raw_stream(buffer) {
            (hyp.confidence, Some(hyp))
        } else {
            (0.0, None)
        }
    };

    SerialDetectionScore {
        candidate_protocol: best_proto,
        baud_rate,
        confidence,
        valid_crc_count: best_count,
        total_frames_scanned: rtu_matches.len()
            + ascii_matches.len()
            + mstp_matches.len()
            + dnp3_matches.len()
            + profibus_matches.len()
            + hart_matches.len(),
        unknown_hypothesis,
    }
}

// Minimal internal hex decoder helper for Modbus ASCII without external hex crate
mod hex {
    pub fn decode(s: &[u8]) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.chunks(2) {
            let h = from_hex_digit(chunk[0])?;
            let l = from_hex_digit(chunk[1])?;
            out.push((h << 4) | l);
        }
        Ok(out)
    }

    fn from_hex_digit(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_timing_intervals_for_high_baud() {
        let timing = calculate_silence_intervals(115200);
        assert_eq!(timing.t1_5_us, 750);
        assert_eq!(timing.t3_5_us, 1750);

        let timing_38400 = calculate_silence_intervals(38400);
        assert_eq!(timing_38400.t1_5_us, 750);
        assert_eq!(timing_38400.t3_5_us, 1750);
    }

    #[test]
    fn test_timing_intervals_for_calculated_baud() {
        let timing = calculate_silence_intervals(9600);
        assert_eq!(timing.t1_5_us, 1719);
        assert_eq!(timing.t3_5_us, 4010);
    }

    #[test]
    fn test_sliding_window_modbus_resynchronization() {
        let noise_and_frames = vec![
            0xFF, 0x00, 0xAA, // Noise
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A, // Frame 1
            0xDE, 0xAD, 0xBE, 0xEF, // Corrupt Noise
            0x01, 0x03, 0x02, 0x00, 0x64, 0xB9, 0xAF, // Frame 2 (Response)
        ];

        let matches = scan_modbus_rtu_frames(&noise_and_frames);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (3, 8));
        assert_eq!(matches[1], (15, 7));
    }

    #[test]
    fn test_modbus_ascii_scanner() {
        // Modbus ASCII read query: ":010300000001F6\r\n"
        // 0x01 + 0x03 + 0x00 + 0x00 + 0x00 + 0x01 = 0x05 -> LRC = (!0x05) + 1 = 0xFA + 1 = 0xFB
        // ":010300000001FB\r\n"
        let ascii_stream = b"NOISE:010300000001FB\r\nTRAILING";
        let matches = scan_modbus_ascii_frames(ascii_stream);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], (5, 17));
    }

    #[test]
    fn test_score_serial_stream() {
        let stream = vec![
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A, 0x01, 0x03, 0x02, 0x00, 0x64, 0xB9,
            0xAF,
        ];
        let score = score_serial_stream(&stream, 9600);
        assert_eq!(score.candidate_protocol, SerialProtocolCandidate::ModbusRtu);
        assert_eq!(score.valid_crc_count, 2);
        assert!(score.confidence > 0.5);
    }

    #[test]
    fn test_score_serial_stream_modbus_ascii() {
        let stream = b"NOISE:010300000001FB\r\nTRAILING";
        let score = score_serial_stream(stream, 19200);
        assert_eq!(
            score.candidate_protocol,
            SerialProtocolCandidate::ModbusAscii
        );
        assert_eq!(score.valid_crc_count, 1);
        assert!(score.confidence > 0.3);
    }

    #[test]
    fn test_score_serial_stream_unknown_hypothesis() {
        // Unknown proprietary protocol stream with repeating 8-byte frames:
        // [0xAA, 0x55, node, seq, val_hi, val_lo, crc_hi, crc_lo]
        // using CCITT CRC-16 (0x1021)
        let mut stream = Vec::new();
        for i in 0..6u8 {
            let node = if i % 2 == 0 { 0x01 } else { 0x02 };
            let val = (500 + (i as u16) * 10).to_be_bytes();
            let mut frame = vec![0xAA, 0x55, node, i, val[0], val[1]];
            let crc = crate::unknown_framer::compute_crc16_ccitt(&frame);
            frame.extend_from_slice(&crc.to_be_bytes());
            stream.extend_from_slice(&frame);
        }

        let score = score_serial_stream(&stream, 115200);
        assert_eq!(score.candidate_protocol, SerialProtocolCandidate::Unknown);
        assert!(score.unknown_hypothesis.is_some());
        let hyp = score.unknown_hypothesis.unwrap();
        assert_eq!(hyp.frame_length, 8);
        assert_eq!(hyp.sample_preamble, vec![0xAA, 0x55]);
        assert_eq!(
            hyp.detected_crc_type,
            Some("CRC-16/CCITT (0x1021)".to_string())
        );
        assert!(score.confidence > 0.7);
    }

    #[test]
    fn test_scan_profibus_dp_frames() {
        // Embedded PROFIBUS DP SD2 frame in noise:
        // L = 6 (DA=3, SA=1, FC=0x49, PDU=[0x11, 0x22, 0x33])
        // Sum = 3 + 1 + 73 + 17 + 34 + 51 = 179 = 0xB3
        let noise_and_profibus = vec![
            0x00, 0x55, 0xAA, // Noise
            0x68, 0x06, 0x06, 0x68, 0x03, 0x01, 0x49, 0x11, 0x22, 0x33, 0xB3,
            0x16, // SD2 frame (12 bytes)
            0xDE, 0xAD, // Noise
            0x10, 0x02, 0x01, 0x49, 0x4C,
            0x16, // SD1 frame (6 bytes: DA=2, SA=1, FC=0x49, FCS=2+1+73=76=0x4C)
        ];

        let matches = scan_profibus_dp_frames(&noise_and_profibus);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (3, 12));
        assert_eq!(matches[1], (17, 6));

        let score = score_serial_stream(&noise_and_profibus, 19200);
        assert_eq!(
            score.candidate_protocol,
            SerialProtocolCandidate::ProfibusDp
        );
    }

    #[test]
    fn test_scan_hart_frames() {
        // Embedded HART frame in noise:
        // Preamble: [0xFF, 0xFF, 0xFF, 0xFF]
        // Delimiter: 0x02, Addr: 0x80, Cmd: 0x01, ByteCount: 0x00
        // LRC = 0x02 ^ 0x80 ^ 0x01 ^ 0x00 = 0x83
        let noise_and_hart = vec![
            0x00, 0xAA, // Noise
            0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x80, 0x01, 0x00, 0x83, // HART frame (9 bytes)
            0x12, 0x34, // Noise
        ];

        let matches = scan_hart_frames(&noise_and_hart);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], (2, 9));

        let score = score_serial_stream(&noise_and_hart, 1200);
        assert_eq!(score.candidate_protocol, SerialProtocolCandidate::Hart);
    }

    // Property-based fuzz test: random byte slices of any length up to 1024 bytes MUST NEVER PANIC
    proptest! {
        #[test]
        fn fuzz_scan_modbus_rtu_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = scan_modbus_rtu_frames(&data);
        }

        #[test]
        fn fuzz_scan_modbus_ascii_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = scan_modbus_ascii_frames(&data);
        }

        #[test]
        fn fuzz_scan_bacnet_mstp_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = scan_bacnet_mstp_frames(&data);
        }

        #[test]
        fn fuzz_scan_profibus_dp_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = scan_profibus_dp_frames(&data);
        }

        #[test]
        fn fuzz_scan_hart_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = scan_hart_frames(&data);
        }

        #[test]
        fn fuzz_score_serial_stream_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024), baud in 2400u32..230400u32) {
            let _ = score_serial_stream(&data, baud);
        }
    }
}
