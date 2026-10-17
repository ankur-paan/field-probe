use serde::{Deserialize, Serialize};

use crate::crc::{
    bacnet_crc8, modbus_ascii_lrc, verify_dnp3_crc16, verify_modbus_rtu_crc16,
};

/// Candidate serial protocol detected on the bus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SerialProtocolCandidate {
    ModbusRtu,
    ModbusAscii,
    BacnetMstp,
    Dnp3,
    Unknown,
}

/// Standard baud rates evaluated during auto-detection scan
pub const CANDIDATE_BAUD_RATES: [u32; 8] = [
    9600, 19200, 38400, 57600, 115200, 230400, 4800, 2400,
];

/// Serial timing tolerances (t1.5 and t3.5) in microseconds
/// (Timing parameters based on Modbus standard specifications and field serial analysis)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialSilenceIntervals {
    /// Inter-character timeout t1.5 in microseconds
    pub t1_5_us: u64,
    /// Inter-frame silence t3.5 in microseconds
    pub t3_5_us: u64,
}

/// Calculate exact t1.5 and t3.5 silence intervals for a given baud rate.
/// For baud rates > 19200 bps, uses fixed standard constants (750 us and 1750 us).
pub fn calculate_silence_intervals(baud_rate: u32) -> SerialSilenceIntervals {
    if baud_rate > 19200 {
        SerialSilenceIntervals {
            t1_5_us: 750,
            t3_5_us: 1750,
        }
    } else {
        let char_time_us = 11_000_000.0 / (baud_rate as f64);
        let t1_5 = (1.5 * char_time_us).round() as u64;
        let t3_5 = (3.5 * char_time_us).round() as u64;
        SerialSilenceIntervals {
            t1_5_us: t1_5,
            t3_5_us: t3_5,
        }
    }
}

/// Result of auto-detecting a serial bus stream
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerialDetectionScore {
    pub candidate_protocol: SerialProtocolCandidate,
    pub baud_rate: u32,
    pub confidence: f32,
    pub valid_crc_count: usize,
    pub total_frames_scanned: usize,
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

/// Score a raw serial buffer against candidate protocols
pub fn score_serial_stream(buffer: &[u8], baud_rate: u32) -> SerialDetectionScore {
    let rtu_matches = scan_modbus_rtu_frames(buffer);
    let mstp_matches = scan_bacnet_mstp_frames(buffer);
    let dnp3_matches = scan_dnp3_frames(buffer);

    let (proto, count) = if rtu_matches.len() >= mstp_matches.len() && rtu_matches.len() >= dnp3_matches.len() && !rtu_matches.is_empty() {
        (SerialProtocolCandidate::ModbusRtu, rtu_matches.len())
    } else if mstp_matches.len() > rtu_matches.len() && mstp_matches.len() >= dnp3_matches.len() {
        (SerialProtocolCandidate::BacnetMstp, mstp_matches.len())
    } else if dnp3_matches.len() > rtu_matches.len() {
        (SerialProtocolCandidate::Dnp3, dnp3_matches.len())
    } else {
        (SerialProtocolCandidate::Unknown, 0)
    };

    let confidence = if count > 0 {
        (count as f32 * 0.35).min(1.0)
    } else {
        0.0
    };

    SerialDetectionScore {
        candidate_protocol: proto,
        baud_rate,
        confidence,
        valid_crc_count: count,
        total_frames_scanned: rtu_matches.len() + mstp_matches.len() + dnp3_matches.len(),
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
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A,
            0x01, 0x03, 0x02, 0x00, 0x64, 0xB9, 0xAF,
        ];
        let score = score_serial_stream(&stream, 9600);
        assert_eq!(score.candidate_protocol, SerialProtocolCandidate::ModbusRtu);
        assert_eq!(score.valid_crc_count, 2);
        assert!(score.confidence > 0.5);
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
        fn fuzz_score_serial_stream_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024), baud in 2400u32..230400u32) {
            let _ = score_serial_stream(&data, baud);
        }
    }
}
