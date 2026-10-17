use serde::{Deserialize, Serialize};

/// AUTOSAR End-to-End (E2E) Communication Protection Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum E2eStatus {
    Ok,
    CrcError { expected: u8, got: u8 },
    CounterMismatch { expected: u8, got: u8 },
    Repeated { counter: u8 },
    SequenceLoss { expected: u8, got: u8 },
}

/// Calculate AUTOSAR E2E Profile 1 CRC-8 (Polynomial 0x1D, Init 0xFF, XorOut 0xFF)
pub fn calculate_e2e_p1_crc(data: &[u8], data_id: u16) -> u8 {
    let mut crc = 0xFFu8;

    // Ingest data bytes
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x1D;
            } else {
                crc <<= 1;
            }
        }
    }

    // Ingest 16-bit Data ID (lower byte then upper byte)
    let id_bytes = [(data_id & 0xFF) as u8, ((data_id >> 8) & 0xFF) as u8];
    for &b in &id_bytes {
        crc ^= b;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x1D;
            } else {
                crc <<= 1;
            }
        }
    }

    crc ^ 0xFF
}

/// Validate AUTOSAR E2E Profile 1 frame
pub fn validate_e2e_p1(
    payload: &[u8],
    data_id: u16,
    crc_offset: usize,
    counter_offset: usize,
    last_counter: Option<u8>,
) -> E2eStatus {
    if payload.len() <= crc_offset || payload.len() <= counter_offset {
        return E2eStatus::CrcError {
            expected: 0,
            got: 0,
        };
    }

    let actual_crc = payload[crc_offset];
    let actual_counter = payload[counter_offset] & 0x0F;

    // CRC is calculated over payload excluding the CRC byte itself
    let mut data_for_crc = Vec::with_capacity(payload.len().saturating_sub(1));
    data_for_crc.extend_from_slice(&payload[..crc_offset]);
    if crc_offset + 1 < payload.len() {
        data_for_crc.extend_from_slice(&payload[crc_offset + 1..]);
    }

    let expected_crc = calculate_e2e_p1_crc(&data_for_crc, data_id);
    if actual_crc != expected_crc {
        return E2eStatus::CrcError {
            expected: expected_crc,
            got: actual_crc,
        };
    }

    // Verify counter sequence (0..=14)
    if let Some(prev) = last_counter {
        let expected_counter = (prev + 1) % 15;
        if actual_counter == prev {
            return E2eStatus::Repeated {
                counter: actual_counter,
            };
        } else if actual_counter != expected_counter {
            return E2eStatus::SequenceLoss {
                expected: expected_counter,
                got: actual_counter,
            };
        }
    }

    E2eStatus::Ok
}

/// Calculate AUTOSAR E2E Profile 2 CRC-8 (SAE J1850, Polynomial 0x2F, Init 0xFF, XorOut 0xFF)
pub fn calculate_e2e_p2_crc(data: &[u8], data_id_list: &[u8; 16], counter: u8) -> u8 {
    let mut crc = 0xFFu8;

    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x2F;
            } else {
                crc <<= 1;
            }
        }
    }

    // Ingest Data ID byte corresponding to counter index (counter % 16)
    let id_byte = data_id_list[(counter % 16) as usize];
    crc ^= id_byte;
    for _ in 0..8 {
        if (crc & 0x80) != 0 {
            crc = (crc << 1) ^ 0x2F;
        } else {
            crc <<= 1;
        }
    }

    crc ^ 0xFF
}

/// Validate AUTOSAR E2E Profile 2 frame
pub fn validate_e2e_p2(
    payload: &[u8],
    data_id_list: &[u8; 16],
    crc_offset: usize,
    counter_offset: usize,
    last_counter: Option<u8>,
) -> E2eStatus {
    if payload.len() <= crc_offset || payload.len() <= counter_offset {
        return E2eStatus::CrcError {
            expected: 0,
            got: 0,
        };
    }

    let actual_crc = payload[crc_offset];
    let actual_counter = payload[counter_offset] & 0x0F;

    let mut data_for_crc = Vec::with_capacity(payload.len().saturating_sub(1));
    data_for_crc.extend_from_slice(&payload[..crc_offset]);
    if crc_offset + 1 < payload.len() {
        data_for_crc.extend_from_slice(&payload[crc_offset + 1..]);
    }

    let expected_crc = calculate_e2e_p2_crc(&data_for_crc, data_id_list, actual_counter);
    if actual_crc != expected_crc {
        return E2eStatus::CrcError {
            expected: expected_crc,
            got: actual_crc,
        };
    }

    if let Some(prev) = last_counter {
        let expected_counter = (prev + 1) % 16;
        if actual_counter == prev {
            return E2eStatus::Repeated {
                counter: actual_counter,
            };
        } else if actual_counter != expected_counter {
            return E2eStatus::SequenceLoss {
                expected: expected_counter,
                got: actual_counter,
            };
        }
    }

    E2eStatus::Ok
}

/// Generate a 64-byte notch bitmask suppressing CRC byte and rolling counter bits
/// to eliminate analog/checksum false positives during physical event correlation.
pub fn generate_e2e_notch_mask(
    crc_offset: usize,
    counter_offset: usize,
    is_counter_low_nibble: bool,
) -> [u8; 64] {
    let mut mask = [0u8; 64];

    if crc_offset < 64 {
        mask[crc_offset] = 0xFF; // Suppress all 8 bits of CRC
    }

    if counter_offset < 64 {
        let counter_mask = if is_counter_low_nibble { 0x0F } else { 0xF0 };
        mask[counter_offset] |= counter_mask;
    }

    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_profile1_crc_and_validation() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let data_id = 0x1234;
        let crc = calculate_e2e_p1_crc(&data, data_id);
        assert_ne!(crc, 0);

        // Construct 6-byte frame: [Counter, D1, D2, D3, D4, CRC]
        let mut frame = vec![0x01, 0x01, 0x02, 0x03, 0x04];
        let computed = calculate_e2e_p1_crc(&frame, data_id);
        frame.push(computed);

        // Validate frame: CRC at offset 5, Counter at offset 0
        let status = validate_e2e_p1(&frame, data_id, 5, 0, Some(0));
        assert_eq!(status, E2eStatus::Ok);

        // Sequence loss test: previous counter was 5, expected 6, but got 1
        let seq_loss = validate_e2e_p1(&frame, data_id, 5, 0, Some(5));
        assert_eq!(
            seq_loss,
            E2eStatus::SequenceLoss {
                expected: 6,
                got: 1
            }
        );
    }

    #[test]
    fn test_e2e_profile2_crc_and_validation() {
        let data_id_list = [
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED,
            0xFE, 0x0F,
        ];
        let mut frame = vec![0x03, 0xAA, 0xBB, 0xCC];
        let counter = 3;
        let crc = calculate_e2e_p2_crc(&frame, &data_id_list, counter);
        frame.push(crc);

        let status = validate_e2e_p2(&frame, &data_id_list, 4, 0, Some(2));
        assert_eq!(status, E2eStatus::Ok);
    }

    #[test]
    fn test_e2e_notch_mask_generation() {
        // CRC at byte 0, Counter in low nibble of byte 1
        let mask = generate_e2e_notch_mask(0, 1, true);
        assert_eq!(mask[0], 0xFF);
        assert_eq!(mask[1], 0x0F);
        assert_eq!(mask[2], 0x00);
    }
}
