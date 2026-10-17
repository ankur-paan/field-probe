use serde::{Deserialize, Serialize};

/// BACnet MS/TP Frame Types (ANSI/ASHRAE Standard 135)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BacnetMstpFrameType {
    Token = 0,
    PollForMaster = 1,
    ReplyToPollForMaster = 2,
    TestRequest = 3,
    TestResponse = 4,
    BacnetDataExpectingReply = 5,
    BacnetDataNotExpectingReply = 6,
    ReplyPostponed = 7,
    Unknown = 255,
}

impl BacnetMstpFrameType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Token,
            1 => Self::PollForMaster,
            2 => Self::ReplyToPollForMaster,
            3 => Self::TestRequest,
            4 => Self::TestResponse,
            5 => Self::BacnetDataExpectingReply,
            6 => Self::BacnetDataNotExpectingReply,
            7 => Self::ReplyPostponed,
            _ => Self::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Token => "Token Pass",
            Self::PollForMaster => "Poll For Master",
            Self::ReplyToPollForMaster => "Reply To Poll For Master",
            Self::TestRequest => "Test Request",
            Self::TestResponse => "Test Response",
            Self::BacnetDataExpectingReply => "BACnet Data Expecting Reply",
            Self::BacnetDataNotExpectingReply => "BACnet Data Not Expecting Reply",
            Self::ReplyPostponed => "Reply Postponed",
            Self::Unknown => "Proprietary or Unknown Frame Type",
        }
    }
}

/// Dissected BACnet MS/TP Frame
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacnetMstpFrame {
    pub frame_type: BacnetMstpFrameType,
    pub destination_address: u8,
    pub source_address: u8,
    pub data_length: u16,
    pub header_crc: u8,
    pub payload: Vec<u8>,
    pub data_crc: Option<u16>,
}

/// Calculate BACnet MS/TP Header CRC-8
/// Polynomial: X^8 + X^7 + X^4 + X^3 + X + 1 (0x11D), initial value 0xFF, invert at end.
pub fn calculate_bacnet_crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &b in data {
        let mut data_byte = b;
        for _ in 0..8 {
            let feedback = (crc ^ data_byte) & 0x01;
            crc >>= 1;
            if feedback != 0 {
                crc ^= 0x8C; // Reflected polynomial 0x11D -> 0x8C
            }
            data_byte >>= 1;
        }
    }
    !crc
}

/// Calculate BACnet MS/TP Data CRC-16
/// Polynomial: X^16 + X^12 + X^5 + 1 (CCITT 0x1021, reflected 0x8408)
/// Initial value: 0xFFFF, invert at end (!crc)
pub fn calculate_bacnet_data_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        let mut data_byte = b as u16;
        for _ in 0..8 {
            let feedback = (crc ^ data_byte) & 0x0001;
            crc >>= 1;
            if feedback != 0 {
                crc ^= 0x8408; // Reflected CCITT 0x1021 -> 0x8408
            }
            data_byte >>= 1;
        }
    }
    !crc
}

/// Dissect BACnet MS/TP Frame from byte buffer.
/// Preambles: 0x55 0xFF
pub fn dissect_bacnet_mstp(raw: &[u8]) -> Option<BacnetMstpFrame> {
    if raw.len() < 8 {
        return None;
    }

    // Preamble check
    if raw[0] != 0x55 || raw[1] != 0xFF {
        return None;
    }

    let frame_type = BacnetMstpFrameType::from_u8(raw[2]);
    let destination_address = raw[3];
    let source_address = raw[4];
    let data_length = u16::from_be_bytes([raw[5], raw[6]]);
    let header_crc = raw[7];

    // Validate header CRC (bytes 2..7)
    let calculated_crc = calculate_bacnet_crc8(&raw[2..7]);
    if calculated_crc != header_crc {
        return None;
    }

    let payload_len = data_length as usize;
    if payload_len == 0 {
        return Some(BacnetMstpFrame {
            frame_type,
            destination_address,
            source_address,
            data_length,
            header_crc,
            payload: Vec::new(),
            data_crc: None,
        });
    }

    // If payload exists, frame must have payload + 2 bytes data CRC
    if raw.len() >= 8 + payload_len + 2 {
        let payload = raw[8..8 + payload_len].to_vec();
        let data_crc = u16::from_le_bytes([raw[8 + payload_len], raw[8 + payload_len + 1]]);

        // Validate Data CRC-16
        let calculated_data_crc = calculate_bacnet_data_crc16(&payload);
        if calculated_data_crc != data_crc {
            return None;
        }

        Some(BacnetMstpFrame {
            frame_type,
            destination_address,
            source_address,
            data_length,
            header_crc,
            payload,
            data_crc: Some(data_crc),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_bacnet_token_frame() {
        // Preamble: 0x55, 0xFF, Type: 0 (Token), Dest: 0x02, Source: 0x01, Len: 0x0000
        // Header CRC calculated over [0x00, 0x02, 0x01, 0x00, 0x00]
        let crc = calculate_bacnet_crc8(&[0x00, 0x02, 0x01, 0x00, 0x00]);
        let frame_bytes = vec![0x55, 0xFF, 0x00, 0x02, 0x01, 0x00, 0x00, crc];

        let frame = dissect_bacnet_mstp(&frame_bytes).expect("Valid BACnet Token frame");
        assert_eq!(frame.frame_type, BacnetMstpFrameType::Token);
        assert_eq!(frame.destination_address, 2);
        assert_eq!(frame.source_address, 1);
        assert_eq!(frame.data_length, 0);
    }

    #[test]
    fn test_bacnet_data_frame_with_crc16() {
        // Frame Type 5: BacnetDataExpectingReply, Dest 0x0A, Source 0x05, Length 0x0004
        let header_data = [0x05, 0x0A, 0x05, 0x00, 0x04];
        let header_crc = calculate_bacnet_crc8(&header_data);
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let data_crc = calculate_bacnet_data_crc16(&payload);

        let mut frame_bytes = vec![0x55, 0xFF];
        frame_bytes.extend_from_slice(&header_data);
        frame_bytes.push(header_crc);
        frame_bytes.extend_from_slice(&payload);
        frame_bytes.extend_from_slice(&data_crc.to_le_bytes());

        // Valid frame with valid data CRC
        let frame = dissect_bacnet_mstp(&frame_bytes).expect("Valid BACnet Data frame with CRC-16");
        assert_eq!(frame.frame_type, BacnetMstpFrameType::BacnetDataExpectingReply);
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.data_crc, Some(data_crc));

        // Corrupt data CRC should be rejected (returns None)
        let mut corrupt_frame = frame_bytes.clone();
        let last_idx = corrupt_frame.len() - 1;
        corrupt_frame[last_idx] ^= 0xFF;
        assert!(dissect_bacnet_mstp(&corrupt_frame).is_none());
    }

    proptest::proptest! {
        #[test]
        fn fuzz_bacnet_dissector_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = dissect_bacnet_mstp(&data);
            let _ = calculate_bacnet_crc8(&data);
        }
    }
}
