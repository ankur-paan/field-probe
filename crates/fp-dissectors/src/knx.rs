use serde::{Deserialize, Serialize};

/// KNX APCI (Application Layer Control Information) Service Type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnxApciService {
    GroupValueRead,
    GroupValueResponse,
    GroupValueWrite,
    IndividualAddrWrite,
    IndividualAddrRead,
    IndividualAddrResponse,
    Other(u16),
}

/// KNX Priority Level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnxPriority {
    System,
    Urgent,
    Normal,
    Low,
}

/// Dissected KNX TP1 Telegram
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnxMessage {
    pub control_byte: u8,
    pub priority: KnxPriority,
    pub is_repeated: bool,
    pub source_address_raw: u16,
    pub source_address_str: String,
    pub destination_address_raw: u16,
    pub destination_address_str: String,
    pub is_group_address: bool,
    pub hop_count: u8,
    pub service: KnxApciService,
    pub payload: Vec<u8>,
    pub checksum_valid: bool,
}

/// Verify KNX longitudinal parity checksum (byte-wise XOR inverted)
pub fn verify_knx_checksum(frame: &[u8]) -> bool {
    if frame.len() < 8 {
        return false;
    }
    let body = &frame[..frame.len() - 1];
    let expected = frame[frame.len() - 1];
    let xor_sum = body.iter().fold(0xFFu8, |acc, &b| acc ^ b);
    xor_sum == expected
}

/// Calculate KNX longitudinal parity checksum
pub fn calculate_knx_checksum(body: &[u8]) -> u8 {
    body.iter().fold(0xFFu8, |acc, &b| acc ^ b)
}

/// Dissect a raw KNX TP1 telegram (minimum 8 bytes)
pub fn dissect_knx(raw: &[u8]) -> Option<KnxMessage> {
    if raw.len() < 8 {
        return None;
    }

    let checksum_valid = verify_knx_checksum(raw);

    let control_byte = raw[0];
    let is_repeated = (control_byte & 0x20) == 0;
    let priority = match (control_byte >> 2) & 0x03 {
        0 => KnxPriority::System,
        2 => KnxPriority::Urgent,
        1 => KnxPriority::Normal,
        _ => KnxPriority::Low,
    };

    let src_raw = u16::from_be_bytes([raw[1], raw[2]]);
    let src_area = ((src_raw >> 12) & 0x0F) as u8;
    let src_line = ((src_raw >> 8) & 0x0F) as u8;
    let src_dev = (src_raw & 0xFF) as u8;
    let source_address_str = format!("{}.{}.{}", src_area, src_line, src_dev);

    let dst_raw = u16::from_be_bytes([raw[3], raw[4]]);
    let routing_byte = raw[5];
    let is_group_address = (routing_byte & 0x80) != 0;
    let hop_count = (routing_byte >> 4) & 0x07;
    let length_field = (routing_byte & 0x0F) as usize;

    let destination_address_str = if is_group_address {
        let main = ((dst_raw >> 11) & 0x1F) as u8;
        let middle = ((dst_raw >> 8) & 0x07) as u8;
        let sub = (dst_raw & 0xFF) as u8;
        format!("{}/{}/{}", main, middle, sub)
    } else {
        let dst_area = ((dst_raw >> 12) & 0x0F) as u8;
        let dst_line = ((dst_raw >> 8) & 0x0F) as u8;
        let dst_dev = (dst_raw & 0xFF) as u8;
        format!("{}.{}.{}", dst_area, dst_line, dst_dev)
    };

    let tpci_apci_high = raw[6];
    let raw_apci_high = (tpci_apci_high & 0x03) as u16;

    let (service, payload) = if length_field <= 1 {
        // Small data (up to 6 bits) encoded directly in raw[6]
        let apci_code = raw_apci_high;
        let service = match apci_code {
            0 => KnxApciService::GroupValueRead,
            1 => KnxApciService::GroupValueResponse,
            2 => KnxApciService::GroupValueWrite,
            _ => KnxApciService::Other(apci_code),
        };
        let small_val = tpci_apci_high & 0x3F;
        (service, vec![small_val])
    } else {
        // Multi-byte data: raw[7] contains APCI low bits + first byte
        let apci_low = if raw.len() > 7 {
            (raw[7] >> 6) as u16
        } else {
            0
        };
        let full_apci = (raw_apci_high << 2) | apci_low;

        let service = match full_apci {
            0 => KnxApciService::GroupValueRead,
            1 => KnxApciService::GroupValueResponse,
            2 => KnxApciService::GroupValueWrite,
            3 => KnxApciService::IndividualAddrWrite,
            4 => KnxApciService::IndividualAddrRead,
            5 => KnxApciService::IndividualAddrResponse,
            other => KnxApciService::Other(other),
        };

        let data_start = 7;
        let data_end = (data_start + length_field).min(raw.len().saturating_sub(1));
        let payload = if data_start < data_end {
            raw[data_start..data_end].to_vec()
        } else {
            Vec::new()
        };
        (service, payload)
    };

    Some(KnxMessage {
        control_byte,
        priority,
        is_repeated,
        source_address_raw: src_raw,
        source_address_str,
        destination_address_raw: dst_raw,
        destination_address_str,
        is_group_address,
        hop_count,
        service,
        payload,
        checksum_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_knx_group_value_write_switch() {
        // Control: 0xBC (Standard, Normal Priority, not repeated)
        // Source: 1.1.25 -> Area 1, Line 1, Device 25 -> (1 << 12) | (1 << 8) | 25 = 0x1119
        // Dest: Group 2/1/40 -> Main 2, Middle 1, Sub 40 -> (2 << 11) | (1 << 8) | 40 = 0x1128
        // Routing: DAF=1, Hop=6, Len=1 -> 0xE1 (1110 0001)
        // TPCI/APCI: GroupValueWrite (APCI=2 -> 0b000010), Data bit 1 (Switch ON):
        // Byte 6: TPCI=0, APCI=0b10, Data=0b01 -> 0x81 (or APCI=2 -> 0x02 | 0x01 = 0x03)
        let body = [
            0xBC, 0x11, 0x19, // Src: 1.1.25
            0x11, 0x28, // Dst: 2/1/40
            0xE1, // Routing
            0x82, // GroupValueWrite (0x80 | 0x02)
        ];
        let cs = calculate_knx_checksum(&body);
        let mut frame = body.to_vec();
        frame.push(cs);

        let msg = dissect_knx(&frame).expect("Dissect KNX telegram");
        assert_eq!(msg.priority, KnxPriority::Low);
        assert!(!msg.is_repeated);
        assert_eq!(msg.source_address_str, "1.1.25");
        assert_eq!(msg.destination_address_str, "2/1/40");
        assert!(msg.is_group_address);
        assert_eq!(msg.hop_count, 6);
        assert!(msg.checksum_valid);
    }

    #[test]
    fn test_knx_temperature_sensor_response() {
        // 2-byte temperature report: 21.5 C
        let body = [
            0xBC, 0x11, 0x05, // Src: 1.1.5
            0x18, 0x01, // Dst: Group 3/0/1
            0xE2, // Routing: DAF=1, Hop=6, Len=2
            0x40, // GroupValueResponse TPCI/APCI
            0x0C, 0x1A, // DPT 9.001 2-byte float
        ];
        let cs = calculate_knx_checksum(&body);
        let mut frame = body.to_vec();
        frame.push(cs);

        let msg = dissect_knx(&frame).expect("Dissect KNX float telegram");
        assert_eq!(msg.source_address_str, "1.1.5");
        assert_eq!(msg.destination_address_str, "3/0/1");
        assert!(msg.checksum_valid);
        assert_eq!(msg.payload.len(), 2);
    }

    proptest! {
        #[test]
        fn fuzz_knx_dissector_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = dissect_knx(&data);
            let _ = verify_knx_checksum(&data);
            let _ = calculate_knx_checksum(&data);
        }
    }
}
