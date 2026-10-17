use serde::{Deserialize, Serialize};

/// AUTOSAR CAN Network Management Control Bit Vector (CBV) per AUTOSAR SWS CAN Network Management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlBitVector {
    pub raw: u8,
    /// Bit 0: Repeat Message Request (1 = Node requests Repeat Message state)
    pub repeat_message_request: bool,
    /// Bit 3: Active Wakeup Bit (1 = Node woke up the network)
    pub active_wakeup: bool,
    /// Bit 6: Partial Network Information (1 = User data contains Partial Network Cluster requests)
    pub partial_network_info: bool,
}

impl ControlBitVector {
    pub fn from_u8(raw: u8) -> Self {
        Self {
            raw,
            repeat_message_request: (raw & 0x01) != 0,
            active_wakeup: (raw & 0x08) != 0,
            partial_network_info: (raw & 0x40) != 0,
        }
    }
}

/// Dissected AUTOSAR CAN Network Management (CAN NM) PDU
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutosarNmMessage {
    pub can_id: u32,
    pub source_node_id: u8,
    pub control_bit_vector: ControlBitVector,
    pub user_data: Vec<u8>,
}

/// Helper to identify if an arbitration ID is within standard AUTOSAR CAN NM base ID ranges
pub fn is_potential_nm_frame(can_id: u32) -> bool {
    // Standard Base ranges: 0x400..=0x4FF or 0x500..=0x5FF or 0x600..=0x6FF
    // Or 29-bit NM PDU format (PF = 0xCB, J1939 NM or extended AUTOSAR NM)
    (0x400..=0x6FF).contains(&can_id) || ((can_id >> 16) & 0xFF) == 0xCB
}

/// Dissect raw CAN frame data as an AUTOSAR CAN NM PDU
pub fn dissect_autosar_nm(can_id: u32, data: &[u8]) -> Option<AutosarNmMessage> {
    if data.len() < 2 {
        return None;
    }

    // Default AUTOSAR NM PDU format: Byte 0 = Source Node ID, Byte 1 = Control Bit Vector (CBV)
    let source_node_id = data[0];
    let cbv_raw = data[1];
    let control_bit_vector = ControlBitVector::from_u8(cbv_raw);
    let user_data = if data.len() > 2 {
        data[2..].to_vec()
    } else {
        Vec::new()
    };

    Some(AutosarNmMessage {
        can_id,
        source_node_id,
        control_bit_vector,
        user_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autosar_nm_dissection() {
        // CAN ID 0x500 (ECU 0x22 NM Frame)
        // Byte 0: Node ID 0x22
        // Byte 1: CBV = 0x09 (ActiveWakeup 0x08 + RepeatMessage 0x01)
        // Bytes 2..7: User Data [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00]
        let can_id = 0x500;
        let data = [0x22, 0x09, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00];

        assert!(is_potential_nm_frame(can_id));
        let msg = dissect_autosar_nm(can_id, &data).expect("Dissected AUTOSAR NM");
        assert_eq!(msg.source_node_id, 0x22);
        assert!(msg.control_bit_vector.active_wakeup);
        assert!(msg.control_bit_vector.repeat_message_request);
        assert!(!msg.control_bit_vector.partial_network_info);
        assert_eq!(msg.user_data.len(), 6);
        assert_eq!(msg.user_data[0], 0xAA);
    }

    #[test]
    fn test_autosar_nm_partial_network() {
        let can_id = 0x410;
        // CBV = 0x40 (Partial Network Info)
        let data = [0x10, 0x40, 0x01];
        let msg = dissect_autosar_nm(can_id, &data).unwrap();
        assert_eq!(msg.source_node_id, 0x10);
        assert!(msg.control_bit_vector.partial_network_info);
        assert!(!msg.control_bit_vector.active_wakeup);
        assert_eq!(msg.user_data, vec![0x01]);
    }
}
