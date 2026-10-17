use serde::{Deserialize, Serialize};

/// ODVA DeviceNet CAN Identifier Message Groups (11-bit CAN IDs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceNetGroup {
    /// Group 1 (0x000 - 0x3FF): High-priority I/O data
    Group1 { message_id: u8, mac_id: u8 },
    /// Group 2 (0x400 - 0x5FF): Predefined Master/Slave Connection Set
    Group2 { mac_id: u8, message_id: u8 },
    /// Group 3 (0x600 - 0x7BF): Explicit Messaging & UCMM
    Group3 { message_id: u8, mac_id: u8 },
    /// Group 4 (0x7C0 - 0x7FF): Network Management, Fault Recovery, Duplicate MAC check
    Group4 { message_id: u8 },
}

/// DeviceNet Group 2 Predefined Master/Slave Message Types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Group2MessageType {
    MasterChangeOfStateAck, // 0
    MasterBitStrobeCommand, // 1
    MasterMulticastPoll,    // 2
    MasterExplicitRequest,  // 3
    SlaveExplicitResponse,  // 4
    SlaveChangeOfStateIo,   // 5
    SlavePollResponse,      // 6
    SlaveBitStrobeResponse, // 7
    Unknown(u8),
}

impl From<u8> for Group2MessageType {
    fn from(val: u8) -> Self {
        match val {
            0 => Group2MessageType::MasterChangeOfStateAck,
            1 => Group2MessageType::MasterBitStrobeCommand,
            2 => Group2MessageType::MasterMulticastPoll,
            3 => Group2MessageType::MasterExplicitRequest,
            4 => Group2MessageType::SlaveExplicitResponse,
            5 => Group2MessageType::SlaveChangeOfStateIo,
            6 => Group2MessageType::SlavePollResponse,
            7 => Group2MessageType::SlaveBitStrobeResponse,
            other => Group2MessageType::Unknown(other),
        }
    }
}

/// DeviceNet Explicit Messaging Fragmentation Header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceNetFragmentHeader {
    pub fragment_type: u8, // 0 = First, 1 = Middle, 2 = End, 3 = Ack
    pub fragment_type_name: String,
    pub fragment_count: u8,
}

/// High-level decoded DeviceNet Payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeviceNetPayload {
    /// Group 2 Predefined Master/Slave explicit request/response
    ExplicitMessage {
        service: u8,
        service_name: String,
        is_response: bool,
        class_id: Option<u16>,
        instance_id: Option<u16>,
        attribute_id: Option<u8>,
        data: Vec<u8>,
    },
    /// Fragmented Explicit Message
    FragmentedExplicit {
        header: DeviceNetFragmentHeader,
        data: Vec<u8>,
    },
    /// Master Bit-Strobe Command (64 bits of run/idle per node)
    BitStrobeCommand { strobe_bits: Vec<u8> },
    /// Master or Slave I/O Poll Data
    PollIoData {
        message_type: Group2MessageType,
        io_data: Vec<u8>,
    },
    /// Group 4 Network Management (Duplicate MAC, Heartbeat)
    NetworkManagement {
        message_id: u8,
        description: String,
        data: Vec<u8>,
    },
    /// Generic or unparsed payload
    Generic {
        group: DeviceNetGroup,
        data: Vec<u8>,
    },
}

/// Fully dissected ODVA DeviceNet Message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceNetMessage {
    pub can_id: u16,
    pub group: DeviceNetGroup,
    pub mac_id: Option<u8>,
    pub payload: DeviceNetPayload,
}

/// Parse 11-bit CAN ID into DeviceNet Group and Node Addressing
pub fn parse_devicenet_id(can_id: u16) -> Option<DeviceNetGroup> {
    if can_id > 0x7FF {
        return None;
    }

    if can_id <= 0x3FF {
        let message_id = ((can_id >> 6) & 0x0F) as u8;
        let mac_id = (can_id & 0x3F) as u8;
        Some(DeviceNetGroup::Group1 { message_id, mac_id })
    } else if can_id <= 0x5FF {
        let mac_id = ((can_id >> 3) & 0x3F) as u8;
        let message_id = (can_id & 0x07) as u8;
        Some(DeviceNetGroup::Group2 { mac_id, message_id })
    } else if can_id <= 0x7BF {
        let message_id = ((can_id >> 6) & 0x07) as u8;
        let mac_id = (can_id & 0x3F) as u8;
        Some(DeviceNetGroup::Group3 { message_id, mac_id })
    } else {
        let message_id = (can_id & 0x3F) as u8;
        Some(DeviceNetGroup::Group4 { message_id })
    }
}

pub fn devicenet_cip_service_name(service: u8) -> &'static str {
    match service & 0x7F {
        0x01 => "Get_Attributes_All",
        0x02 => "Set_Attributes_All",
        0x03 => "Get_Attribute_List",
        0x04 => "Set_Attribute_List",
        0x05 => "Reset",
        0x06 => "Start",
        0x07 => "Stop",
        0x08 => "Create",
        0x09 => "Delete",
        0x0E => "Get_Attribute_Single",
        0x10 => "Set_Attribute_Single",
        0x4B => "DeviceNet_Allocate_Master_Slave",
        0x4C => "DeviceNet_Release_Master_Slave",
        _ => "Vendor Specific CIP Service",
    }
}

/// Dissect an 11-bit CAN frame as ODVA DeviceNet
pub fn dissect_devicenet(can_id: u32, data: &[u8]) -> Option<DeviceNetMessage> {
    if can_id > 0x7FF {
        return None;
    }
    let can_id_11 = can_id as u16;
    let group = parse_devicenet_id(can_id_11)?;

    let (mac_id, payload) = match &group {
        DeviceNetGroup::Group2 { mac_id, message_id } => {
            let msg_type = Group2MessageType::from(*message_id);
            match msg_type {
                Group2MessageType::MasterExplicitRequest
                | Group2MessageType::SlaveExplicitResponse => {
                    let payload = dissect_explicit_payload(data);
                    (Some(*mac_id), payload)
                }
                Group2MessageType::MasterBitStrobeCommand => (
                    Some(*mac_id),
                    DeviceNetPayload::BitStrobeCommand {
                        strobe_bits: data.to_vec(),
                    },
                ),
                Group2MessageType::SlavePollResponse
                | Group2MessageType::MasterMulticastPoll
                | Group2MessageType::SlaveChangeOfStateIo
                | Group2MessageType::MasterChangeOfStateAck => (
                    Some(*mac_id),
                    DeviceNetPayload::PollIoData {
                        message_type: msg_type,
                        io_data: data.to_vec(),
                    },
                ),
                _ => (
                    Some(*mac_id),
                    DeviceNetPayload::Generic {
                        group: group.clone(),
                        data: data.to_vec(),
                    },
                ),
            }
        }
        DeviceNetGroup::Group1 { mac_id, .. } => (
            Some(*mac_id),
            DeviceNetPayload::Generic {
                group: group.clone(),
                data: data.to_vec(),
            },
        ),
        DeviceNetGroup::Group3 { mac_id, .. } => (
            Some(*mac_id),
            if !data.is_empty() {
                dissect_explicit_payload(data)
            } else {
                DeviceNetPayload::Generic {
                    group: group.clone(),
                    data: data.to_vec(),
                }
            },
        ),
        DeviceNetGroup::Group4 { message_id } => {
            let desc = match message_id {
                0..=2 => "Duplicate MAC ID Check / Response",
                3 => "Communication Fault Request",
                4 => "Communication Fault Response",
                _ => "Network Management Frame",
            };
            (
                None,
                DeviceNetPayload::NetworkManagement {
                    message_id: *message_id,
                    description: desc.to_string(),
                    data: data.to_vec(),
                },
            )
        }
    };

    Some(DeviceNetMessage {
        can_id: can_id_11,
        group,
        mac_id,
        payload,
    })
}

fn dissect_explicit_payload(data: &[u8]) -> DeviceNetPayload {
    if data.is_empty() {
        return DeviceNetPayload::Generic {
            group: DeviceNetGroup::Group4 { message_id: 0 },
            data: Vec::new(),
        };
    }

    let is_fragmented = (data[0] & 0x80) != 0;
    if is_fragmented {
        let frag_type = (data[0] >> 6) & 0x01;
        let frag_count = data[0] & 0x3F;
        let type_name = if frag_type == 0 {
            "First Fragment"
        } else {
            "Subsequent Fragment"
        };
        DeviceNetPayload::FragmentedExplicit {
            header: DeviceNetFragmentHeader {
                fragment_type: frag_type,
                fragment_type_name: type_name.to_string(),
                fragment_count: frag_count,
            },
            data: data[1..].to_vec(),
        }
    } else {
        let raw_service = data[0];
        let is_response = (raw_service & 0x80) != 0;
        let service = raw_service & 0x7F;
        let service_name = devicenet_cip_service_name(service).to_string();

        let class_id = if data.len() >= 2 {
            Some(data[1] as u16)
        } else {
            None
        };
        let instance_id = if data.len() >= 3 {
            Some(data[2] as u16)
        } else {
            None
        };
        let attribute_id = if data.len() >= 4 { Some(data[3]) } else { None };
        let payload_data = if data.len() >= 4 {
            data[4..].to_vec()
        } else {
            Vec::new()
        };

        DeviceNetPayload::ExplicitMessage {
            service,
            service_name,
            is_response,
            class_id,
            instance_id,
            attribute_id,
            data: payload_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_devicenet_group2_master_slave_explicit() {
        // Group 2 CAN ID: MAC ID 5 (0x05), Msg ID 3 (Master Explicit Request)
        // can_id = 0x400 | (0x05 << 3) | 3 = 0x400 | 0x28 | 3 = 0x42B
        let can_id = 0x42B;
        // CIP Get_Attribute_Single (0x0E), Class 1 (Identity), Instance 1, Attribute 1 (Vendor ID)
        let data = [0x0E, 0x01, 0x01, 0x01];

        let msg = dissect_devicenet(can_id, &data).expect("Dissect DeviceNet");
        assert_eq!(msg.can_id, 0x42B);
        assert_eq!(msg.mac_id, Some(5));

        match msg.payload {
            DeviceNetPayload::ExplicitMessage {
                service,
                service_name,
                is_response,
                class_id,
                instance_id,
                attribute_id,
                ..
            } => {
                assert_eq!(service, 0x0E);
                assert_eq!(service_name, "Get_Attribute_Single");
                assert!(!is_response);
                assert_eq!(class_id, Some(1));
                assert_eq!(instance_id, Some(1));
                assert_eq!(attribute_id, Some(1));
            }
            _ => panic!("Expected ExplicitMessage"),
        }
    }

    #[test]
    fn test_devicenet_fragmentation_header() {
        // CAN ID for Slave Explicit Response from Node 10 (0x0A): Msg ID 4
        // can_id = 0x400 | (0x0A << 3) | 4 = 0x454
        let can_id = 0x454;
        // First fragment: bit 7 = 1, bits 6..6 = 0 (type 0 First Fragment), fragment count 0 -> 0x80
        let data = [0x80, 0x8E, 0x00, 0x00, 0x01, 0x00];

        let msg = dissect_devicenet(can_id, &data).expect("Dissect Fragmented DeviceNet");
        match msg.payload {
            DeviceNetPayload::FragmentedExplicit { header, data: body } => {
                assert_eq!(header.fragment_type, 0);
                assert_eq!(header.fragment_type_name, "First Fragment");
                assert_eq!(header.fragment_count, 0);
                assert_eq!(body.len(), 5);
            }
            _ => panic!("Expected FragmentedExplicit"),
        }
    }

    #[test]
    fn test_devicenet_poll_io() {
        // Group 2: Node 12 (0x0C), Msg ID 6 (Slave Poll Response)
        // can_id = 0x400 | (0x0C << 3) | 6 = 0x466
        let can_id = 0x466;
        let io_data = [0x01, 0x02, 0x03, 0x04];

        let msg = dissect_devicenet(can_id, &io_data).expect("Dissect I/O Poll Response");
        match msg.payload {
            DeviceNetPayload::PollIoData {
                message_type,
                io_data: rx_data,
            } => {
                assert_eq!(message_type, Group2MessageType::SlavePollResponse);
                assert_eq!(rx_data, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected PollIoData"),
        }
    }

    proptest::proptest! {
        #[test]
        fn fuzz_devicenet_dissector_never_panics(can_id in any::<u32>(), data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = dissect_devicenet(can_id, &data);
            let _ = parse_devicenet_id((can_id & 0x7FF) as u16);
        }
    }
}
