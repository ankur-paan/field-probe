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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BacnetMstpFrame {
    pub frame_type: BacnetMstpFrameType,
    pub destination_address: u8,
    pub source_address: u8,
    pub data_length: u16,
    pub header_crc: u8,
    pub payload: Vec<u8>,
    pub data_crc: Option<u16>,
    pub apdu: Option<BacnetApdu>,
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

/// BACnet Standard Object Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacnetObjectType {
    AnalogInput,
    AnalogOutput,
    AnalogValue,
    BinaryInput,
    BinaryOutput,
    BinaryValue,
    Calendar,
    Command,
    Device,
    EventEnrollment,
    File,
    Group,
    Loop,
    MultiStateInput,
    MultiStateOutput,
    NotificationClass,
    Program,
    Schedule,
    Averaging,
    MultiStateValue,
    TrendLog,
    PulseConverter,
    Accumulator,
    Other(u16),
}

pub fn bacnet_object_type_name(obj_type: &BacnetObjectType) -> &'static str {
    match obj_type {
        BacnetObjectType::AnalogInput => "Analog Input",
        BacnetObjectType::AnalogOutput => "Analog Output",
        BacnetObjectType::AnalogValue => "Analog Value",
        BacnetObjectType::BinaryInput => "Binary Input",
        BacnetObjectType::BinaryOutput => "Binary Output",
        BacnetObjectType::BinaryValue => "Binary Value",
        BacnetObjectType::Calendar => "Calendar",
        BacnetObjectType::Command => "Command",
        BacnetObjectType::Device => "Device",
        BacnetObjectType::EventEnrollment => "Event Enrollment",
        BacnetObjectType::File => "File",
        BacnetObjectType::Group => "Group",
        BacnetObjectType::Loop => "Loop",
        BacnetObjectType::MultiStateInput => "Multi-State Input",
        BacnetObjectType::MultiStateOutput => "Multi-State Output",
        BacnetObjectType::NotificationClass => "Notification Class",
        BacnetObjectType::Program => "Program",
        BacnetObjectType::Schedule => "Schedule",
        BacnetObjectType::Averaging => "Averaging",
        BacnetObjectType::MultiStateValue => "Multi-State Value",
        BacnetObjectType::TrendLog => "Trend Log",
        BacnetObjectType::PulseConverter => "Pulse Converter",
        BacnetObjectType::Accumulator => "Accumulator",
        BacnetObjectType::Other(_) => "Custom Object",
    }
}

/// BACnet Object Identifier (Type + 22-bit Instance)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacnetObjectId {
    pub object_type: BacnetObjectType,
    pub instance: u32,
}

pub fn parse_bacnet_object_id(raw: u32) -> BacnetObjectId {
    let obj_type_u16 = ((raw >> 22) & 0x3FF) as u16;
    let instance = raw & 0x3FFFFF;
    let object_type = match obj_type_u16 {
        0 => BacnetObjectType::AnalogInput,
        1 => BacnetObjectType::AnalogOutput,
        2 => BacnetObjectType::AnalogValue,
        3 => BacnetObjectType::BinaryInput,
        4 => BacnetObjectType::BinaryOutput,
        5 => BacnetObjectType::BinaryValue,
        6 => BacnetObjectType::Calendar,
        7 => BacnetObjectType::Command,
        8 => BacnetObjectType::Device,
        9 => BacnetObjectType::EventEnrollment,
        10 => BacnetObjectType::File,
        11 => BacnetObjectType::Group,
        12 => BacnetObjectType::Loop,
        13 => BacnetObjectType::MultiStateInput,
        14 => BacnetObjectType::MultiStateOutput,
        15 => BacnetObjectType::NotificationClass,
        16 => BacnetObjectType::Program,
        17 => BacnetObjectType::Schedule,
        18 => BacnetObjectType::Averaging,
        19 => BacnetObjectType::MultiStateValue,
        20 => BacnetObjectType::TrendLog,
        28 => BacnetObjectType::PulseConverter,
        40 => BacnetObjectType::Accumulator,
        other => BacnetObjectType::Other(other),
    };
    BacnetObjectId {
        object_type,
        instance,
    }
}

pub fn bacnet_property_name(prop_id: u32) -> &'static str {
    match prop_id {
        28 => "Description",
        75 => "Object_List",
        77 => "Object_Identifier",
        79 => "Object_Name",
        84 => "Reliability",
        85 => "Present_Value",
        111 => "Status_Flags",
        117 => "Units",
        121 => "Out_Of_Service",
        _ => "Property",
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BacnetService {
    WhoIs {
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    },
    IAm {
        device_id: u32,
        max_apdu: u16,
        segmentation: u8,
        vendor_id: u16,
    },
    ReadProperty {
        object: BacnetObjectId,
        property_id: u32,
        property_name: String,
        array_index: Option<u32>,
    },
    ReadPropertyAck {
        object: BacnetObjectId,
        property_id: u32,
        property_name: String,
        value: Option<f32>,
        raw_value: Vec<u8>,
    },
    WriteProperty {
        object: BacnetObjectId,
        property_id: u32,
        property_name: String,
        raw_value: Vec<u8>,
    },
    CovNotification {
        subscriber_process_id: u32,
        initiating_device: u32,
        monitored_object: BacnetObjectId,
        time_remaining_sec: u32,
    },
    Other {
        service_choice: u8,
        service_name: String,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BacnetApdu {
    pub pdu_type: u8,
    pub pdu_type_name: String,
    pub invoke_id: Option<u8>,
    pub service: BacnetService,
}

/// Dissect raw BACnet APDU bytes
pub fn dissect_bacnet_apdu(data: &[u8]) -> Option<BacnetApdu> {
    if data.is_empty() {
        return None;
    }

    let pdu_type = (data[0] >> 4) & 0x0F;
    let (pdu_type_name, invoke_id, service) = match pdu_type {
        0 => {
            // Confirmed-REQ: [0x00, max_seg_and_apdu, invoke_id, service_choice, ...]
            if data.len() < 4 {
                return None;
            }
            let invoke_id = data[2];
            let service_choice = data[3];
            let payload = &data[4..];

            let service = match service_choice {
                12 if payload.len() >= 7 => {
                    // ReadProperty: [0x0C (tag 0, len 4), obj_id (4), 0x19 (tag 1, len 1), prop_id (1)]
                    let raw_obj =
                        u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                    let object = parse_bacnet_object_id(raw_obj);
                    let prop_id = payload[6] as u32;
                    BacnetService::ReadProperty {
                        object,
                        property_id: prop_id,
                        property_name: bacnet_property_name(prop_id).to_string(),
                        array_index: None,
                    }
                }
                15 if payload.len() >= 7 => {
                    // WriteProperty: [0x0C, obj_id(4), 0x19, prop_id(1), ...]
                    let raw_obj =
                        u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                    let object = parse_bacnet_object_id(raw_obj);
                    let prop_id = payload[6] as u32;
                    let raw_val = if payload.len() > 7 {
                        payload[7..].to_vec()
                    } else {
                        Vec::new()
                    };
                    BacnetService::WriteProperty {
                        object,
                        property_id: prop_id,
                        property_name: bacnet_property_name(prop_id).to_string(),
                        raw_value: raw_val,
                    }
                }
                _ => BacnetService::Other {
                    service_choice,
                    service_name: format!("Confirmed Service {}", service_choice),
                    data: payload.to_vec(),
                },
            };

            ("Confirmed-REQ".to_string(), Some(invoke_id), service)
        }
        1 => {
            // Unconfirmed-REQ: [0x10, service_choice, ...]
            if data.len() < 2 {
                return None;
            }
            let service_choice = data[1];
            let payload = &data[2..];

            let service = match service_choice {
                8 => {
                    // Who-Is
                    let (low_limit, high_limit) =
                        if payload.len() >= 4 && payload[0] == 0x09 && payload[2] == 0x19 {
                            (Some(payload[1] as u32), Some(payload[3] as u32))
                        } else {
                            (None, None)
                        };
                    BacnetService::WhoIs {
                        low_limit,
                        high_limit,
                    }
                }
                0 if payload.len() >= 11 => {
                    // I-Am: [0xC4 (tag 12 len 4), obj_id(4), 0x22 (tag 2 len 2), max_apdu(2), 0x91 (tag 9 len 1), seg(1), 0x21 (tag 2 len 1), vendor(1)]
                    let raw_dev =
                        u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                    let dev_obj = parse_bacnet_object_id(raw_dev);
                    let max_apdu = u16::from_be_bytes([payload[6], payload[7]]);
                    let segmentation = payload[9];
                    let vendor_id = payload[11] as u16;
                    BacnetService::IAm {
                        device_id: dev_obj.instance,
                        max_apdu,
                        segmentation,
                        vendor_id,
                    }
                }
                _ => BacnetService::Other {
                    service_choice,
                    service_name: format!("Unconfirmed Service {}", service_choice),
                    data: payload.to_vec(),
                },
            };

            ("Unconfirmed-REQ".to_string(), None, service)
        }
        3 => {
            // Complex-ACK: [0x30, invoke_id, service_choice, ...]
            if data.len() < 3 {
                return None;
            }
            let invoke_id = data[1];
            let service_choice = data[2];
            let payload = &data[3..];

            let service = match service_choice {
                12 if payload.len() >= 7 => {
                    // ReadPropertyAck: [0x0C, obj(4), 0x19, prop(1), 0x3E (open 3), value..., 0x3F (close 3)]
                    let raw_obj =
                        u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                    let object = parse_bacnet_object_id(raw_obj);
                    let prop_id = payload[6] as u32;

                    let mut float_val = None;
                    if let Some(open_pos) = payload.iter().position(|&b| b == 0x3E) {
                        if open_pos + 5 < payload.len() && payload[open_pos + 1] == 0x44 {
                            // IEEE 754 Real float: 0x44 followed by 4 bytes
                            float_val = Some(f32::from_be_bytes([
                                payload[open_pos + 2],
                                payload[open_pos + 3],
                                payload[open_pos + 4],
                                payload[open_pos + 5],
                            ]));
                        }
                    }

                    BacnetService::ReadPropertyAck {
                        object,
                        property_id: prop_id,
                        property_name: bacnet_property_name(prop_id).to_string(),
                        value: float_val,
                        raw_value: payload.to_vec(),
                    }
                }
                _ => BacnetService::Other {
                    service_choice,
                    service_name: format!("Complex-ACK Service {}", service_choice),
                    data: payload.to_vec(),
                },
            };

            ("Complex-ACK".to_string(), Some(invoke_id), service)
        }
        _ => (
            format!("PDU Type {}", pdu_type),
            None,
            BacnetService::Other {
                service_choice: 0,
                service_name: "Generic APDU".to_string(),
                data: data.to_vec(),
            },
        ),
    };

    Some(BacnetApdu {
        pdu_type,
        pdu_type_name,
        invoke_id,
        service,
    })
}

/// Dissect BACnet NPDU (Network Protocol Data Unit) and return inner APDU if present
pub fn dissect_bacnet_npdu(data: &[u8]) -> Option<BacnetApdu> {
    if data.len() < 2 || data[0] != 0x01 {
        return None;
    }
    let control = data[1];
    if (control & 0x80) != 0 {
        // Network layer message, not application layer APDU
        return None;
    }

    let mut idx = 2;
    // Destination present (DNET, DLEN, DADR)
    if (control & 0x20) != 0 {
        if idx + 3 > data.len() {
            return None;
        }
        let dlen = data[idx + 2] as usize;
        idx += 3 + dlen;
    }

    // Source present (SNET, SLEN, SADR)
    if (control & 0x08) != 0 {
        if idx + 3 > data.len() {
            return None;
        }
        let slen = data[idx + 2] as usize;
        idx += 3 + slen;
    }

    // Hop count (present if destination present)
    if (control & 0x20) != 0 {
        idx += 1;
    }

    if idx < data.len() {
        dissect_bacnet_apdu(&data[idx..])
    } else {
        None
    }
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
            apdu: None,
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

        let apdu = dissect_bacnet_npdu(&payload);

        Some(BacnetMstpFrame {
            frame_type,
            destination_address,
            source_address,
            data_length,
            header_crc,
            payload,
            data_crc: Some(data_crc),
            apdu,
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
        assert_eq!(
            frame.frame_type,
            BacnetMstpFrameType::BacnetDataExpectingReply
        );
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.data_crc, Some(data_crc));

        // Corrupt data CRC should be rejected (returns None)
        let mut corrupt_frame = frame_bytes.clone();
        let last_idx = corrupt_frame.len() - 1;
        corrupt_frame[last_idx] ^= 0xFF;
        assert!(dissect_bacnet_mstp(&corrupt_frame).is_none());
    }

    #[test]
    fn test_bacnet_apdu_read_property_and_complex_ack() {
        // ReadProperty Request:
        // NPDU: [0x01, 0x04]
        // APDU: Confirmed-REQ (0x00), Seg/Max (0x05), Invoke (0x01), Service 12
        // Object: AnalogInput 1 -> raw = (0 << 22) | 1 = 0x00000001
        // Tag 0 (0x0C), [0x00, 0x00, 0x00, 0x01], Tag 1 (0x19), [85 Present_Value]
        let req_npdu_apdu = vec![
            0x01, 0x04, 0x00, 0x05, 0x01, 12, 0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 85,
        ];
        let req_apdu = dissect_bacnet_npdu(&req_npdu_apdu).expect("Dissect ReadProperty APDU");
        assert_eq!(req_apdu.pdu_type_name, "Confirmed-REQ");
        assert_eq!(req_apdu.invoke_id, Some(1));
        match req_apdu.service {
            BacnetService::ReadProperty {
                object,
                property_id,
                property_name,
                ..
            } => {
                assert_eq!(object.object_type, BacnetObjectType::AnalogInput);
                assert_eq!(object.instance, 1);
                assert_eq!(property_id, 85);
                assert_eq!(property_name, "Present_Value");
            }
            _ => panic!("Expected ReadProperty"),
        }

        // ReadProperty Complex-ACK:
        // APDU: Complex-ACK (0x30), Invoke (0x01), Service 12
        // Object: AnalogInput 1 (0x0C, [0x00, 0x00, 0x00, 0x01]), Property (0x19, [85])
        // Tag 3 Open (0x3E), Real Float 23.5 C (0x44, 23.5f32.to_be_bytes()), Tag 3 Close (0x3F)
        let float_bytes = 23.5f32.to_be_bytes();
        let ack_apdu_bytes = vec![
            0x30,
            0x01,
            12,
            0x0C,
            0x00,
            0x00,
            0x00,
            0x01,
            0x19,
            85,
            0x3E,
            0x44,
            float_bytes[0],
            float_bytes[1],
            float_bytes[2],
            float_bytes[3],
            0x3F,
        ];
        let ack_apdu = dissect_bacnet_apdu(&ack_apdu_bytes).expect("Dissect ReadPropertyAck");
        assert_eq!(ack_apdu.pdu_type_name, "Complex-ACK");
        match ack_apdu.service {
            BacnetService::ReadPropertyAck {
                object,
                property_id,
                value,
                ..
            } => {
                assert_eq!(object.object_type, BacnetObjectType::AnalogInput);
                assert_eq!(object.instance, 1);
                assert_eq!(property_id, 85);
                assert!((value.unwrap() - 23.5).abs() < 0.01);
            }
            _ => panic!("Expected ReadPropertyAck"),
        }
    }

    proptest::proptest! {
        #[test]
        fn fuzz_bacnet_dissector_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = dissect_bacnet_mstp(&data);
            let _ = calculate_bacnet_crc8(&data);
        }
    }
}
