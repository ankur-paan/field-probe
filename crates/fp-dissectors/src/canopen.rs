use serde::{Deserialize, Serialize};

/// CANopen NMT Node State (as reported in Heartbeat / Bootup frames)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanOpenNmtState {
    Bootup = 0x00,
    Stopped = 0x04,
    Operational = 0x05,
    PreOperational = 0x7F,
    Unknown = 0xFF,
}

impl CanOpenNmtState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x00 => Self::Bootup,
            0x04 => Self::Stopped,
            0x05 => Self::Operational,
            0x7F => Self::PreOperational,
            _ => Self::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Bootup => "Boot-Up",
            Self::Stopped => "Stopped",
            Self::Operational => "Operational",
            Self::PreOperational => "Pre-Operational",
            Self::Unknown => "Unknown State",
        }
    }
}

/// CANopen Function Code based on the Pre-defined Connection Set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanOpenFunctionCode {
    Nmt = 0x0,
    SyncOrEmcy = 0x1,
    Time = 0x2,
    Tpdo1 = 0x3,
    Rpdo1 = 0x4,
    Tpdo2 = 0x5,
    Rpdo2 = 0x6,
    Tpdo3 = 0x7,
    Rpdo3 = 0x8,
    Tpdo4 = 0x9,
    Rpdo4 = 0xA,
    Tsdo = 0xB,
    Rsdo = 0xC,
    HeartbeatOrNodeGuarding = 0xE,
    Unknown = 0xF,
}

/// Dissected high-level CANopen message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CanOpenPayload {
    /// NMT Master Command (COB-ID 0x000)
    NmtCommand {
        cs: u8,
        cs_name: String,
        target_node_id: u8,
    },
    /// SYNC Object (COB-ID 0x080)
    Sync,
    /// Time Stamp (COB-ID 0x100)
    Time {
        millis_after_midnight: u32,
        days_since_jan_1984: u16,
    },
    /// Emergency Object (COB-ID 0x081..0x0FF)
    Emergency {
        node_id: u8,
        error_code: u16,
        error_register: u8,
        manufacturer_specific: [u8; 5],
    },
    /// Heartbeat or Node Guarding (COB-ID 0x700 + Node ID)
    Heartbeat {
        node_id: u8,
        state: CanOpenNmtState,
        state_name: String,
    },
    /// Process Data Object (PDO)
    Pdo {
        pdo_num: u8,
        is_transmit: bool,
        node_id: u8,
        data: Vec<u8>,
    },
    /// Service Data Object (SDO)
    Sdo {
        is_client_to_server: bool,
        node_id: u8,
        command_specifier: u8,
        multiplexer_index: u16,
        multiplexer_subindex: u8,
        data: Vec<u8>,
    },
    /// Raw unparsed CANopen frame
    Raw { cob_id: u16, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanOpenMessage {
    pub cob_id: u16,
    pub payload: CanOpenPayload,
}

/// Zero-panic CANopen frame dissector
pub fn dissect_canopen(cob_id: u16, data: &[u8]) -> Option<CanOpenMessage> {
    if cob_id == 0x000 {
        if data.len() >= 2 {
            let cs = data[0];
            let cs_name = match cs {
                0x01 => "Start Remote Node (Go Operational)",
                0x02 => "Stop Remote Node",
                0x80 => "Enter Pre-Operational",
                0x81 => "Reset Node",
                0x82 => "Reset Communication",
                _ => "Unknown NMT CS",
            };
            return Some(CanOpenMessage {
                cob_id,
                payload: CanOpenPayload::NmtCommand {
                    cs,
                    cs_name: cs_name.to_string(),
                    target_node_id: data[1],
                },
            });
        }
        return None;
    }

    if cob_id == 0x080 {
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Sync,
        });
    }

    if cob_id == 0x100 && data.len() >= 6 {
        let millis = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) & 0x0FFFFFFF;
        let days = u16::from_le_bytes([data[4], data[5]]);
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Time {
                millis_after_midnight: millis,
                days_since_jan_1984: days,
            },
        });
    }

    // Heartbeat / Node Guarding (0x700 .. 0x77F)
    if (0x700..=0x77F).contains(&cob_id) {
        let node_id = (cob_id - 0x700) as u8;
        let state_byte = *data.first().unwrap_or(&0xFF);
        let state = CanOpenNmtState::from_u8(state_byte);
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Heartbeat {
                node_id,
                state,
                state_name: state.name().to_string(),
            },
        });
    }

    // Emergency (0x081 .. 0x0FF)
    if (0x081..=0x0FF).contains(&cob_id) && data.len() >= 8 {
        let node_id = (cob_id - 0x080) as u8;
        let error_code = u16::from_le_bytes([data[0], data[1]]);
        let error_register = data[2];
        let mut mfg = [0u8; 5];
        mfg.copy_from_slice(&data[3..8]);
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Emergency {
                node_id,
                error_code,
                error_register,
                manufacturer_specific: mfg,
            },
        });
    }

    // SDO: Transmit (0x580..0x5FF) or Receive (0x600..0x67F)
    if (0x580..=0x5FF).contains(&cob_id) && data.len() >= 4 {
        let node_id = (cob_id - 0x580) as u8;
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Sdo {
                is_client_to_server: false,
                node_id,
                command_specifier: data[0],
                multiplexer_index: u16::from_le_bytes([data[1], data[2]]),
                multiplexer_subindex: data[3],
                data: data[4..].to_vec(),
            },
        });
    }
    if (0x600..=0x67F).contains(&cob_id) && data.len() >= 4 {
        let node_id = (cob_id - 0x600) as u8;
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Sdo {
                is_client_to_server: true,
                node_id,
                command_specifier: data[0],
                multiplexer_index: u16::from_le_bytes([data[1], data[2]]),
                multiplexer_subindex: data[3],
                data: data[4..].to_vec(),
            },
        });
    }

    // PDOs
    let (pdo_num, is_tx, base) = if (0x180..=0x1FF).contains(&cob_id) {
        (1, true, 0x180)
    } else if (0x200..=0x27F).contains(&cob_id) {
        (1, false, 0x200)
    } else if (0x280..=0x2FF).contains(&cob_id) {
        (2, true, 0x280)
    } else if (0x300..=0x37F).contains(&cob_id) {
        (2, false, 0x300)
    } else if (0x380..=0x3FF).contains(&cob_id) {
        (3, true, 0x380)
    } else if (0x400..=0x47F).contains(&cob_id) {
        (3, false, 0x400)
    } else if (0x480..=0x4FF).contains(&cob_id) {
        (4, true, 0x480)
    } else if (0x500..=0x57F).contains(&cob_id) {
        (4, false, 0x500)
    } else {
        return Some(CanOpenMessage {
            cob_id,
            payload: CanOpenPayload::Raw {
                cob_id,
                data: data.to_vec(),
            },
        });
    };

    let node_id = (cob_id - base) as u8;
    Some(CanOpenMessage {
        cob_id,
        payload: CanOpenPayload::Pdo {
            pdo_num,
            is_transmit: is_tx,
            node_id,
            data: data.to_vec(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_canopen_heartbeat_dissection() {
        let cob_id = 0x705; // Node 5 Heartbeat
        let data = [0x05]; // Operational
        let msg = dissect_canopen(cob_id, &data).expect("Heartbeat message");
        match msg.payload {
            CanOpenPayload::Heartbeat {
                node_id,
                state,
                state_name,
            } => {
                assert_eq!(node_id, 5);
                assert_eq!(state, CanOpenNmtState::Operational);
                assert_eq!(state_name, "Operational");
            }
            _ => panic!("Expected Heartbeat"),
        }
    }

    #[test]
    fn test_canopen_nmt_command() {
        let cob_id = 0x000;
        let data = [0x01, 0x00]; // Start all nodes
        let msg = dissect_canopen(cob_id, &data).expect("NMT Command");
        match msg.payload {
            CanOpenPayload::NmtCommand {
                cs, target_node_id, ..
            } => {
                assert_eq!(cs, 0x01);
                assert_eq!(target_node_id, 0);
            }
            _ => panic!("Expected NmtCommand"),
        }
    }

    #[test]
    fn test_canopen_sdo_upload() {
        let cob_id = 0x582; // Transmit SDO from Node 2
                            // CS: 0x4B (Upload response, 2 bytes), Index: 0x1018, Sub: 0x01, Data: 0x0403
        let data = [0x4B, 0x18, 0x10, 0x01, 0x03, 0x04, 0x00, 0x00];
        let msg = dissect_canopen(cob_id, &data).expect("SDO message");
        match msg.payload {
            CanOpenPayload::Sdo {
                is_client_to_server,
                node_id,
                multiplexer_index,
                multiplexer_subindex,
                ..
            } => {
                assert!(!is_client_to_server);
                assert_eq!(node_id, 2);
                assert_eq!(multiplexer_index, 0x1018);
                assert_eq!(multiplexer_subindex, 0x01);
            }
            _ => panic!("Expected SDO"),
        }
    }

    proptest::proptest! {
        #[test]
        fn fuzz_canopen_dissector_never_panics(cob_id in any::<u16>(), data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = dissect_canopen(cob_id, &data);
        }
    }
}
