use serde::{Deserialize, Serialize};

/// ASAM MCD-1 XCP Error Codes
pub fn xcp_error_name(code: u8) -> &'static str {
    match code {
        0x00 => "ERR_CMD_SYNCH",
        0x10 => "ERR_CMD_BUSY",
        0x20 => "ERR_CMD_UNKNOWN",
        0x21 => "ERR_CMD_SYNTAX",
        0x22 => "ERR_OUT_OF_RANGE",
        0x23 => "ERR_WRITE_PROTECTED",
        0x24 => "ERR_ACCESS_DENIED",
        0x25 => "ERR_ACCESS_LOCKED",
        0x26 => "ERR_PAGE_NOT_VALID",
        0x27 => "ERR_MODE_NOT_VALID",
        0x28 => "ERR_SEGMENT_NOT_VALID",
        0x29 => "ERR_SEQUENCE",
        0x2A => "ERR_DAQ_CONFIG",
        0x30 => "ERR_MEMORY_OVERFLOW",
        0x31 => "ERR_GENERIC",
        0x32 => "ERR_VERIFY",
        _ => "ERR_UNKNOWN",
    }
}

/// ASAM MCD-1 XCP (Universal Measurement and Calibration Protocol) Command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XcpCommand {
    Connect {
        mode: u8,
    },
    Disconnect,
    GetStatus,
    Synch,
    GetCommModeInfo,
    GetId {
        id_type: u8,
    },
    SetRequest {
        mode: u8,
        session_id: u16,
    },
    GetSeed {
        mode: u8,
        resource: u8,
    },
    Unlock {
        key: Vec<u8>,
    },
    SetMta {
        address: u32,
        address_extension: u8,
    },
    Upload {
        num_bytes: u8,
    },
    ShortUpload {
        num_bytes: u8,
        address: u32,
        address_extension: u8,
    },
    BuildChecksum {
        block_size: u32,
    },
    Download {
        num_bytes: u8,
        data: Vec<u8>,
    },
    ShortDownload {
        num_bytes: u8,
        address: u32,
        address_extension: u8,
        data: Vec<u8>,
    },
    ModifyBits {
        shift_value: u8,
        and_mask: u16,
        xor_mask: u16,
    },
    SetCalPage {
        mode: u8,
        logical_segment: u8,
        logical_page: u8,
    },
    GetCalPage {
        access_mode: u8,
        logical_segment: u8,
    },
    GenericCommand {
        pid: u8,
        data: Vec<u8>,
    },
}

/// ASAM MCD-1 XCP Response Packet
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XcpResponse {
    Positive { data: Vec<u8> },
    Error { error_code: u8, error_name: String },
    Event { event_code: u8, data: Vec<u8> },
}

/// CAN Calibration Protocol (CCP v2.1) Command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcpCommand {
    Connect {
        station_address: u16,
    },
    SetMta {
        mta_num: u8,
        address_extension: u8,
        address: u32,
    },
    Dnload {
        num_bytes: u8,
        data: Vec<u8>,
    },
    Upload {
        num_bytes: u8,
    },
    GetSeed {
        resource: u8,
    },
    Unlock {
        key: Vec<u8>,
    },
    Disconnect {
        command_type: u8,
        station_address: u16,
    },
    Generic {
        cmd: u8,
        data: Vec<u8>,
    },
}

/// CAN Calibration Protocol (CCP v2.1) Response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcpResponse {
    CommandReturnMessage {
        command_counter: u8,
        return_code: u8,
        data: Vec<u8>,
    },
}

/// Top-level calibration protocol container
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalibrationMessage {
    XcpCommand(XcpCommand),
    XcpResponse(XcpResponse),
    XcpDaq { daq_list_id: u8, data: Vec<u8> },
    CcpCommand(CcpCommand),
    CcpResponse(CcpResponse),
}

/// Dissect raw CAN data payload as ASAM MCD-1 XCP packet
pub fn dissect_xcp(data: &[u8], is_slave_response: bool) -> Option<CalibrationMessage> {
    if data.is_empty() {
        return None;
    }

    let pid = data[0];

    if is_slave_response {
        match pid {
            // 0xFF: Positive response (RES)
            0xFF => Some(CalibrationMessage::XcpResponse(XcpResponse::Positive {
                data: data[1..].to_vec(),
            })),
            // 0xFE: Error packet (ERR)
            0xFE => {
                let err_code = data.get(1).copied().unwrap_or(0x31);
                let err_name = xcp_error_name(err_code).to_string();
                Some(CalibrationMessage::XcpResponse(XcpResponse::Error {
                    error_code: err_code,
                    error_name: err_name,
                }))
            }
            // 0xFD: Event packet (EV)
            0xFD => {
                let ev_code = data.get(1).copied().unwrap_or(0);
                Some(CalibrationMessage::XcpResponse(XcpResponse::Event {
                    event_code: ev_code,
                    data: if data.len() > 2 {
                        data[2..].to_vec()
                    } else {
                        Vec::new()
                    },
                }))
            }
            // DTO DAQ packet
            _ => Some(CalibrationMessage::XcpDaq {
                daq_list_id: pid,
                data: data[1..].to_vec(),
            }),
        }
    } else {
        // Master Command (CTO)
        let cmd = match pid {
            0xFF => {
                let mode = data.get(1).copied().unwrap_or(0);
                XcpCommand::Connect { mode }
            }
            0xFE => XcpCommand::Disconnect,
            0xFD => XcpCommand::GetStatus,
            0xFC => XcpCommand::Synch,
            0xFB => XcpCommand::GetCommModeInfo,
            0xFA => {
                let id_type = data.get(1).copied().unwrap_or(0);
                XcpCommand::GetId { id_type }
            }
            0xF9 => {
                let mode = data.get(1).copied().unwrap_or(0);
                let session_id = if data.len() >= 4 {
                    u16::from_le_bytes([data[2], data[3]])
                } else {
                    0
                };
                XcpCommand::SetRequest { mode, session_id }
            }
            0xF8 => {
                let mode = data.get(1).copied().unwrap_or(0);
                let resource = data.get(2).copied().unwrap_or(0);
                XcpCommand::GetSeed { mode, resource }
            }
            0xF7 => {
                let key = if data.len() > 1 {
                    data[1..].to_vec()
                } else {
                    Vec::new()
                };
                XcpCommand::Unlock { key }
            }
            0xF6 => {
                let address_extension = data.get(2).copied().unwrap_or(0);
                let address = if data.len() >= 8 {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
                } else {
                    0
                };
                XcpCommand::SetMta {
                    address,
                    address_extension,
                }
            }
            0xF5 => {
                let num_bytes = data.get(1).copied().unwrap_or(0);
                XcpCommand::Upload { num_bytes }
            }
            0xF4 => {
                let num_bytes = data.get(1).copied().unwrap_or(0);
                let address_extension = data.get(2).copied().unwrap_or(0);
                let address = if data.len() >= 8 {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
                } else {
                    0
                };
                XcpCommand::ShortUpload {
                    num_bytes,
                    address,
                    address_extension,
                }
            }
            0xF3 => {
                let block_size = if data.len() >= 8 {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
                } else {
                    0
                };
                XcpCommand::BuildChecksum { block_size }
            }
            0xF0 => {
                let num_bytes = data.get(1).copied().unwrap_or(0);
                let payload = if data.len() > 2 {
                    data[2..].to_vec()
                } else {
                    Vec::new()
                };
                XcpCommand::Download {
                    num_bytes,
                    data: payload,
                }
            }
            0xED => {
                let num_bytes = data.get(1).copied().unwrap_or(0);
                let address_extension = data.get(2).copied().unwrap_or(0);
                let address = if data.len() >= 8 {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
                } else {
                    0
                };
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    Vec::new()
                };
                XcpCommand::ShortDownload {
                    num_bytes,
                    address,
                    address_extension,
                    data: payload,
                }
            }
            0xEC => {
                let shift_value = data.get(1).copied().unwrap_or(0);
                let and_mask = if data.len() >= 4 {
                    u16::from_le_bytes([data[2], data[3]])
                } else {
                    0
                };
                let xor_mask = if data.len() >= 6 {
                    u16::from_le_bytes([data[4], data[5]])
                } else {
                    0
                };
                XcpCommand::ModifyBits {
                    shift_value,
                    and_mask,
                    xor_mask,
                }
            }
            0xEB => {
                let mode = data.get(1).copied().unwrap_or(0);
                let logical_segment = data.get(2).copied().unwrap_or(0);
                let logical_page = data.get(3).copied().unwrap_or(0);
                XcpCommand::SetCalPage {
                    mode,
                    logical_segment,
                    logical_page,
                }
            }
            0xEA => {
                let access_mode = data.get(1).copied().unwrap_or(0);
                let logical_segment = data.get(2).copied().unwrap_or(0);
                XcpCommand::GetCalPage {
                    access_mode,
                    logical_segment,
                }
            }
            _ => XcpCommand::GenericCommand {
                pid,
                data: data[1..].to_vec(),
            },
        };
        Some(CalibrationMessage::XcpCommand(cmd))
    }
}

/// Dissect raw CAN data payload as CAN Calibration Protocol (CCP v2.1) packet
pub fn dissect_ccp(data: &[u8], is_slave_response: bool) -> Option<CalibrationMessage> {
    if data.is_empty() {
        return None;
    }

    if is_slave_response {
        // CCP Command Return Message (CRM)
        let pid = data[0];
        if pid == 0xFF {
            let return_code = data.get(1).copied().unwrap_or(0);
            let command_counter = data.get(2).copied().unwrap_or(0);
            let payload = if data.len() > 3 {
                data[3..].to_vec()
            } else {
                Vec::new()
            };
            Some(CalibrationMessage::CcpResponse(
                CcpResponse::CommandReturnMessage {
                    command_counter,
                    return_code,
                    data: payload,
                },
            ))
        } else {
            None
        }
    } else {
        // CCP Master Command Object (CRO)
        let cmd_code = data[0];
        let cmd = match cmd_code {
            0x01 => {
                let station_address = if data.len() >= 4 {
                    u16::from_le_bytes([data[2], data[3]])
                } else {
                    0
                };
                CcpCommand::Connect { station_address }
            }
            0x02 => {
                let mta_num = data.get(2).copied().unwrap_or(0);
                let address_extension = data.get(3).copied().unwrap_or(0);
                let address = if data.len() >= 8 {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
                } else {
                    0
                };
                CcpCommand::SetMta {
                    mta_num,
                    address_extension,
                    address,
                }
            }
            0x03 => {
                let num_bytes = data.get(2).copied().unwrap_or(0);
                let payload = if data.len() > 3 {
                    data[3..].to_vec()
                } else {
                    Vec::new()
                };
                CcpCommand::Dnload {
                    num_bytes,
                    data: payload,
                }
            }
            0x04 => {
                let num_bytes = data.get(2).copied().unwrap_or(0);
                CcpCommand::Upload { num_bytes }
            }
            0x0C => {
                let resource = data.get(2).copied().unwrap_or(0);
                CcpCommand::GetSeed { resource }
            }
            0x0D => {
                let key = if data.len() > 2 {
                    data[2..].to_vec()
                } else {
                    Vec::new()
                };
                CcpCommand::Unlock { key }
            }
            0x17 => {
                let command_type = data.get(2).copied().unwrap_or(0);
                let station_address = if data.len() >= 6 {
                    u16::from_le_bytes([data[4], data[5]])
                } else {
                    0
                };
                CcpCommand::Disconnect {
                    command_type,
                    station_address,
                }
            }
            _ => CcpCommand::Generic {
                cmd: cmd_code,
                data: data[1..].to_vec(),
            },
        };
        Some(CalibrationMessage::CcpCommand(cmd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xcp_connect_and_response() {
        // Master CONNECT: PID 0xFF, Mode 0x00
        let req = [0xFF, 0x00];
        let msg = dissect_xcp(&req, false).expect("Dissected XCP Connect");
        assert_eq!(
            msg,
            CalibrationMessage::XcpCommand(XcpCommand::Connect { mode: 0 })
        );

        // Slave RES: 0xFF, comm mode info, max cto/dto
        let resp = [0xFF, 0x14, 0x01, 0x08, 0x08, 0x00, 0x01, 0x00];
        let msg_resp = dissect_xcp(&resp, true).expect("Dissected XCP Positive Response");
        match msg_resp {
            CalibrationMessage::XcpResponse(XcpResponse::Positive { data }) => {
                assert_eq!(data.len(), 7);
                assert_eq!(data[0], 0x14);
            }
            _ => panic!("Expected XcpResponse::Positive"),
        }
    }

    #[test]
    fn test_xcp_error_packet() {
        // Slave ERR: PID 0xFE, ERR_ACCESS_LOCKED (0x25)
        let err_pkt = [0xFE, 0x25];
        let msg = dissect_xcp(&err_pkt, true).expect("Dissected XCP Error");
        assert_eq!(
            msg,
            CalibrationMessage::XcpResponse(XcpResponse::Error {
                error_code: 0x25,
                error_name: "ERR_ACCESS_LOCKED".to_string(),
            })
        );
    }

    #[test]
    fn test_xcp_set_mta_and_upload() {
        // Set MTA: 0xF6, 0x00, ext 0x00, 0x00, addr 0x20000000 (LE: 0x00, 0x00, 0x00, 0x20)
        let mta_cmd = [0xF6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
        let msg = dissect_xcp(&mta_cmd, false).expect("Dissected SetMta");
        assert_eq!(
            msg,
            CalibrationMessage::XcpCommand(XcpCommand::SetMta {
                address: 0x20000000,
                address_extension: 0,
            })
        );

        // Upload 4 bytes: 0xF5, 0x04
        let upload_cmd = [0xF5, 0x04];
        assert_eq!(
            dissect_xcp(&upload_cmd, false).unwrap(),
            CalibrationMessage::XcpCommand(XcpCommand::Upload { num_bytes: 4 })
        );
    }

    #[test]
    fn test_ccp_connect_and_crm() {
        // CCP Connect: CRO 0x01, CTR 0x01, station address 0x0039 (LE: 0x39, 0x00)
        let ccp_cro = [0x01, 0x01, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00];
        let msg = dissect_ccp(&ccp_cro, false).expect("Dissected CCP Connect");
        assert_eq!(
            msg,
            CalibrationMessage::CcpCommand(CcpCommand::Connect {
                station_address: 0x0039
            })
        );

        // CCP CRM: PID 0xFF, ReturnCode 0x00 (SUCCESS), CTR 0x01
        let ccp_crm = [0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let msg_resp = dissect_ccp(&ccp_crm, true).expect("Dissected CCP CRM");
        assert_eq!(
            msg_resp,
            CalibrationMessage::CcpResponse(CcpResponse::CommandReturnMessage {
                command_counter: 1,
                return_code: 0,
                data: vec![0, 0, 0, 0, 0],
            })
        );
    }
}
