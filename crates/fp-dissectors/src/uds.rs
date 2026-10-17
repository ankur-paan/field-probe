use serde::{Deserialize, Serialize};

/// ISO 14229 Negative Response Codes (NRC)
pub fn uds_nrc_description(nrc: u8) -> &'static str {
    match nrc {
        0x10 => "GeneralReject",
        0x11 => "ServiceNotSupported",
        0x12 => "SubFunctionNotSupported",
        0x13 => "IncorrectMessageLengthOrInvalidFormat",
        0x14 => "ResponseTooLong",
        0x21 => "BusyRepeatRequest",
        0x22 => "ConditionsNotCorrect",
        0x24 => "RequestSequenceError",
        0x31 => "RequestOutOfRange",
        0x33 => "SecurityAccessDenied",
        0x35 => "InvalidKey",
        0x36 => "ExceedNumberOfAttempts",
        0x37 => "RequiredTimeDelayNotExpired",
        0x78 => "RequestCorrectlyReceivedResponsePending",
        0x7E => "SubFunctionNotSupportedInActiveSession",
        0x7F => "ServiceNotSupportedInActiveSession",
        _ => "UnknownNegativeResponseCode",
    }
}

/// Standard Data Identifier (DID) lookup table per ISO 14229-1 Annex C
pub fn uds_did_name(did: u16) -> Option<&'static str> {
    match did {
        0xF180 => Some("BootSoftwareIdentification"),
        0xF181 => Some("ApplicationSoftwareIdentification"),
        0xF182 => Some("ApplicationDataIdentification"),
        0xF186 => Some("ActiveDiagnosticSession"),
        0xF187 => Some("VehicleManufacturerSparePartNumber"),
        0xF188 => Some("VehicleManufacturerECUSoftwareNumber"),
        0xF189 => Some("VehicleManufacturerECUSoftwareVersionNumber"),
        0xF190 => Some("VIN"),
        0xF191 => Some("VehicleManufacturerECUHardwareNumber"),
        0xF192 => Some("SystemSupplierECUHardwareNumber"),
        0xF193 => Some("SystemSupplierECUHardwareVersionNumber"),
        0xF194 => Some("SystemSupplierECUSoftwareNumber"),
        0xF195 => Some("SystemSupplierECUSoftwareVersionNumber"),
        0xF197 => Some("SystemSupplierIdentifier"),
        0xF19E => Some("ASAM_ODX_File_Identifier"),
        _ => None,
    }
}

/// Standard 3-byte Diagnostic Trouble Code with status mask (ISO 14229 / ISO 15031-6)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdsDtc {
    /// 5-character SAE trouble code string (e.g. "P0100", "U0100")
    pub code: String,
    /// 1-byte Failure Mode Indicator (FMI) / Fault Type Byte (FTB)
    pub fmi: u8,
    /// 1-byte DTC Status bitmask
    pub status_mask: u8,
    /// True if bit 0 (testFailed) is active
    pub test_failed: bool,
    /// True if bit 2 (pendingDTC) is active
    pub pending: bool,
    /// True if bit 3 (confirmedDTC) is active
    pub confirmed: bool,
    /// True if bit 7 (warningIndicatorRequested) is active
    pub warning_indicator: bool,
}

impl UdsDtc {
    /// Parse raw 3-byte DTC code plus 1-byte status mask into structured representation
    pub fn parse(b0: u8, b1: u8, fmi: u8, status_mask: u8) -> Self {
        let prefix = match (b0 >> 6) & 0x03 {
            0 => 'P',
            1 => 'C',
            2 => 'B',
            3 => 'U',
            _ => unreachable!(),
        };

        let second_val = (b0 >> 4) & 0x03;
        let second_char = match second_val {
            0 => '0',
            1 => '1',
            2 => '2',
            3 => '3',
            _ => unreachable!(),
        };

        let third_char = format!("{:X}", b0 & 0x0F).chars().next().unwrap_or('0');
        let fourth_char = format!("{:X}", (b1 >> 4) & 0x0F)
            .chars()
            .next()
            .unwrap_or('0');
        let fifth_char = format!("{:X}", b1 & 0x0F).chars().next().unwrap_or('0');

        let code = format!(
            "{}{}{}{}{}",
            prefix, second_char, third_char, fourth_char, fifth_char
        );

        Self {
            code,
            fmi,
            status_mask,
            test_failed: (status_mask & 0x01) != 0,
            pending: (status_mask & 0x04) != 0,
            confirmed: (status_mask & 0x08) != 0,
            warning_indicator: (status_mask & 0x80) != 0,
        }
    }

    /// Parse contiguous sequence of 4-byte UDS DTC records (3 bytes DTC + 1 byte status mask)
    pub fn parse_list(data: &[u8]) -> Vec<Self> {
        let mut dtcs = Vec::new();
        let mut i = 0;
        while i + 3 < data.len() {
            let b0 = data[i];
            let b1 = data[i + 1];
            let fmi = data[i + 2];
            let status = data[i + 3];
            dtcs.push(Self::parse(b0, b1, fmi, status));
            i += 4;
        }
        dtcs
    }
}

/// Structured representation of parsed ISO 14229 (UDS) message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdsMessage {
    DiagnosticSessionControl {
        session_type: u8,
    },
    DiagnosticSessionControlResponse {
        session_type: u8,
        p2_server_max_ms: Option<u16>,
    },
    EcuReset {
        reset_type: u8,
    },
    ClearDiagnosticInformation {
        dtc_group: u32,
    },
    ReadDtcInformation {
        sub_function: u8,
        status_mask: u8,
    },
    ReadDtcInformationResponse {
        sub_function: u8,
        dtc_status_availability_mask: u8,
        dtcs: Vec<UdsDtc>,
    },
    ReadDataByIdentifier {
        dids: Vec<u16>,
    },
    ReadDataByIdentifierResponse {
        did: u16,
        data: Vec<u8>,
    },
    SecurityAccess {
        sub_function: u8,
        data: Vec<u8>,
    },
    SecurityAccessResponse {
        sub_function: u8,
        seed_or_key: Vec<u8>,
    },
    WriteDataByIdentifier {
        did: u16,
        data: Vec<u8>,
    },
    InputOutputControlByIdentifier {
        did: u16,
        control_option: u8,
        control_state: Vec<u8>,
    },
    InputOutputControlByIdentifierResponse {
        did: u16,
        control_status_record: Vec<u8>,
    },
    RoutineControl {
        routine_type: u8,
        routine_id: u16,
        routine_control_option_record: Vec<u8>,
    },
    RoutineControlResponse {
        routine_type: u8,
        routine_id: u16,
        routine_status_record: Vec<u8>,
    },
    RequestDownload {
        data_format_id: u8,
        address_and_length_format_id: u8,
        memory_address: u64,
        memory_size: u64,
    },
    RequestDownloadResponse {
        max_number_of_block_length: Option<usize>,
    },
    RequestUpload {
        data_format_id: u8,
        address_and_length_format_id: u8,
        memory_address: u64,
        memory_size: u64,
    },
    RequestUploadResponse {
        max_number_of_block_length: Option<usize>,
    },
    TransferData {
        block_sequence_counter: u8,
        data: Vec<u8>,
    },
    TransferDataResponse {
        block_sequence_counter: u8,
        data: Vec<u8>,
    },
    RequestTransferExit {
        transfer_request_parameter_record: Vec<u8>,
    },
    RequestTransferExitResponse {
        transfer_response_parameter_record: Vec<u8>,
    },
    TesterPresent {
        suppress_pos_rsp: bool,
    },
    TesterPresentResponse,
    NegativeResponse {
        rejected_sid: u8,
        nrc: u8,
        nrc_description: String,
    },
    RawService {
        sid: u8,
        data: Vec<u8>,
    },
}

/// Helper to parse variable-length address and size records
fn parse_address_and_size(format_id: u8, slice: &[u8]) -> (u64, u64) {
    let size_len = ((format_id >> 4) & 0x0F) as usize;
    let addr_len = (format_id & 0x0F) as usize;

    let mut addr = 0u64;
    for &b in slice.iter().take(addr_len) {
        addr = (addr << 8) | (b as u64);
    }

    let mut size = 0u64;
    for &b in slice.iter().skip(addr_len).take(size_len) {
        size = (size << 8) | (b as u64);
    }

    (addr, size)
}

/// Dissect a reassembled ISO-TP application payload into an ISO 14229 UDS message
pub fn dissect_uds(payload: &[u8]) -> Option<UdsMessage> {
    if payload.is_empty() {
        return None;
    }

    let sid = payload[0];

    match sid {
        // 0x10: DiagnosticSessionControl
        0x10 => {
            let session_type = payload.get(1).copied().unwrap_or(0x01);
            Some(UdsMessage::DiagnosticSessionControl { session_type })
        }

        // 0x50: DiagnosticSessionControl Positive Response
        0x50 => {
            let session_type = payload.get(1).copied().unwrap_or(0x01);
            let p2 = if payload.len() >= 4 {
                Some(((payload[2] as u16) << 8) | (payload[3] as u16))
            } else {
                None
            };
            Some(UdsMessage::DiagnosticSessionControlResponse {
                session_type,
                p2_server_max_ms: p2,
            })
        }

        // 0x11: EcuReset
        0x11 => {
            let reset_type = payload.get(1).copied().unwrap_or(0x01);
            Some(UdsMessage::EcuReset { reset_type })
        }

        // 0x14: ClearDiagnosticInformation
        0x14 => {
            if payload.len() >= 4 {
                let dtc =
                    ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);
                Some(UdsMessage::ClearDiagnosticInformation { dtc_group: dtc })
            } else {
                Some(UdsMessage::ClearDiagnosticInformation {
                    dtc_group: 0xFFFFFF,
                })
            }
        }

        // 0x19: ReadDtcInformation Request
        0x19 => {
            let sub_function = payload.get(1).copied().unwrap_or(0x02);
            let status_mask = payload.get(2).copied().unwrap_or(0xFF);
            Some(UdsMessage::ReadDtcInformation {
                sub_function,
                status_mask,
            })
        }

        // 0x59: ReadDtcInformation Positive Response
        0x59 => {
            let sub_function = payload.get(1).copied().unwrap_or(0x02);
            let dtc_status_availability_mask = payload.get(2).copied().unwrap_or(0xFF);
            let dtcs = if payload.len() > 3 {
                UdsDtc::parse_list(&payload[3..])
            } else {
                Vec::new()
            };
            Some(UdsMessage::ReadDtcInformationResponse {
                sub_function,
                dtc_status_availability_mask,
                dtcs,
            })
        }

        // 0x22: ReadDataByIdentifier
        0x22 => {
            let mut dids = Vec::new();
            let mut i = 1;
            while i + 1 < payload.len() {
                let did = ((payload[i] as u16) << 8) | (payload[i + 1] as u16);
                dids.push(did);
                i += 2;
            }
            Some(UdsMessage::ReadDataByIdentifier { dids })
        }

        // 0x62: ReadDataByIdentifier Positive Response
        0x62 => {
            if payload.len() >= 3 {
                let did = ((payload[1] as u16) << 8) | (payload[2] as u16);
                let data = payload[3..].to_vec();
                Some(UdsMessage::ReadDataByIdentifierResponse { did, data })
            } else {
                None
            }
        }

        // 0x27: SecurityAccess
        0x27 => {
            let sub_function = payload.get(1).copied().unwrap_or(0x01);
            let data = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            Some(UdsMessage::SecurityAccess { sub_function, data })
        }

        // 0x67: SecurityAccess Positive Response
        0x67 => {
            let sub_function = payload.get(1).copied().unwrap_or(0x01);
            let seed_or_key = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            Some(UdsMessage::SecurityAccessResponse {
                sub_function,
                seed_or_key,
            })
        }

        // 0x2E: WriteDataByIdentifier
        0x2E => {
            if payload.len() >= 3 {
                let did = ((payload[1] as u16) << 8) | (payload[2] as u16);
                let data = payload[3..].to_vec();
                Some(UdsMessage::WriteDataByIdentifier { did, data })
            } else {
                None
            }
        }

        // 0x2F: InputOutputControlByIdentifier
        0x2F => {
            if payload.len() >= 4 {
                let did = ((payload[1] as u16) << 8) | (payload[2] as u16);
                let control_option = payload[3];
                let control_state = payload[4..].to_vec();
                Some(UdsMessage::InputOutputControlByIdentifier {
                    did,
                    control_option,
                    control_state,
                })
            } else {
                None
            }
        }

        // 0x6F: InputOutputControlByIdentifier Positive Response
        0x6F => {
            if payload.len() >= 3 {
                let did = ((payload[1] as u16) << 8) | (payload[2] as u16);
                let control_status_record = payload[3..].to_vec();
                Some(UdsMessage::InputOutputControlByIdentifierResponse {
                    did,
                    control_status_record,
                })
            } else {
                None
            }
        }

        // 0x31: RoutineControl Request
        0x31 => {
            if payload.len() >= 4 {
                let routine_type = payload[1];
                let routine_id = ((payload[2] as u16) << 8) | (payload[3] as u16);
                let routine_control_option_record = payload[4..].to_vec();
                Some(UdsMessage::RoutineControl {
                    routine_type,
                    routine_id,
                    routine_control_option_record,
                })
            } else {
                None
            }
        }

        // 0x71: RoutineControl Positive Response
        0x71 => {
            if payload.len() >= 4 {
                let routine_type = payload[1];
                let routine_id = ((payload[2] as u16) << 8) | (payload[3] as u16);
                let routine_status_record = payload[4..].to_vec();
                Some(UdsMessage::RoutineControlResponse {
                    routine_type,
                    routine_id,
                    routine_status_record,
                })
            } else {
                None
            }
        }

        // 0x34: RequestDownload
        0x34 => {
            if payload.len() >= 3 {
                let data_format_id = payload[1];
                let address_and_length_format_id = payload[2];
                let (memory_address, memory_size) =
                    parse_address_and_size(address_and_length_format_id, &payload[3..]);
                Some(UdsMessage::RequestDownload {
                    data_format_id,
                    address_and_length_format_id,
                    memory_address,
                    memory_size,
                })
            } else {
                None
            }
        }

        // 0x74: RequestDownload Positive Response
        0x74 => {
            let max_block = if payload.len() >= 3 {
                let mut len = 0usize;
                for b in &payload[2..] {
                    len = (len << 8) | (*b as usize);
                }
                Some(len)
            } else {
                None
            };
            Some(UdsMessage::RequestDownloadResponse {
                max_number_of_block_length: max_block,
            })
        }

        // 0x35: RequestUpload
        0x35 => {
            if payload.len() >= 3 {
                let data_format_id = payload[1];
                let address_and_length_format_id = payload[2];
                let (memory_address, memory_size) =
                    parse_address_and_size(address_and_length_format_id, &payload[3..]);
                Some(UdsMessage::RequestUpload {
                    data_format_id,
                    address_and_length_format_id,
                    memory_address,
                    memory_size,
                })
            } else {
                None
            }
        }

        // 0x75: RequestUpload Positive Response
        0x75 => {
            let max_block = if payload.len() >= 3 {
                let mut len = 0usize;
                for b in &payload[2..] {
                    len = (len << 8) | (*b as usize);
                }
                Some(len)
            } else {
                None
            };
            Some(UdsMessage::RequestUploadResponse {
                max_number_of_block_length: max_block,
            })
        }

        // 0x36: TransferData Request
        0x36 => {
            if payload.len() >= 2 {
                let block_sequence_counter = payload[1];
                let data = payload[2..].to_vec();
                Some(UdsMessage::TransferData {
                    block_sequence_counter,
                    data,
                })
            } else {
                None
            }
        }

        // 0x76: TransferData Positive Response
        0x76 => {
            if payload.len() >= 2 {
                let block_sequence_counter = payload[1];
                let data = payload[2..].to_vec();
                Some(UdsMessage::TransferDataResponse {
                    block_sequence_counter,
                    data,
                })
            } else {
                None
            }
        }

        // 0x37: RequestTransferExit Request
        0x37 => {
            let transfer_request_parameter_record = if payload.len() > 1 {
                payload[1..].to_vec()
            } else {
                Vec::new()
            };
            Some(UdsMessage::RequestTransferExit {
                transfer_request_parameter_record,
            })
        }

        // 0x77: RequestTransferExit Positive Response
        0x77 => {
            let transfer_response_parameter_record = if payload.len() > 1 {
                payload[1..].to_vec()
            } else {
                Vec::new()
            };
            Some(UdsMessage::RequestTransferExitResponse {
                transfer_response_parameter_record,
            })
        }

        // 0x3E: TesterPresent
        0x3E => {
            let sub = payload.get(1).copied().unwrap_or(0x00);
            let suppress_pos_rsp = (sub & 0x80) != 0;
            Some(UdsMessage::TesterPresent { suppress_pos_rsp })
        }

        // 0x7E: TesterPresent Positive Response
        0x7E => Some(UdsMessage::TesterPresentResponse),

        // 0x7F: NegativeResponse
        0x7F => {
            if payload.len() >= 3 {
                let rejected_sid = payload[1];
                let nrc = payload[2];
                let nrc_description = uds_nrc_description(nrc).to_string();
                Some(UdsMessage::NegativeResponse {
                    rejected_sid,
                    nrc,
                    nrc_description,
                })
            } else {
                None
            }
        }

        // Fallback for other valid SIDs
        _ => Some(UdsMessage::RawService {
            sid,
            data: payload[1..].to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dissect_read_did() {
        // 0x22, DID 0xF190 (VIN), DID 0xF189 (SW Version)
        let query = [0x22, 0xF1, 0x90, 0xF1, 0x89];
        let msg = dissect_uds(&query).expect("Parsed UDS");
        assert_eq!(
            msg,
            UdsMessage::ReadDataByIdentifier {
                dids: vec![0xF190, 0xF189]
            }
        );
        assert_eq!(uds_did_name(0xF190), Some("VIN"));
        assert_eq!(
            uds_did_name(0xF189),
            Some("VehicleManufacturerECUSoftwareVersionNumber")
        );

        // Positive Response: 0x62, DID 0xF190, "WBA..."
        let resp = [0x62, 0xF1, 0x90, 0x57, 0x42, 0x41];
        let msg_resp = dissect_uds(&resp).expect("Parsed UDS response");
        assert_eq!(
            msg_resp,
            UdsMessage::ReadDataByIdentifierResponse {
                did: 0xF190,
                data: vec![0x57, 0x42, 0x41],
            }
        );
    }

    #[test]
    fn test_dissect_routine_control() {
        // 0x31 (RoutineControl), startRoutine (0x01), routineId 0x0203 (Check Memory), option [0x01, 0x02]
        let req = [0x31, 0x01, 0x02, 0x03, 0x01, 0x02];
        let msg = dissect_uds(&req).expect("Parsed RoutineControl");
        assert_eq!(
            msg,
            UdsMessage::RoutineControl {
                routine_type: 0x01,
                routine_id: 0x0203,
                routine_control_option_record: vec![0x01, 0x02],
            }
        );

        // 0x71 (Positive response), routineId 0x0203, status 0x00 (Success)
        let resp = [0x71, 0x01, 0x02, 0x03, 0x00];
        let msg_resp = dissect_uds(&resp).unwrap();
        assert_eq!(
            msg_resp,
            UdsMessage::RoutineControlResponse {
                routine_type: 0x01,
                routine_id: 0x0203,
                routine_status_record: vec![0x00],
            }
        );
    }

    #[test]
    fn test_dissect_flashing_services() {
        // 0x34 RequestDownload: dataFormat 0x00, formatId 0x44 (4B addr, 4B size), addr 0x00010000, size 0x00004000
        let req_dl = [
            0x34, 0x00, 0x44, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
        ];
        let msg = dissect_uds(&req_dl).expect("Parsed RequestDownload");
        assert_eq!(
            msg,
            UdsMessage::RequestDownload {
                data_format_id: 0x00,
                address_and_length_format_id: 0x44,
                memory_address: 0x00010000,
                memory_size: 0x00004000,
            }
        );

        // 0x36 TransferData: block counter 1, payload [0xDE, 0xAD, 0xBE, 0xEF]
        let transfer = [0x36, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            dissect_uds(&transfer).unwrap(),
            UdsMessage::TransferData {
                block_sequence_counter: 0x01,
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }
        );

        // 0x37 RequestTransferExit
        assert_eq!(
            dissect_uds(&[0x37]).unwrap(),
            UdsMessage::RequestTransferExit {
                transfer_request_parameter_record: vec![],
            }
        );
    }

    #[test]
    fn test_dissect_read_dtc_information_response() {
        // 0x59, subfunction 0x02, availability mask 0xFF, DTC: P0100 (0x01, 0x00), FMI 0x16, status 0x29 (confirmed + testFailed)
        let dtc_resp = [0x59, 0x02, 0xFF, 0x01, 0x00, 0x16, 0x29];
        let msg = dissect_uds(&dtc_resp).expect("Parsed DTC response");
        match msg {
            UdsMessage::ReadDtcInformationResponse {
                sub_function,
                dtc_status_availability_mask,
                dtcs,
            } => {
                assert_eq!(sub_function, 0x02);
                assert_eq!(dtc_status_availability_mask, 0xFF);
                assert_eq!(dtcs.len(), 1);
                assert_eq!(dtcs[0].code, "P0100");
                assert_eq!(dtcs[0].fmi, 0x16);
                assert!(dtcs[0].test_failed);
                assert!(dtcs[0].confirmed);
            }
            _ => panic!("Expected ReadDtcInformationResponse"),
        }
    }

    #[test]
    fn test_dissect_negative_response() {
        // 0x7F, Rejected SID 0x22, NRC 0x33 (SecurityAccessDenied)
        let nack = [0x7F, 0x22, 0x33];
        let msg = dissect_uds(&nack).expect("Parsed negative response");
        assert_eq!(
            msg,
            UdsMessage::NegativeResponse {
                rejected_sid: 0x22,
                nrc: 0x33,
                nrc_description: "SecurityAccessDenied".to_string(),
            }
        );
    }

    #[test]
    fn test_dissect_security_access() {
        // Request Seed: 0x27, Sub 0x01
        let req_seed = [0x27, 0x01];
        assert_eq!(
            dissect_uds(&req_seed).unwrap(),
            UdsMessage::SecurityAccess {
                sub_function: 0x01,
                data: vec![]
            }
        );

        // Seed Response: 0x67, Sub 0x01, Seed = [0xAA, 0xBB, 0xCC, 0xDD]
        let resp_seed = [0x67, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(
            dissect_uds(&resp_seed).unwrap(),
            UdsMessage::SecurityAccessResponse {
                sub_function: 0x01,
                seed_or_key: vec![0xAA, 0xBB, 0xCC, 0xDD]
            }
        );
    }
}
