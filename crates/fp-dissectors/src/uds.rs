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
                let dtc = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);
                Some(UdsMessage::ClearDiagnosticInformation { dtc_group: dtc })
            } else {
                Some(UdsMessage::ClearDiagnosticInformation { dtc_group: 0xFFFFFF })
            }
        }

        // 0x19: ReadDtcInformation
        0x19 => {
            let sub_function = payload.get(1).copied().unwrap_or(0x02);
            let status_mask = payload.get(2).copied().unwrap_or(0xFF);
            Some(UdsMessage::ReadDtcInformation {
                sub_function,
                status_mask,
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
