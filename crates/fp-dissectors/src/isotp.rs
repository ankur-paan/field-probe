use fp_core::CanId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ISO 15765-2 Protocol Control Information (PCI) frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsoTpFrameType {
    SingleFrame,
    FirstFrame,
    ConsecutiveFrame,
    FlowControl,
}

/// Flow Control Status (ISO 15765-2 section 6.5.5)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    ContinueToSend,
    Wait,
    Overflow,
    Reserved(u8),
}

/// Flow Control parameters extracted from an ISO-TP Flow Control frame
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowControlInfo {
    pub flow_status: FlowStatus,
    pub block_size: u8,
    pub st_min_ms: f32,
}

/// Parse an ISO 15765-2 Flow Control (FC) frame payload
pub fn parse_flow_control(data: &[u8]) -> Option<FlowControlInfo> {
    if data.is_empty() || (data[0] >> 4) != 0x3 {
        return None;
    }
    let fs_raw = data[0] & 0x0F;
    let flow_status = match fs_raw {
        0 => FlowStatus::ContinueToSend,
        1 => FlowStatus::Wait,
        2 => FlowStatus::Overflow,
        other => FlowStatus::Reserved(other),
    };
    let block_size = data.get(1).copied().unwrap_or(0);
    let st_raw = data.get(2).copied().unwrap_or(0);
    let st_min_ms = if st_raw <= 0x7F {
        st_raw as f32
    } else if (0xF1..=0xF9).contains(&st_raw) {
        ((st_raw - 0xF0) as f32) * 0.1
    } else {
        0.0
    };
    Some(FlowControlInfo {
        flow_status,
        block_size,
        st_min_ms,
    })
}

/// ISO 15765-2 addressing formats across 11-bit and 29-bit CAN identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsoTpAddressing {
    /// Normal 11-bit addressing (e.g. 0x7E0 request / 0x7E8 response)
    Normal11Bit { can_id: u16 },
    /// Normal Fixed 29-bit addressing (ISO 15765-2 Section 7.3.3.2)
    /// Priority (3-bit), Target Address / PS (8-bit), Source Address / SA (8-bit)
    NormalFixed29Bit {
        priority: u8,
        target: u8,
        source: u8,
        is_functional: bool,
    },
    /// Extended 11-bit addressing with Target Address in payload byte 0 (N_TA)
    Extended11Bit { can_id: u16, target: u8 },
    /// Mixed 29-bit addressing (PF=0xCE) with Address Extension in payload byte 0 (N_AE)
    Mixed29Bit {
        priority: u8,
        target: u8,
        source: u8,
        address_extension: u8,
    },
}

/// Dissect CAN arbitration ID into ISO-TP addressing schema
pub fn parse_isotp_addressing(can_id: CanId, first_byte: Option<u8>) -> Option<IsoTpAddressing> {
    match can_id {
        CanId::Standard(id) => {
            if (0x7E0..=0x7EF).contains(&id) {
                Some(IsoTpAddressing::Normal11Bit { can_id: id })
            } else if let Some(target) = first_byte {
                Some(IsoTpAddressing::Extended11Bit { can_id: id, target })
            } else {
                Some(IsoTpAddressing::Normal11Bit { can_id: id })
            }
        }
        CanId::Extended(id) => {
            let priority = ((id >> 26) & 0x07) as u8;
            let pf = ((id >> 16) & 0xFF) as u8;
            let target = ((id >> 8) & 0xFF) as u8;
            let source = (id & 0xFF) as u8;

            if pf == 0xDA {
                Some(IsoTpAddressing::NormalFixed29Bit {
                    priority,
                    target,
                    source,
                    is_functional: false,
                })
            } else if pf == 0xDB {
                Some(IsoTpAddressing::NormalFixed29Bit {
                    priority,
                    target,
                    source,
                    is_functional: true,
                })
            } else if pf == 0xCE {
                let address_extension = first_byte.unwrap_or(0);
                Some(IsoTpAddressing::Mixed29Bit {
                    priority,
                    target,
                    source,
                    address_extension,
                })
            } else {
                None
            }
        }
    }
}

/// Errors encountered during ISO-TP transport reassembly
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsoTpError {
    InvalidLength,
    SequenceMismatch { expected: u8, got: u8 },
    UnexpectedConsecutiveFrame,
    BufferOverflow,
    Timeout,
}

/// Active multi-frame assembly session for a specific CAN arbitration ID
#[derive(Debug, Clone)]
struct AssemblySession {
    total_length: usize,
    payload: Vec<u8>,
    expected_sn: u8,
    last_timestamp_us: u64,
}

/// Zero-panic ISO 15765-2 ISO-TP packet reassembler
#[derive(Debug, Clone, Default)]
pub struct IsoTpReassembler {
    sessions: HashMap<CanId, AssemblySession>,
    last_flow_control: HashMap<CanId, FlowControlInfo>,
    timeout_us: u64,
}

impl IsoTpReassembler {
    pub fn new(timeout_us: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            last_flow_control: HashMap::new(),
            timeout_us,
        }
    }

    /// Retrieve the most recently observed Flow Control parameters for a CAN ID
    pub fn get_last_flow_control(&self, id: &CanId) -> Option<&FlowControlInfo> {
        self.last_flow_control.get(id)
    }

    /// Ingest a raw CAN frame. If a complete multi-frame or single-frame PDU is ready, returns Ok(payload).
    pub fn ingest_frame(
        &mut self,
        id: CanId,
        data: &[u8],
        timestamp_us: u64,
    ) -> Option<Result<Vec<u8>, IsoTpError>> {
        if data.is_empty() {
            return None;
        }

        // Clean up expired sessions
        let timeout = self.timeout_us;
        self.sessions
            .retain(|_, s| timestamp_us.saturating_sub(s.last_timestamp_us) <= timeout);

        let pci_byte = data[0];
        let pci_type = pci_byte >> 4;

        match pci_type {
            // 0x0: Single Frame (SF)
            0x0 => {
                let dl = (pci_byte & 0x0F) as usize;
                let (payload_len, offset) = if dl == 0 && data.len() > 8 {
                    // CAN-FD escape: DLC byte in data[1]
                    if data.len() < 2 {
                        return Some(Err(IsoTpError::InvalidLength));
                    }
                    (data[1] as usize, 2)
                } else {
                    (dl, 1)
                };

                if data.len() < offset + payload_len {
                    return Some(Err(IsoTpError::InvalidLength));
                }

                Some(Ok(data[offset..offset + payload_len].to_vec()))
            }

            // 0x1: First Frame (FF)
            0x1 => {
                let (total_len, header_offset) =
                    if (pci_byte & 0x0F) == 0 && data.len() >= 6 && data[1] == 0 {
                        // CAN-FD 32-bit extended length (ISO 15765-2:2016)
                        let len = ((data[2] as usize) << 24)
                            | ((data[3] as usize) << 16)
                            | ((data[4] as usize) << 8)
                            | (data[5] as usize);
                        (len, 6)
                    } else {
                        if data.len() < 8 {
                            return Some(Err(IsoTpError::InvalidLength));
                        }
                        let len = (((pci_byte & 0x0F) as usize) << 8) | (data[1] as usize);
                        (len, 2)
                    };

                if total_len < 8 {
                    return Some(Err(IsoTpError::InvalidLength));
                }

                let first_chunk_len = (data.len() - header_offset).min(total_len);
                let mut payload = Vec::with_capacity(total_len.min(1024 * 1024));
                payload.extend_from_slice(&data[header_offset..header_offset + first_chunk_len]);

                self.sessions.insert(
                    id,
                    AssemblySession {
                        total_length: total_len,
                        payload,
                        expected_sn: 1,
                        last_timestamp_us: timestamp_us,
                    },
                );
                None
            }

            // 0x2: Consecutive Frame (CF)
            0x2 => {
                let sn = pci_byte & 0x0F;
                let session = match self.sessions.get_mut(&id) {
                    Some(s) => s,
                    None => return Some(Err(IsoTpError::UnexpectedConsecutiveFrame)),
                };

                if sn != session.expected_sn {
                    let err = IsoTpError::SequenceMismatch {
                        expected: session.expected_sn,
                        got: sn,
                    };
                    self.sessions.remove(&id);
                    return Some(Err(err));
                }

                session.expected_sn = (session.expected_sn + 1) % 16;
                session.last_timestamp_us = timestamp_us;

                let remaining = session.total_length.saturating_sub(session.payload.len());
                let bytes_in_frame = (data.len() - 1).min(remaining);
                session
                    .payload
                    .extend_from_slice(&data[1..1 + bytes_in_frame]);

                if session.payload.len() >= session.total_length {
                    if let Some(completed) = self.sessions.remove(&id) {
                        Some(Ok(completed.payload))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }

            // 0x3: Flow Control (FC)
            0x3 => {
                if let Some(fc) = parse_flow_control(data) {
                    self.last_flow_control.insert(id, fc);
                }
                None
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isotp_single_frame() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E8);
        // SF with 3 bytes: 0x03, 0x22, 0xF1, 0x90
        let frame = [0x03, 0x22, 0xF1, 0x90, 0xAA, 0xAA, 0xAA, 0xAA];
        let pdu = reassembler
            .ingest_frame(id, &frame, 1000)
            .expect("Complete PDU");
        assert_eq!(pdu.unwrap(), vec![0x22, 0xF1, 0x90]);
    }

    #[test]
    fn test_isotp_canfd_single_frame() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E8);
        // CAN-FD SF: 0x00, DLC=12, followed by 12 bytes
        let mut frame = vec![0x00, 12];
        frame.extend_from_slice(&[0x62, 0xF1, 0x90, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        frame.resize(64, 0xCC);

        let pdu = reassembler
            .ingest_frame(id, &frame, 1000)
            .expect("Complete PDU")
            .unwrap();
        assert_eq!(pdu.len(), 12);
        assert_eq!(&pdu[0..3], &[0x62, 0xF1, 0x90]);
    }

    #[test]
    fn test_isotp_multi_frame_assembly() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E8);

        // First Frame: Length = 14 bytes (0x00E) -> [0x10, 0x0E, d0, d1, d2, d3, d4, d5]
        let ff = [0x10, 0x0E, 0x62, 0xF1, 0x90, 0x57, 0x42, 0x41];
        assert_eq!(reassembler.ingest_frame(id, &ff, 1000), None);

        // Consecutive Frame 1: SN = 1 -> [0x21, d6, d7, d8, d9, d10, d11, d12]
        let cf1 = [0x21, 0x33, 0x31, 0x41, 0x5A, 0x30, 0x30, 0x30];
        assert_eq!(reassembler.ingest_frame(id, &cf1, 2000), None);

        // Consecutive Frame 2: SN = 2 -> [0x22, d13, 0xAA, ...]
        let cf2 = [0x22, 0x31, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        let res = reassembler
            .ingest_frame(id, &cf2, 3000)
            .expect("Completed multi-frame");
        let pdu = res.unwrap();

        assert_eq!(pdu.len(), 14);
        assert_eq!(pdu[0], 0x62); // Positive response to ReadDataByIdentifier
        assert_eq!(&pdu[1..3], &[0xF1, 0x90]); // VIN DID 0xF190
    }

    #[test]
    fn test_isotp_canfd_32bit_first_frame() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Extended(0x18DA00F1);

        // 32-bit CAN-FD First Frame: [0x10, 0x00, 0x00, 0x00, 0x00, 0x46] (70 bytes total length)
        let mut ff = vec![0x10, 0x00, 0x00, 0x00, 0x00, 0x46];
        ff.extend_from_slice(&[0x55; 58]); // 58 bytes initial chunk
        assert_eq!(reassembler.ingest_frame(id, &ff, 1000), None);

        // Consecutive Frame 1: [0x21, 12 bytes] -> 58 + 12 = 70 bytes complete!
        let mut cf1 = vec![0x21];
        cf1.extend_from_slice(&[0x77; 12]);
        let res = reassembler
            .ingest_frame(id, &cf1, 2000)
            .expect("Completed 32-bit multi-frame");
        let pdu = res.unwrap();
        assert_eq!(pdu.len(), 70);
        assert_eq!(pdu[0], 0x55);
        assert_eq!(pdu[58], 0x77);
    }

    #[test]
    fn test_isotp_flow_control_parsing() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E0);

        // FC Frame: [0x30, BS=8, STmin=0x14 (20 ms)]
        let fc_frame = [0x30, 0x08, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(reassembler.ingest_frame(id, &fc_frame, 1000), None);

        let fc_info = reassembler
            .get_last_flow_control(&id)
            .expect("Flow control captured");
        assert_eq!(fc_info.flow_status, FlowStatus::ContinueToSend);
        assert_eq!(fc_info.block_size, 8);
        assert_eq!(fc_info.st_min_ms, 20.0);

        // Test microsecond STmin: 0xF2 = 200 µs (0.2 ms)
        let fc_micro = parse_flow_control(&[0x30, 0x00, 0xF2]).unwrap();
        assert!((fc_micro.st_min_ms - 0.2).abs() < 1e-4);
    }

    #[test]
    fn test_isotp_29bit_addressing_modes() {
        // Physical request: 0x18DA00F1 (Priority 6, Target 0x00, Source 0xF1)
        let addr = parse_isotp_addressing(CanId::Extended(0x18DA00F1), None).unwrap();
        assert_eq!(
            addr,
            IsoTpAddressing::NormalFixed29Bit {
                priority: 6,
                target: 0x00,
                source: 0xF1,
                is_functional: false,
            }
        );

        // Functional broadcast: 0x18DB33F1
        let addr_func = parse_isotp_addressing(CanId::Extended(0x18DB33F1), None).unwrap();
        assert_eq!(
            addr_func,
            IsoTpAddressing::NormalFixed29Bit {
                priority: 6,
                target: 0x33,
                source: 0xF1,
                is_functional: true,
            }
        );
    }

    #[test]
    fn test_isotp_sequence_mismatch() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E8);

        let ff = [0x10, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(reassembler.ingest_frame(id, &ff, 1000), None);

        // Wrong sequence number (expected 1, got 3)
        let cf_wrong = [0x23, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D];
        let res = reassembler
            .ingest_frame(id, &cf_wrong, 2000)
            .expect("Error returned");
        assert_eq!(
            res.unwrap_err(),
            IsoTpError::SequenceMismatch {
                expected: 1,
                got: 3
            }
        );
    }
}
