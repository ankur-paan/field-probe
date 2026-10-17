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
    timeout_us: u64,
}

impl IsoTpReassembler {
    pub fn new(timeout_us: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            timeout_us,
        }
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
                let payload_len = if dl == 0 && data.len() > 8 {
                    // CAN-FD escape: DLC byte in data[1]
                    if data.len() < 2 {
                        return Some(Err(IsoTpError::InvalidLength));
                    }
                    data[1] as usize
                } else {
                    dl
                };

                let offset = if dl == 0 && data.len() > 8 { 2 } else { 1 };
                if data.len() < offset + payload_len {
                    return Some(Err(IsoTpError::InvalidLength));
                }

                Some(Ok(data[offset..offset + payload_len].to_vec()))
            }

            // 0x1: First Frame (FF)
            0x1 => {
                if data.len() < 8 {
                    return Some(Err(IsoTpError::InvalidLength));
                }
                let total_len = (((pci_byte & 0x0F) as usize) << 8) | (data[1] as usize);
                if total_len < 8 {
                    return Some(Err(IsoTpError::InvalidLength));
                }

                let mut payload = Vec::with_capacity(total_len);
                payload.extend_from_slice(&data[2..8]);

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
                session.payload.extend_from_slice(&data[1..1 + bytes_in_frame]);

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
                // Flow control frames do not carry application payload
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
        let pdu = reassembler.ingest_frame(id, &frame, 1000).expect("Complete PDU");
        assert_eq!(pdu.unwrap(), vec![0x22, 0xF1, 0x90]);
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
        let res = reassembler.ingest_frame(id, &cf2, 3000).expect("Completed multi-frame");
        let pdu = res.unwrap();

        assert_eq!(pdu.len(), 14);
        assert_eq!(pdu[0], 0x62); // Positive response to ReadDataByIdentifier
        assert_eq!(&pdu[1..3], &[0xF1, 0x90]); // VIN DID 0xF190
    }

    #[test]
    fn test_isotp_sequence_mismatch() {
        let mut reassembler = IsoTpReassembler::new(1_000_000);
        let id = CanId::Standard(0x7E8);

        let ff = [0x10, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(reassembler.ingest_frame(id, &ff, 1000), None);

        // Wrong sequence number (expected 1, got 3)
        let cf_wrong = [0x23, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D];
        let res = reassembler.ingest_frame(id, &cf_wrong, 2000).expect("Error returned");
        assert_eq!(res.unwrap_err(), IsoTpError::SequenceMismatch { expected: 1, got: 3 });
    }
}
