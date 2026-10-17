use fp_core::{CanFrame, CanId};
use serde::{Deserialize, Serialize};

/// High-level industrial protocol classified on a CAN network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanProtocolCandidate {
    J1939,
    CanOpen,
    IsoTpUds,
    GenericCan20,
    Unknown,
}

/// Classify CAN protocol based on frame heuristics (J1939 PGNs, CANopen COB-IDs, UDS IDs).
pub fn classify_can_frame(frame: &CanFrame) -> CanProtocolCandidate {
    match frame.id {
        CanId::Extended(id) => {
            // J1939 uses 29-bit extended IDs
            // Parameter Group Number (PGN) is bits 8..25
            let pgn = (id >> 8) & 0x3FFFF;
            if pgn != 0 {
                CanProtocolCandidate::J1939
            } else {
                CanProtocolCandidate::GenericCan20
            }
        }
        CanId::Standard(id) => {
            // ISO-TP / UDS diagnostic IDs (0x7DF = broadcast, 0x7E0..0x7EF = node requests/responses)
            if id == 0x7DF || (0x7E0..=0x7EF).contains(&id) {
                return CanProtocolCandidate::IsoTpUds;
            }

            // CANopen standard COB-IDs:
            // NMT: 0x000, Sync: 0x080, Emergency: 0x081..0x0FF
            // PDO1/2/3/4: 0x180.., SDO: 0x580..0x67F, Heartbeat: 0x700..0x77F
            if id == 0x000
                || (0x180..=0x4FF).contains(&id)
                || (0x580..=0x67F).contains(&id)
                || (0x700..=0x77F).contains(&id)
            {
                CanProtocolCandidate::CanOpen
            } else {
                CanProtocolCandidate::GenericCan20
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_uds_frame() {
        let frame = CanFrame::new_standard(0x7DF, &[0x02, 0x01, 0x00]);
        assert_eq!(classify_can_frame(&frame), CanProtocolCandidate::IsoTpUds);
    }

    #[test]
    fn test_classify_canopen_heartbeat() {
        let frame = CanFrame::new_standard(0x705, &[0x05]); // Heartbeat node 5, operational state
        assert_eq!(classify_can_frame(&frame), CanProtocolCandidate::CanOpen);
    }

    #[test]
    fn test_classify_j1939_frame() {
        let frame = CanFrame::new_extended(0x18F00400, &[0; 8]); // EEC1
        assert_eq!(classify_can_frame(&frame), CanProtocolCandidate::J1939);
    }
}
