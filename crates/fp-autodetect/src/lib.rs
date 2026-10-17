//! `fp-autodetect`
//!
//! Non-intrusive parameter and protocol discovery algorithms for `field-probe`.

pub mod can_hunter;
pub mod crc;
pub mod serial_hunter;
pub mod unknown_framer;

pub use can_hunter::{classify_can_frame, CanProtocolCandidate};
pub use crc::{
    bacnet_crc8, dnp3_crc16, modbus_ascii_lrc, modbus_rtu_crc16, verify_dnp3_crc16,
    verify_modbus_rtu_crc16,
};
pub use serial_hunter::{
    calculate_silence_intervals, scan_bacnet_mstp_frames, scan_dnp3_frames,
    scan_modbus_ascii_frames, scan_modbus_rtu_frames, score_serial_stream, SerialDetectionScore,
    SerialProtocolCandidate, SerialSilenceIntervals, CANDIDATE_BAUD_RATES,
};
pub use unknown_framer::{
    FieldType, FrameStructureHypothesis, InferredField, UnknownFramer,
};
