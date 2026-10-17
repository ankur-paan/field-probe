use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::params::LinkParams;

/// Direction of observed bus traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Rx,
    Tx,
}

/// Raw timestamped bus event emitted by any hardware or replay adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBusEvent {
    /// Adapter / channel identifier
    pub interface_id: String,
    /// Monotonic timestamp in microseconds since start of session or packet epoch
    pub timestamp_us: u64,
    /// Effective link parameters under which event was received
    pub link_params: LinkParams,
    /// Frame payload (Serial chunk or CAN frame)
    pub payload: RawFrame,
    /// Traffic direction
    pub direction: Direction,
    /// Hardware or physical layer error flags (framing error, parity error, stuff error)
    pub error_flags: BusErrorFlags,
}

impl RawBusEvent {
    pub fn new_serial_rx(
        interface_id: impl Into<String>,
        timestamp_us: u64,
        params: LinkParams,
        chunk: TimestampedChunk,
    ) -> Self {
        Self {
            interface_id: interface_id.into(),
            timestamp_us,
            link_params: params,
            payload: RawFrame::Serial(chunk),
            direction: Direction::Rx,
            error_flags: BusErrorFlags::default(),
        }
    }

    pub fn new_can_rx(
        interface_id: impl Into<String>,
        timestamp_us: u64,
        params: LinkParams,
        frame: CanFrame,
    ) -> Self {
        Self {
            interface_id: interface_id.into(),
            timestamp_us,
            link_params: params,
            payload: RawFrame::Can(frame),
            direction: Direction::Rx,
            error_flags: BusErrorFlags::default(),
        }
    }
}

/// Physical layer error flags reported by transceivers or serial drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct BusErrorFlags {
    pub uart_framing_error: bool,
    pub uart_parity_error: bool,
    pub uart_overrun_error: bool,
    pub can_stuff_error: bool,
    pub can_form_error: bool,
    pub can_ack_error: bool,
    pub can_bit_error: bool,
    pub can_crc_error: bool,
}

/// Raw payload variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawFrame {
    Serial(TimestampedChunk),
    Can(CanFrame),
}

/// Timestamped sequence of serial bytes observed on a bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampedChunk {
    /// Raw byte payload
    pub data: Bytes,
    /// Microsecond gap since the previous byte or chunk (useful for t3.5 boundary detection)
    pub inter_frame_gap_us: Option<u64>,
}

impl TimestampedChunk {
    pub fn new(data: impl Into<Bytes>, inter_frame_gap_us: Option<u64>) -> Self {
        Self {
            data: data.into(),
            inter_frame_gap_us,
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(slice),
            inter_frame_gap_us: None,
        }
    }
}

/// CAN arbitration identifier (11-bit standard or 29-bit extended).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanId {
    Standard(u16),
    Extended(u32),
}

impl CanId {
    pub fn as_raw(&self) -> u32 {
        match self {
            Self::Standard(id) => *id as u32,
            Self::Extended(id) => *id,
        }
    }

    pub fn is_extended(&self) -> bool {
        matches!(self, Self::Extended(_))
    }
}

/// Raw CAN 2.0 or CAN-FD frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanFrame {
    pub id: CanId,
    pub dlc: u8,
    pub data: Bytes,
    pub is_fd: bool,
    pub is_rtr: bool,
    pub is_error: bool,
}

impl CanFrame {
    pub fn new_standard(id: u16, data: &[u8]) -> Self {
        Self {
            id: CanId::Standard(id & 0x7FF),
            dlc: data.len() as u8,
            data: Bytes::copy_from_slice(data),
            is_fd: false,
            is_rtr: false,
            is_error: false,
        }
    }

    pub fn new_extended(id: u32, data: &[u8]) -> Self {
        Self {
            id: CanId::Extended(id & 0x1FFFFFFF),
            dlc: data.len() as u8,
            data: Bytes::copy_from_slice(data),
            is_fd: false,
            is_rtr: false,
            is_error: false,
        }
    }

    pub fn new_standard_rtr(id: u16, dlc: u8) -> Self {
        Self {
            id: CanId::Standard(id & 0x7FF),
            dlc,
            data: Bytes::new(),
            is_fd: false,
            is_rtr: true,
            is_error: false,
        }
    }

    pub fn new_extended_rtr(id: u32, dlc: u8) -> Self {
        Self {
            id: CanId::Extended(id & 0x1FFFFFFF),
            dlc,
            data: Bytes::new(),
            is_fd: false,
            is_rtr: true,
            is_error: false,
        }
    }

    pub fn new_standard_fd(id: u16, data: &[u8]) -> Self {
        Self {
            id: CanId::Standard(id & 0x7FF),
            dlc: data.len() as u8,
            data: Bytes::copy_from_slice(data),
            is_fd: true,
            is_rtr: false,
            is_error: false,
        }
    }

    pub fn new_extended_fd(id: u32, data: &[u8]) -> Self {
        Self {
            id: CanId::Extended(id & 0x1FFFFFFF),
            dlc: data.len() as u8,
            data: Bytes::copy_from_slice(data),
            is_fd: true,
            is_rtr: false,
            is_error: false,
        }
    }
}

/// Frame targeted for bus transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundFrame {
    Serial(Bytes),
    Can(CanFrame),
}
