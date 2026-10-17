//! `fp-core`
//!
//! Foundational domain models and core invariants for `field-probe`.
//!
//! # Safety Invariant
//! All hardware adapters default to `SafetyTier::PassiveListenOnly` (Tier 0).
//! No bytes or dominant CAN bits may be transmitted without an explicit `SafetyPermit`.

pub mod capabilities;
pub mod error;
pub mod events;
pub mod params;
pub mod safety;

pub use capabilities::{AdapterCapabilities, IndustrialChip};
pub use error::HalError;
pub use events::{
    BusErrorFlags, CanFrame, CanId, Direction, OutboundFrame, RawBusEvent, RawFrame,
    TimestampedChunk,
};
pub use params::{
    calculate_silence_intervals, BusProtocol, CanParams, DataBits, FlowControl, LinkParams, Parity,
    SerialParams, SerialSilenceIntervals, StopBits, COMMON_CAN_BITRATES, COMMON_SERIAL_BAUD_RATES,
};
pub use safety::{SafetyPermit, SafetyTier};
pub use chrono;

