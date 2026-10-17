//! `fp-hal`
//!
//! Hardware Abstraction Layer & Replay Interface for `field-probe`.
//!
//! Exposes the asynchronous `BusInterface` trait, deterministic `ReplayInterface`,
//! and drivers for serial, SocketCAN, and SLCAN adapters.

pub mod drivers;
pub mod enumeration;
pub mod interface;
pub mod replay;

pub use drivers::{SerialDriver, SlcanCodec, SlcanDriver, SocketCanDriver};
pub use enumeration::enumerate_dongles;
pub use interface::BusInterface;
pub use replay::ReplayInterface;
