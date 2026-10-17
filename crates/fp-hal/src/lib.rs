//! `fp-hal`
//!
//! Hardware Abstraction Layer & Replay Interface for `field-probe`.
//!
//! Exposes the asynchronous `BusInterface` trait, deterministic `ReplayInterface`,
//! and drivers for serial, SocketCAN, and SLCAN adapters.

pub mod drivers;
pub mod interface;
pub mod replay;

pub use drivers::{SerialDriver, SlcanCodec, SocketCanDriver};
pub use interface::BusInterface;
pub use replay::ReplayInterface;
