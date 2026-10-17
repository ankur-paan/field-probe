use serde::{Deserialize, Serialize};

/// Communication link parameters for bus adapters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum LinkParams {
    /// Serial connection parameters (RS-485 / RS-232 / UART)
    Serial(SerialParams),
    /// CAN bus connection parameters (CAN 2.0A/B, CAN-FD)
    Can(CanParams),
    /// Unconfigured / Auto-hunting mode
    #[default]
    Auto,
}

/// Serial communication parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialParams {
    pub baud_rate: u32,
    pub data_bits: DataBits,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub flow_control: FlowControl,
}

impl Default for SerialParams {
    fn default() -> Self {
        Self {
            baud_rate: 9600,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataBits {
    Seven = 7,
    Eight = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Parity {
    None,
    Even,
    Odd,
    Mark,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StopBits {
    One = 1,
    Two = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowControl {
    None,
    Software,
    Hardware,
}

/// CAN bus communication parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanParams {
    pub bitrate: u32,
    pub sample_point_permille: u16,
    pub fd: bool,
    pub data_bitrate: Option<u32>,
}

impl Default for CanParams {
    fn default() -> Self {
        Self {
            bitrate: 500_000,
            sample_point_permille: 875,
            fd: false,
            data_bitrate: None,
        }
    }
}

/// Common candidate baud rates for RS-485/RS-232 hunting
pub const COMMON_SERIAL_BAUD_RATES: &[u32] =
    &[9600, 19200, 38400, 57600, 115200, 4800, 2400, 230400];

/// Common candidate bitrates for CAN bus hunting
pub const COMMON_CAN_BITRATES: &[u32] = &[
    500_000, 250_000, 125_000, 1_000_000, 100_000, 83_333, 50_000,
];

/// Universal industrial bus protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BusProtocol {
    ModbusRtu,
    ModbusAscii,
    ModbusTcp,
    BacnetMstp,
    Dnp3,
    Can20,
    CanFd,
    J1939,
    CanOpen,
    Uds,
    RawSerial,
    Unknown,
}

/// Calculated t1.5 and t3.5 character silence intervals in microseconds for serial bus timing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialSilenceIntervals {
    pub t1_5_us: u64,
    pub t3_5_us: u64,
}

/// Calculate exact t1.5 and t3.5 silence intervals for a given baud rate according to Modbus/serial specifications.
/// For baud rates > 19200 bps, uses fixed standard constants (750 us and 1750 us).
pub fn calculate_silence_intervals(baud_rate: u32) -> SerialSilenceIntervals {
    if baud_rate > 19200 {
        SerialSilenceIntervals {
            t1_5_us: 750,
            t3_5_us: 1750,
        }
    } else {
        let char_time_us = 11_000_000.0 / (baud_rate.max(1) as f64);
        let t1_5 = (1.5 * char_time_us).round() as u64;
        let t3_5 = (3.5 * char_time_us).round() as u64;
        SerialSilenceIntervals {
            t1_5_us: t1_5,
            t3_5_us: t3_5,
        }
    }
}
