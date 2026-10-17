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
pub const COMMON_SERIAL_BAUD_RATES: &[u32] = &[
    9600, 19200, 38400, 57600, 115200, 4800, 2400, 230400,
];

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

