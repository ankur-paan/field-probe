use serde::{Deserialize, Serialize};

/// Hardware capabilities of a discovered or connected adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub interface_id: String,
    pub chip_type: IndustrialChip,
    pub supports_serial: bool,
    pub supports_can: bool,
    pub supports_can_fd: bool,
    pub supports_listen_only: bool,
    pub supported_baud_rates: Vec<u32>,
    pub supported_can_bitrates: Vec<u32>,
    pub usb_vid: Option<u16>,
    pub usb_pid: Option<u16>,
    pub serial_number: Option<String>,
    pub description: String,
}

impl Default for AdapterCapabilities {
    fn default() -> Self {
        Self {
            interface_id: "virtual-replay".to_string(),
            chip_type: IndustrialChip::SyntheticReplay,
            supports_serial: true,
            supports_can: true,
            supports_can_fd: true,
            supports_listen_only: true,
            supported_baud_rates: vec![9600, 19200, 38400, 57600, 115200, 230400],
            supported_can_bitrates: vec![500_000, 250_000, 125_000, 1_000_000],
            usb_vid: None,
            usb_pid: None,
            serial_number: None,
            description: "Synthetic Bus Replay Device".to_string(),
        }
    }
}

/// Fingerprinted industrial USB/CAN/Serial chipsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndustrialChip {
    FtdiFt232,
    FtdiFt4232,
    SiliconLabsCp210x,
    WchCh340,
    PeakPcan,
    KvaserLeaf,
    GsUsbCandleLight,
    LawicelSlcan,
    SyntheticReplay,
    Unknown,
}

impl IndustrialChip {
    /// Identify chip type based on USB VID and PID
    pub fn from_vid_pid(vid: u16, pid: u16) -> Self {
        match (vid, pid) {
            (0x0403, 0x6001) => Self::FtdiFt232,
            (0x0403, 0x6011) => Self::FtdiFt4232,
            (0x10C4, 0xEA60) => Self::SiliconLabsCp210x,
            (0x1A86, 0x7523) => Self::WchCh340,
            (0x0C72, 0x000C) => Self::PeakPcan,
            (0x0BFD, _) => Self::KvaserLeaf,
            (0x1D50, 0x606F) => Self::GsUsbCandleLight,
            _ => Self::Unknown,
        }
    }
}
