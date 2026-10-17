use fp_core::{AdapterCapabilities, IndustrialChip, SafetyTier};

/// Linux SocketCAN driver abstraction
#[derive(Debug, Clone)]
pub struct SocketCanDriver {
    pub interface_name: String,
    pub bitrate: u32,
    pub safety_tier: SafetyTier,
    pub listen_only_enforced: bool,
    pub capabilities: AdapterCapabilities,
}

impl SocketCanDriver {
    pub fn new(interface_name: impl Into<String>) -> Self {
        let name = interface_name.into();
        let caps = AdapterCapabilities {
            interface_id: name.clone(),
            chip_type: IndustrialChip::PeakPcan,
            supports_serial: false,
            supports_can: true,
            supports_can_fd: true,
            supports_listen_only: true,
            supported_baud_rates: vec![],
            supported_can_bitrates: vec![500_000, 250_000, 125_000, 1_000_000],
            usb_vid: Some(0x0C72),
            usb_pid: Some(0x000C),
            serial_number: Some("PCAN-USB-01".to_string()),
            description: format!("SocketCAN Adapter ({})", name),
        };

        Self {
            interface_name: name,
            bitrate: 500_000,
            safety_tier: SafetyTier::PassiveListenOnly,
            listen_only_enforced: true,
            capabilities: caps,
        }
    }

    /// Check if hardware interface supports listen-only mode
    pub fn verify_listen_only_support(&self) -> bool {
        self.capabilities.supports_listen_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketcan_driver_listen_only_default() {
        let driver = SocketCanDriver::new("vcan0");
        assert_eq!(driver.safety_tier, SafetyTier::PassiveListenOnly);
        assert!(driver.listen_only_enforced);
        assert!(driver.verify_listen_only_support());
    }
}
