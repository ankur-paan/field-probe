use fp_core::{AdapterCapabilities, HalError, IndustrialChip, SafetyTier, SerialParams};

/// Serial port driver manager and parameter coordinator
#[derive(Debug, Clone)]
pub struct SerialDriver {
    pub port_name: String,
    pub current_params: SerialParams,
    pub safety_tier: SafetyTier,
    pub capabilities: AdapterCapabilities,
}

impl SerialDriver {
    pub fn new(port_name: impl Into<String>) -> Self {
        let name = port_name.into();
        let caps = AdapterCapabilities {
            interface_id: name.clone(),
            chip_type: IndustrialChip::SiliconLabsCp210x,
            supports_serial: true,
            supports_can: false,
            supports_can_fd: false,
            supports_listen_only: true,
            supported_baud_rates: vec![9600, 19200, 38400, 57600, 115200, 230400],
            supported_can_bitrates: vec![],
            usb_vid: Some(0x10C4),
            usb_pid: Some(0xEA60),
            serial_number: Some("CP2102-001".to_string()),
            description: format!("Industrial Serial Port ({})", name),
        };

        Self {
            port_name: name,
            current_params: SerialParams::default(),
            safety_tier: SafetyTier::PassiveListenOnly,
            capabilities: caps,
        }
    }

    /// Reconfigure serial baud rate and framing
    pub fn configure(&mut self, params: &SerialParams) -> Result<(), HalError> {
        self.current_params = *params;
        Ok(())
    }

    /// Verify whether transmission is permissible
    pub fn can_transmit(&self) -> bool {
        self.safety_tier != SafetyTier::PassiveListenOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_driver_defaults_to_passive() {
        let driver = SerialDriver::new("COM3");
        assert_eq!(driver.safety_tier, SafetyTier::PassiveListenOnly);
        assert!(!driver.can_transmit());
        assert_eq!(driver.current_params.baud_rate, 9600);
    }
}
