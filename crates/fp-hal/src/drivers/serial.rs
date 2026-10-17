use async_trait::async_trait;
use chrono::Utc;
use fp_core::{
    AdapterCapabilities, HalError, IndustrialChip, LinkParams, OutboundFrame, RawBusEvent,
    RawFrame, SafetyPermit, SafetyTier, SerialParams, TimestampedChunk,
};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::interface::BusInterface;

/// Serial port driver manager and parameter coordinator implementing BusInterface
pub struct SerialDriver {
    pub port_name: String,
    pub current_params: SerialParams,
    pub safety_tier: SafetyTier,
    pub capabilities: AdapterCapabilities,
    /// Physical RS-485 transceiver Driver Enable (DE / RTS) pin state
    pub rts_asserted: bool,
    /// Physical DTR line state
    pub dtr_asserted: bool,
    tx_sender: broadcast::Sender<RawBusEvent>,
    last_chunk_instant: Option<Instant>,
}

impl SerialDriver {
    pub fn new(port_name: impl Into<String>) -> Self {
        Self::with_capacity(port_name, 100)
    }

    pub fn with_capacity(port_name: impl Into<String>, broadcast_cap: usize) -> Self {
        let name = port_name.into();
        let (tx, _rx) = broadcast::channel(broadcast_cap);
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
            rts_asserted: false, // Transceiver driver physically held disabled
            dtr_asserted: false,
            tx_sender: tx,
            last_chunk_instant: None,
        }
    }

    /// Ingest a newly arrived serial chunk, calculating inter-chunk gap via Instant
    pub fn ingest_chunk(&mut self, data: &[u8], timestamp_us: u64) {
        let now_instant = Instant::now();
        let inter_frame_gap_us = self.last_chunk_instant.map(|prev| {
            now_instant.duration_since(prev).as_micros() as u64
        });
        self.last_chunk_instant = Some(now_instant);

        let chunk = TimestampedChunk::new(bytes::Bytes::copy_from_slice(data), inter_frame_gap_us);
        let event = RawBusEvent::new_serial_rx(
            &self.port_name,
            timestamp_us,
            LinkParams::Serial(self.current_params),
            chunk,
        );
        let _ = self.tx_sender.send(event);
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

    /// Spawn an asynchronous background reader loop on tokio.
    /// Reads chunks from any AsyncRead source, measuring inter-frame timing gaps,
    /// and broadcasting decoded RawBusEvents.
    pub fn spawn_reader_loop<R>(&self, mut reader: R) -> tokio::task::JoinHandle<()>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt;
        let tx_sender = self.tx_sender.clone();
        let port_name = self.port_name.clone();
        let current_params = self.current_params;

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut last_instant: Option<Instant> = None;

            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let now_instant = Instant::now();
                        let gap = last_instant.map(|prev| now_instant.duration_since(prev).as_micros() as u64);
                        last_instant = Some(now_instant);

                        let now_utc = chrono::Utc::now();
                        let timestamp_us = now_utc.timestamp_micros().max(0) as u64;

                        let chunk = TimestampedChunk::new(bytes::Bytes::copy_from_slice(&buf[..n]), gap);
                        let event = RawBusEvent::new_serial_rx(
                            &port_name,
                            timestamp_us,
                            LinkParams::Serial(current_params),
                            chunk,
                        );
                        let _ = tx_sender.send(event);
                    }
                    Err(_) => break,
                }
            }
        })
    }
}

#[async_trait]
impl BusInterface for SerialDriver {
    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn current_safety_tier(&self) -> SafetyTier {
        self.safety_tier
    }

    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError> {
        match params {
            LinkParams::Serial(s) => self.configure(s),
            _ => Err(HalError::UnsupportedParameters("Serial driver expects LinkParams::Serial".into())),
        }
    }

    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError> {
        self.safety_tier = tier;
        if tier == SafetyTier::PassiveListenOnly {
            // De-assert RTS/DTR to ensure RS-485 transceiver line driver is high-impedance
            self.rts_asserted = false;
            self.dtr_asserted = false;
        } else {
            // Driver can be asserted when permitted
            self.rts_asserted = true;
            self.dtr_asserted = true;
        }
        Ok(())
    }

    fn subscribe_rx(&self) -> broadcast::Receiver<RawBusEvent> {
        self.tx_sender.subscribe()
    }

    async fn transmit(
        &mut self,
        frame: OutboundFrame,
        permit: &SafetyPermit,
    ) -> Result<(), HalError> {
        if self.safety_tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: self.safety_tier,
            });
        }

        let now = Utc::now();
        if !permit.is_valid_for(self.safety_tier, now) {
            return Err(HalError::PermitRejected);
        }

        let target_scope = match &frame {
            OutboundFrame::Serial(b) if !b.is_empty() => format!("Modbus:Slave{:02X}", b[0]),
            _ => "Serial".to_string(),
        };
        if !permit.matches_scope(&target_scope) {
            return Err(HalError::InvalidPermit(format!(
                "Permit scope '{:?}' does not match target '{}'",
                permit.scope, target_scope
            )));
        }

        match frame {
            OutboundFrame::Serial(bytes) => {
                let event = RawBusEvent {
                    interface_id: self.port_name.clone(),
                    timestamp_us: now.timestamp_micros() as u64,
                    link_params: LinkParams::Serial(self.current_params),
                    payload: RawFrame::Serial(TimestampedChunk::new(bytes, None)),
                    direction: fp_core::Direction::Tx,
                    error_flags: fp_core::BusErrorFlags::default(),
                };
                let _ = self.tx_sender.send(event);
                Ok(())
            }
            OutboundFrame::Can(_) => Err(HalError::Io("Serial driver only accepts Serial outbound frames".to_string())),
        }
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
        assert!(!driver.rts_asserted);
        assert!(!driver.dtr_asserted);
        assert_eq!(driver.current_params.baud_rate, 9600);
    }

    #[tokio::test]
    async fn test_serial_driver_bus_interface_tier0_enforcement() {
        let mut driver = SerialDriver::new("COM3");
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ReadOnlyProbe,
            "op",
            Utc::now() + chrono::Duration::minutes(5),
            None,
        );

        let outbound = OutboundFrame::Serial(bytes::Bytes::from_static(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B]));
        let err = driver.transmit(outbound.clone(), &permit).await.unwrap_err();
        assert!(matches!(err, HalError::SafetyViolation { .. }));

        // Elevated tier with permit allows transmit and asserts RTS/DTR
        driver.set_safety_tier(SafetyTier::ReadOnlyProbe).await.unwrap();
        assert!(driver.rts_asserted);
        assert!(driver.dtr_asserted);

        let res = driver.transmit(outbound, &permit).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_serial_driver_inter_chunk_timing() {
        let mut driver = SerialDriver::new("COM3");
        let mut rx = driver.subscribe_rx();

        driver.ingest_chunk(&[0x01, 0x03], 1_000_000);
        let ev1 = rx.recv().await.unwrap();
        if let RawFrame::Serial(chunk) = ev1.payload {
            assert_eq!(chunk.inter_frame_gap_us, None);
        } else {
            panic!("Expected serial chunk");
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        driver.ingest_chunk(&[0x00, 0x01], 1_005_000);
        let ev2 = rx.recv().await.unwrap();
        if let RawFrame::Serial(chunk) = ev2.payload {
            let gap = chunk.inter_frame_gap_us.expect("Inter-frame gap present");
            assert!(gap >= 4000); // at least 4ms recorded
        } else {
            panic!("Expected serial chunk");
        }
    }
}
