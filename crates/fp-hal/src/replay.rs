use async_trait::async_trait;
use chrono::Utc;
use fp_core::{
    AdapterCapabilities, CanFrame, CanId, HalError, IndustrialChip, LinkParams, OutboundFrame,
    RawBusEvent, RawFrame, SafetyPermit, SafetyTier, TimestampedChunk,
};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::interface::BusInterface;

/// A deterministic, hardware-agnostic synthetic bus interface for CI and simulation.
#[derive(Clone)]
pub struct ReplayInterface {
    capabilities: AdapterCapabilities,
    tier: Arc<RwLock<SafetyTier>>,
    link_params: Arc<RwLock<LinkParams>>,
    tx_sender: broadcast::Sender<RawBusEvent>,
    transmitted_history: Arc<RwLock<Vec<OutboundFrame>>>,
}

impl ReplayInterface {
    /// Create a new synthetic replay interface with a broadcast capacity.
    /// Invariant: Tier initializes to Tier-0 PassiveListenOnly.
    pub fn new(interface_id: impl Into<String>, capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        let id_str = interface_id.into();
        Self {
            capabilities: AdapterCapabilities {
                interface_id: id_str.clone(),
                chip_type: IndustrialChip::SyntheticReplay,
                supports_serial: true,
                supports_can: true,
                supports_can_fd: true,
                supports_listen_only: true,
                supported_baud_rates: vec![9600, 19200, 38400, 57600, 115200, 230400],
                supported_can_bitrates: vec![500_000, 250_000, 125_000, 1_000_000],
                usb_vid: None,
                usb_pid: None,
                serial_number: Some("REPLAY-VIRTUAL-001".to_string()),
                description: format!("Virtual Replay Interface ({})", id_str),
            },
            tier: Arc::new(RwLock::new(SafetyTier::PassiveListenOnly)),
            link_params: Arc::new(RwLock::new(LinkParams::Auto)),
            tx_sender: tx,
            transmitted_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Inject a synthetic bus event into the receiver stream.
    pub fn inject_event(&self, event: RawBusEvent) -> Result<usize, HalError> {
        self.tx_sender
            .send(event)
            .map_err(|e| HalError::Io(format!("Failed to broadcast replay event: {}", e)))
    }

    /// Inject a raw synthetic Modbus RTU chunk.
    pub fn inject_modbus_rtu(
        &self,
        timestamp_us: u64,
        payload: &[u8],
        inter_frame_gap_us: Option<u64>,
    ) -> Result<usize, HalError> {
        let params = {
            let p = self
                .link_params
                .try_read()
                .map_err(|_| HalError::Timeout("Lock contention".into()))?;
            p.clone()
        };
        let chunk = TimestampedChunk::new(payload.to_vec(), inter_frame_gap_us);
        let event = RawBusEvent::new_serial_rx(
            self.capabilities.interface_id.clone(),
            timestamp_us,
            params,
            chunk,
        );
        self.inject_event(event)
    }

    /// Inject a synthetic CAN frame.
    pub fn inject_can_frame(&self, timestamp_us: u64, frame: CanFrame) -> Result<usize, HalError> {
        let params = {
            let p = self
                .link_params
                .try_read()
                .map_err(|_| HalError::Timeout("Lock contention".into()))?;
            p.clone()
        };
        let event = RawBusEvent::new_can_rx(
            self.capabilities.interface_id.clone(),
            timestamp_us,
            params,
            frame,
        );
        self.inject_event(event)
    }

    /// Return recorded transmitted frames (for assertion in tests)
    pub async fn get_transmitted(&self) -> Vec<OutboundFrame> {
        self.transmitted_history.read().await.clone()
    }

    /// Spawn an asynchronous task replaying a sequence of events into the broadcast channel.
    /// If real_time is true, pauses between events to match original arrival timings.
    pub fn spawn_file_replay(
        &self,
        events: Vec<RawBusEvent>,
        real_time: bool,
    ) -> tokio::task::JoinHandle<()> {
        let replay = self.clone();
        tokio::spawn(async move {
            let mut prev_ts: Option<u64> = None;
            for ev in events {
                if real_time {
                    if let Some(prev) = prev_ts {
                        if ev.timestamp_us > prev {
                            let diff_us = (ev.timestamp_us - prev).min(1_000_000);
                            tokio::time::sleep(tokio::time::Duration::from_micros(diff_us)).await;
                        }
                    }
                    prev_ts = Some(ev.timestamp_us);
                }
                let _ = replay.inject_event(ev);
            }
        })
    }
}

#[async_trait]
impl BusInterface for ReplayInterface {
    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn current_safety_tier(&self) -> SafetyTier {
        // Fast synchronous check if possible
        if let Ok(guard) = self.tier.try_read() {
            *guard
        } else {
            SafetyTier::PassiveListenOnly
        }
    }

    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError> {
        let mut guard = self.link_params.write().await;
        *guard = params.clone();
        Ok(())
    }

    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError> {
        let mut guard = self.tier.write().await;
        *guard = tier;
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
        let current_tier = *self.tier.read().await;

        // Tier-0 Zero-TX Default invariant
        if current_tier == SafetyTier::PassiveListenOnly {
            return Err(HalError::SafetyViolation {
                required: SafetyTier::ReadOnlyProbe,
                current: current_tier,
            });
        }

        // Validate permit
        let now = Utc::now();
        if !permit.is_valid_for(current_tier, now) {
            return Err(HalError::PermitRejected);
        }

        let target_scope = match &frame {
            OutboundFrame::Can(c) => format!("CAN:0x{:X}", c.id.as_raw()),
            OutboundFrame::Serial(b) if !b.is_empty() => format!("Modbus:Slave{:02X}", b[0]),
            OutboundFrame::Serial(_) => "Serial".to_string(),
        };
        if !permit.matches_scope(&target_scope) {
            return Err(HalError::InvalidPermit(format!(
                "Permit scope '{:?}' does not match target '{}'",
                permit.scope, target_scope
            )));
        }

        // Store transmitted frame
        self.transmitted_history.write().await.push(frame.clone());

        // Emit loopback/direction TX event on bus
        let current_params = self.link_params.read().await.clone();
        let payload = match frame {
            OutboundFrame::Serial(b) => RawFrame::Serial(TimestampedChunk::new(b, None)),
            OutboundFrame::Can(c) => RawFrame::Can(c),
        };
        let tx_event = RawBusEvent {
            interface_id: self.capabilities.interface_id.clone(),
            timestamp_us: (now.timestamp_micros()).max(0) as u64,
            link_params: current_params,
            payload,
            direction: fp_core::Direction::Tx,
            error_flags: Default::default(),
        };

        let _ = self.tx_sender.send(tx_event);
        Ok(())
    }
}

/// Parse Wireshark PCAP-NG binary buffer into RawBusEvent items
pub fn parse_pcapng_events(bytes: &[u8]) -> Result<Vec<RawBusEvent>, HalError> {
    if bytes.len() < 28 {
        return Err(HalError::Io("PCAP-NG file too small".to_string()));
    }
    // Verify SHB magic 0x0A0D0D0A
    if bytes[0..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
        return Err(HalError::Io("Invalid PCAP-NG magic header".to_string()));
    }

    let mut events = Vec::new();
    let mut offset = 0;

    while offset + 8 <= bytes.len() {
        let block_type = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let block_len = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;
        if block_len < 8 || offset + block_len > bytes.len() {
            break;
        }

        // EPB block type = 0x00000006
        if block_type == 0x00000006 && block_len >= 32 {
            let if_id = u32::from_le_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
            ]);
            let ts_high = u32::from_le_bytes([
                bytes[offset + 12],
                bytes[offset + 13],
                bytes[offset + 14],
                bytes[offset + 15],
            ]);
            let ts_low = u32::from_le_bytes([
                bytes[offset + 16],
                bytes[offset + 17],
                bytes[offset + 18],
                bytes[offset + 19],
            ]);
            let ts_us = ((ts_high as u64) << 32) | (ts_low as u64);
            let cap_len = u32::from_le_bytes([
                bytes[offset + 20],
                bytes[offset + 21],
                bytes[offset + 22],
                bytes[offset + 23],
            ]) as usize;

            if offset + 28 + cap_len <= offset + block_len {
                let packet_data = &bytes[offset + 28..offset + 28 + cap_len];
                if if_id == 0 && cap_len >= 8 {
                    // SocketCAN
                    let can_id_raw = u32::from_be_bytes([
                        packet_data[0],
                        packet_data[1],
                        packet_data[2],
                        packet_data[3],
                    ]);
                    let dlc = (packet_data[4] as usize).min(cap_len.saturating_sub(8));
                    let is_eff = (can_id_raw & 0x80000000) != 0;
                    let is_rtr = (can_id_raw & 0x40000000) != 0;
                    let is_err = (can_id_raw & 0x20000000) != 0;

                    let can_id = if is_eff {
                        CanId::Extended(can_id_raw & 0x1FFFFFFF)
                    } else {
                        CanId::Standard((can_id_raw & 0x7FF) as u16)
                    };
                    let data = if cap_len >= 8 + dlc {
                        bytes::Bytes::copy_from_slice(&packet_data[8..8 + dlc])
                    } else {
                        bytes::Bytes::new()
                    };

                    let frame = CanFrame {
                        id: can_id,
                        dlc: dlc as u8,
                        data,
                        is_fd: false,
                        is_rtr,
                        is_error: is_err,
                    };

                    events.push(RawBusEvent {
                        interface_id: "can0".to_string(),
                        timestamp_us: ts_us,
                        link_params: LinkParams::Can(Default::default()),
                        payload: RawFrame::Can(frame),
                        direction: fp_core::Direction::Rx,
                        error_flags: Default::default(),
                    });
                } else {
                    // Serial RTAC or other
                    let chunk = TimestampedChunk::new(packet_data.to_vec(), None);
                    events.push(RawBusEvent::new_serial_rx(
                        "serial0",
                        ts_us,
                        LinkParams::Serial(Default::default()),
                        chunk,
                    ));
                }
            }
        }

        offset += block_len;
    }

    Ok(events)
}

/// Parse a line from a Linux candump log
pub fn parse_candump_line(line: &str) -> Option<(u64, CanFrame)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Check Format 1: (timestamp) iface ID#DATA or iface ID#DATA
    if let Some(hash_pos) = line.find('#') {
        let left = line[..hash_pos].trim();
        let right = line[hash_pos + 1..].trim();

        // Check if there is timestamp in parentheses: (1600000000.123456)
        let (ts_us, rest_left) = if left.starts_with('(') {
            if let Some(close_paren) = left.find(')') {
                let ts_str = &left[1..close_paren];
                let ts_us = parse_candump_ts(ts_str);
                (ts_us, left[close_paren + 1..].trim())
            } else {
                (0, left)
            }
        } else {
            (0, left)
        };

        let id_str = rest_left.split_whitespace().last()?;
        let id_val = u32::from_str_radix(id_str, 16).ok()?;
        let is_ext = id_str.len() > 3;

        let data = hex_to_bytes(right);
        let dlc = data.len();

        let can_id = if is_ext {
            CanId::Extended(id_val)
        } else {
            CanId::Standard(id_val as u16)
        };

        return Some((
            ts_us,
            CanFrame {
                id: can_id,
                dlc: dlc as u8,
                data: bytes::Bytes::from(data),
                is_fd: false,
                is_rtr: false,
                is_error: false,
            },
        ));
    }

    // Check Format 2: can0  123   [4]  11 22 33 44
    if let (Some(bracket_open), Some(bracket_close)) = (line.find('['), line.find(']')) {
        let left = line[..bracket_open].trim();
        let right = line[bracket_close + 1..].trim();

        let id_str = left.split_whitespace().last()?;
        let id_val = u32::from_str_radix(id_str, 16).ok()?;
        let is_ext = id_str.len() > 3;

        let mut data = Vec::new();
        for token in right.split_whitespace() {
            if let Ok(b) = u8::from_str_radix(token, 16) {
                data.push(b);
            }
        }
        let dlc = data.len();

        let can_id = if is_ext {
            CanId::Extended(id_val)
        } else {
            CanId::Standard(id_val as u16)
        };

        return Some((
            0,
            CanFrame {
                id: can_id,
                dlc: dlc as u8,
                data: bytes::Bytes::from(data),
                is_fd: false,
                is_rtr: false,
                is_error: false,
            },
        ));
    }

    None
}

fn parse_candump_ts(s: &str) -> u64 {
    if let Some(dot) = s.find('.') {
        let sec: u64 = s[..dot].parse().unwrap_or(0);
        let micro_str = &s[dot + 1..];
        let micro: u64 = if micro_str.len() >= 6 {
            micro_str[..6].parse().unwrap_or(0)
        } else {
            let padded = format!("{:0<6}", micro_str);
            padded.parse().unwrap_or(0)
        };
        sec * 1_000_000 + micro
    } else {
        s.parse::<u64>().unwrap_or(0) * 1_000_000
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    for chunk in chars.chunks(2) {
        if chunk.len() == 2 {
            let hex_s: String = chunk.iter().collect();
            if let Ok(b) = u8::from_str_radix(&hex_s, 16) {
                out.push(b);
            }
        }
    }
    out
}

/// Load replay events from a file (.pcapng, candump text log, or raw binary)
pub fn load_replay_file(path: &str) -> Result<Vec<RawBusEvent>, HalError> {
    let content = std::fs::read(path)
        .map_err(|e| HalError::Io(format!("Failed to read replay file '{}': {}", path, e)))?;

    if content.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A])
        || path.ends_with(".pcapng")
        || path.ends_with(".pcap")
    {
        return parse_pcapng_events(&content);
    }

    if let Ok(text) = std::str::from_utf8(&content) {
        let mut events = Vec::new();
        for line in text.lines() {
            if let Some((ts_us, frame)) = parse_candump_line(line) {
                events.push(RawBusEvent::new_can_rx(
                    "candump0",
                    ts_us,
                    LinkParams::Can(Default::default()),
                    frame,
                ));
            }
        }
        if !events.is_empty() {
            return Ok(events);
        }
    }

    // Fallback: chunk raw binary content into serial events
    let mut events = Vec::new();
    let mut ts = 1_000_000u64;
    for chunk in content.chunks(64) {
        events.push(RawBusEvent::new_serial_rx(
            "raw0",
            ts,
            LinkParams::Serial(Default::default()),
            TimestampedChunk::new(chunk.to_vec(), Some(10_000)),
        ));
        ts += 10_000;
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Duration;
    use fp_core::{CanFrame, CanId, SerialParams};

    #[tokio::test]
    async fn test_initial_tier_is_passive_and_blocks_tx() {
        let mut replay = ReplayInterface::new("vbus0", 16);
        assert_eq!(replay.current_safety_tier(), SafetyTier::PassiveListenOnly);

        let now = Utc::now();
        let permit = SafetyPermit::new(
            "p1",
            SafetyTier::ActiveWrite,
            "tester",
            now + Duration::minutes(1),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        let result = replay.transmit(frame, &permit).await;

        match result {
            Err(HalError::SafetyViolation { required, current }) => {
                assert_eq!(required, SafetyTier::ReadOnlyProbe);
                assert_eq!(current, SafetyTier::PassiveListenOnly);
            }
            _ => panic!("Expected SafetyViolation error, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_elevated_tier_with_valid_permit_allows_tx() {
        let mut replay = ReplayInterface::new("vbus1", 16);
        replay
            .set_safety_tier(SafetyTier::ReadOnlyProbe)
            .await
            .unwrap();

        let now = Utc::now();
        let permit = SafetyPermit::new(
            "p2",
            SafetyTier::ReadOnlyProbe,
            "tester",
            now + Duration::minutes(1),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        replay
            .transmit(frame.clone(), &permit)
            .await
            .expect("Transmit should succeed");

        let history = replay.get_transmitted().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], frame);
    }

    #[tokio::test]
    async fn test_expired_permit_is_rejected() {
        let mut replay = ReplayInterface::new("vbus2", 16);
        replay
            .set_safety_tier(SafetyTier::ReadOnlyProbe)
            .await
            .unwrap();

        let now = Utc::now();
        let expired_permit = SafetyPermit::new(
            "p3",
            SafetyTier::ReadOnlyProbe,
            "tester",
            now - Duration::seconds(5),
            None,
        );

        let frame = OutboundFrame::Serial(Bytes::from_static(b"\x01\x03\x00\x00\x00\x01\x84\x0A"));
        let result = replay.transmit(frame, &expired_permit).await;
        assert!(matches!(result, Err(HalError::PermitRejected)));
    }

    #[tokio::test]
    async fn test_synthetic_event_streaming() {
        let mut replay = ReplayInterface::new("vbus_stream", 32);
        replay
            .set_link_params(&LinkParams::Serial(SerialParams::default()))
            .await
            .unwrap();

        let mut rx = replay.subscribe_rx();

        // Inject Modbus query
        let modbus_req = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x74, 0x17];
        replay
            .inject_modbus_rtu(1000, &modbus_req, Some(3500))
            .unwrap();

        // Inject CAN frame
        let can_frame =
            CanFrame::new_standard(0x7DF, &[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        replay.inject_can_frame(2500, can_frame).unwrap();

        let ev1 = rx.recv().await.unwrap();
        assert_eq!(ev1.timestamp_us, 1000);
        if let RawFrame::Serial(chunk) = ev1.payload {
            assert_eq!(&chunk.data[..], &modbus_req);
            assert_eq!(chunk.inter_frame_gap_us, Some(3500));
        } else {
            panic!("Expected serial event");
        }

        let ev2 = rx.recv().await.unwrap();
        assert_eq!(ev2.timestamp_us, 2500);
        if let RawFrame::Can(can) = ev2.payload {
            assert_eq!(can.id, CanId::Standard(0x7DF));
            assert_eq!(can.dlc, 8);
        } else {
            panic!("Expected CAN event");
        }
    }

    #[tokio::test]
    async fn test_out_of_scope_permit_is_rejected() {
        let mut replay = ReplayInterface::new("vbus_scope", 16);
        replay
            .set_safety_tier(SafetyTier::ReadOnlyProbe)
            .await
            .unwrap();

        let permit_scoped = SafetyPermit::new(
            "p_can_only",
            SafetyTier::ReadOnlyProbe,
            "tester",
            Utc::now() + Duration::hours(1),
            Some("CAN:0x7E0".to_string()),
        );

        // Frame targeting CAN 0x123 violates scope "CAN:0x7E0"
        let can_frame = CanFrame::new_standard(0x123, &[0x00]);
        let result = replay
            .transmit(OutboundFrame::Can(can_frame), &permit_scoped)
            .await;
        assert!(matches!(result, Err(HalError::InvalidPermit(_))));

        // Frame targeting CAN 0x7E0 satisfies scope
        let valid_frame = CanFrame::new_standard(0x7E0, &[0x02, 0x10, 0x01]);
        assert!(replay
            .transmit(OutboundFrame::Can(valid_frame), &permit_scoped)
            .await
            .is_ok());
    }

    #[test]
    fn test_parse_candump_line_hash_format() {
        let line = "(1600000000.123456) can0 123#11223344";
        let (ts, frame) = parse_candump_line(line).expect("Parsed candump line");
        assert_eq!(ts, 1_600_000_000_123_456);
        assert_eq!(frame.id, CanId::Standard(0x123));
        assert_eq!(frame.dlc, 4);
        assert_eq!(frame.data.as_ref(), &[0x11, 0x22, 0x33, 0x44]);

        let ext_line = "can0 18DAF110#020100";
        let (ts_ext, ext_frame) = parse_candump_line(ext_line).expect("Parsed ext line");
        assert_eq!(ts_ext, 0);
        assert_eq!(ext_frame.id, CanId::Extended(0x18DAF110));
        assert_eq!(ext_frame.dlc, 3);
        assert_eq!(ext_frame.data.as_ref(), &[0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_parse_candump_line_bracket_format() {
        let line = "can0  7DF   [8]  02 01 05 00 00 00 00 00";
        let (_, frame) = parse_candump_line(line).expect("Parsed candump line");
        assert_eq!(frame.id, CanId::Standard(0x7DF));
        assert_eq!(frame.dlc, 8);
        assert_eq!(
            frame.data.as_ref(),
            &[0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_pcapng_roundtrip_parsing() {
        // Construct synthetic PCAP-NG matching Wireshark EPB format
        let mut bytes = Vec::new();
        // 1. SHB (28 bytes)
        bytes.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        bytes.extend_from_slice(&28u32.to_le_bytes());
        bytes.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_le_bytes());
        bytes.extend_from_slice(&28u32.to_le_bytes());

        // 2. IDB 0 (20 bytes)
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&20u32.to_le_bytes());
        bytes.extend_from_slice(&227u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&20u32.to_le_bytes());

        // 3. EPB with SocketCAN frame: ID 0x123 (standard), DLC 2, data [0xAA, 0xBB]
        let packet = vec![0x00, 0x00, 0x01, 0x23, 2, 0, 0, 0, 0xAA, 0xBB];
        let cap_len = packet.len() as u32;
        let pad_len = (4 - (cap_len % 4)) % 4;
        let epb_len = 32 + cap_len + pad_len;

        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(&epb_len.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let ts_us: u64 = 1_500_000;
        bytes.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
        bytes.extend_from_slice(&((ts_us & 0xFFFFFFFF) as u32).to_le_bytes());
        bytes.extend_from_slice(&cap_len.to_le_bytes());
        bytes.extend_from_slice(&cap_len.to_le_bytes());
        bytes.extend_from_slice(&packet);
        bytes.resize(bytes.len() + pad_len as usize, 0);
        bytes.extend_from_slice(&epb_len.to_le_bytes());

        let parsed = parse_pcapng_events(&bytes).expect("Parsed PCAP-NG");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].timestamp_us, 1_500_000);
        if let RawFrame::Can(c) = &parsed[0].payload {
            assert_eq!(c.id, CanId::Standard(0x123));
            assert_eq!(c.data.as_ref(), &[0xAA, 0xBB]);
        } else {
            panic!("Expected CAN frame");
        }
    }
}
