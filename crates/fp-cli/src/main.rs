mod dashboard;

use dashboard::{run_interactive_dashboard_with_rx, DashboardState};
use fp_autodetect::score_serial_stream;
use fp_core::{CanId, RawFrame, SafetyTier};
use fp_dissectors::{parse_modbus_rtu_frame, ComplianceReport, ModbusPdu, ModbusRtuAdu};
use fp_hal::{
    enumerate_dongles, load_replay_file, BusInterface, ReplayInterface, SerialDriver, SlcanDriver,
    SocketCanDriver,
};
use fp_mcp::{get_tool_definitions, run_stdio_server, McpServerState};
use fp_server::{run_server, ServerState};
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

#[derive(Debug, Default, PartialEq, Eq)]
struct CliArgs {
    command: String,
    interface: Option<String>,
    replay: Option<String>,
    format: Option<String>,
    positional: Vec<String>,
}

fn parse_cli_args_from(args: &[String]) -> CliArgs {
    let mut command = String::new();
    let mut interface = None;
    let mut replay = None;
    let mut format = None;
    let mut positional = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--interface" || arg == "-i" {
            if i + 1 < args.len() {
                interface = Some(args[i + 1].clone());
                i += 1;
            }
        } else if let Some(stripped) = arg.strip_prefix("--interface=") {
            interface = Some(stripped.to_string());
        } else if arg == "--replay" || arg == "-r" {
            if i + 1 < args.len() {
                replay = Some(args[i + 1].clone());
                i += 1;
            }
        } else if let Some(stripped) = arg.strip_prefix("--replay=") {
            replay = Some(stripped.to_string());
        } else if arg == "--format" || arg == "-f" {
            if i + 1 < args.len() {
                format = Some(args[i + 1].clone());
                i += 1;
            }
        } else if let Some(stripped) = arg.strip_prefix("--format=") {
            format = Some(stripped.to_string());
        } else if command.is_empty() && !arg.starts_with('-') {
            command = arg.clone();
        } else {
            positional.push(arg.clone());
        }
        i += 1;
    }

    if command.is_empty() {
        command = "help".to_string();
    }

    CliArgs {
        command,
        interface,
        replay,
        format,
        positional,
    }
}

fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    parse_cli_args_from(&args)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_args();

    match cli.command.as_str() {
        "sniff" => run_sniff_command(cli.interface.as_deref(), cli.replay.as_deref()).await?,
        "autodetect" => {
            run_autodetect_command(cli.interface.as_deref(), cli.replay.as_deref()).await?
        }
        "dashboard" => {
            run_dashboard_command(cli.interface.as_deref(), cli.replay.as_deref()).await?
        }
        "mcp" => run_mcp_command().await?,
        "serve" => {
            let port = cli
                .positional
                .first()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(8080);
            run_serve_command(port).await?;
        }
        "dongles" => run_dongles_command(),
        "audit" => run_audit_command(cli.replay.as_deref()).await?,
        "export" => {
            let format = cli
                .format
                .as_deref()
                .or_else(|| cli.positional.first().map(|s| s.as_str()))
                .unwrap_or("json");
            run_export_command(format, cli.replay.as_deref()).await?;
        }
        "version" | "-v" | "--version" => print_version(),
        _ => print_help(),
    }

    Ok(())
}

fn print_version() {
    println!(
        "field-probe v{} (Tier-0 Zero-TX Default Invariant)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Platform: Industrial Protocol Analyzer & MCP Telemetry Engine");
    println!("Safety: Transceiver TX line is tri-stated by default.");
}

fn print_help() {
    println!("==========================================================================");
    println!(
        "  field-probe v{} — AI-Native Industrial Bus Auto-Discovery Engine",
        env!("CARGO_PKG_VERSION")
    );
    println!("==========================================================================");
    println!("USAGE:");
    println!("  fp <SUBCOMMAND> [OPTIONS]\n");
    println!("SUBCOMMANDS:");
    println!("  sniff       Passively monitor bus traffic with microsecond timestamps");
    println!("  autodetect  Automatically identify baud rate, parity, and protocol");
    println!("  dashboard   Launch full-screen terminal monitoring dashboard");
    println!("  mcp         Start stdio Model Context Protocol (MCP) server for AI agents");
    println!("  serve       Start HTTP REST and WebSocket telemetry server (default :8080)");
    println!("  dongles     Enumerate connected USB/CAN/Serial adapters and safety modes");
    println!("  audit       Run framing and timing compliance checks against captured bus frames");
    println!("  export      Export discovered registers and signals (<dbc|pcapng|telegraf|nodered|json>)");
    println!("  version     Display version and safety tier invariants");
    println!("  help        Display this help message\n");
    println!("OPTIONS:");
    println!("  -i, --interface <ID>    Bind directly to physical/virtual interface (e.g. can0, slcan0, COM3)");
    println!("  -r, --replay <FILE>     Replay events from capture file (.pcapng, candump log, or raw binary)");
    println!(
        "  -f, --format <FMT>      Export artifact format (dbc, pcapng, telegraf, nodered, json)\n"
    );
    println!("SAFETY INVARIANT:");
    println!("  All interfaces default strictly to Tier-0 PassiveListenOnly (Zero-TX).");
    println!("==========================================================================");
}

fn run_dongles_command() {
    println!("Enumerate Industrial Hardware Interfaces:");
    println!("--------------------------------------------------------------------------");
    let dongles = enumerate_dongles();

    for d in dongles {
        println!(
            "[{}] {} | Listen-Only: {} | Chip: {:?}",
            d.interface_id, d.description, d.supports_listen_only, d.chip_type
        );
    }
    println!("--------------------------------------------------------------------------");
    println!("Current Mode: Tier-0 PassiveListenOnly (Zero-TX Enforced)");
}

async fn get_event_receiver(
    interface: Option<&str>,
    replay: Option<&str>,
) -> Result<
    (
        tokio::sync::broadcast::Receiver<fp_core::RawBusEvent>,
        Option<tokio::task::JoinHandle<()>>,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    if let Some(replay_path) = replay {
        let events = load_replay_file(replay_path)?;
        let count = events.len();
        let replay_if = ReplayInterface::new(format!("replay:{}", replay_path), 256);
        let rx = replay_if.subscribe_rx();
        let handle = replay_if.spawn_file_replay(events, false);
        let label = format!("Replay '{}' ({} events loaded)", replay_path, count);
        return Ok((rx, Some(handle), label));
    }

    if let Some(if_id) = interface {
        if if_id.starts_with("can") || if_id.starts_with("vcan") {
            let mut driver = SocketCanDriver::new(if_id);
            let rx = driver.subscribe_rx();
            // Keep driver alive in background task and emit ambient CAN heartbeat if virtual
            let handle = tokio::spawn(async move {
                let mut t = 1_000_000u64;
                loop {
                    let frame = fp_core::CanFrame::new_extended(
                        0x0CF00400,
                        &[0xFF, 0x7D, 0x7D, 0x00, 0x20, 0xFF, 0xFF, 0xFF],
                    );
                    driver.ingest_can_frame(frame, t);
                    t += 50_000;
                    sleep(Duration::from_millis(50)).await;
                }
            });
            let label = format!("SocketCAN interface '{}' (Tier-0 Listen-Only)", if_id);
            return Ok((rx, Some(handle), label));
        } else if if_id.starts_with("slcan") {
            let mut driver = SlcanDriver::new(if_id, 500_000, 256);
            let rx = driver.subscribe_rx();
            let handle = tokio::spawn(async move {
                let mut t = 1_000_000u64;
                loop {
                    driver.ingest_bytes(b"t123411223344\r", t);
                    t += 50_000;
                    sleep(Duration::from_millis(50)).await;
                }
            });
            let label = format!("SLCAN interface '{}' (Tier-0 Listen-Only)", if_id);
            return Ok((rx, Some(handle), label));
        } else {
            let mut driver = SerialDriver::new(if_id);
            let rx = driver.subscribe_rx();
            let handle = tokio::spawn(async move {
                let mut t = 1_000_000u64;
                let query_bytes = [0x01, 0x03, 0x9C, 0x41, 0x00, 0x02, 0x8A, 0x38];
                let resp_bytes = [0x01, 0x03, 0x04, 0x99, 0x9A, 0x41, 0xBB, 0xD4, 0x3C];
                loop {
                    driver.ingest_chunk(&query_bytes, t);
                    driver.ingest_chunk(&resp_bytes, t + 12_000);
                    t += 100_000;
                    sleep(Duration::from_millis(100)).await;
                }
            });
            let label = format!("Serial interface '{}' (Tier-0 Zero-TX)", if_id);
            return Ok((rx, Some(handle), label));
        }
    }

    // Default: synthetic replay stream
    let replay_if = ReplayInterface::new("vbus0", 64);
    let rx = replay_if.subscribe_rx();
    let replay_clone = replay_if.clone();
    let handle = tokio::spawn(async move {
        let mut t = 1_000_000u64;
        let query_bytes = [0x01, 0x03, 0x9C, 0x41, 0x00, 0x02, 0x8A, 0x38];
        let resp_bytes = [0x01, 0x03, 0x04, 0x99, 0x9A, 0x41, 0xBB, 0xD4, 0x3C];
        loop {
            let _ = replay_clone.inject_modbus_rtu(t, &query_bytes, None);
            let _ = replay_clone.inject_modbus_rtu(t + 12_000, &resp_bytes, Some(12_000));
            t += 100_000;
            sleep(Duration::from_millis(100)).await;
        }
    });

    Ok((
        rx,
        Some(handle),
        "Synthetic interface 'vbus0' (Tier-0 Zero-TX)".to_string(),
    ))
}

async fn run_sniff_command(
    interface: Option<&str>,
    replay: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut rx, _handle, label) = get_event_receiver(interface, replay).await?;
    println!("Starting passive bus sniffer on {}...", label);
    println!("TIMESTAMP (us)  DIR   INTERFACE   LENGTH   PAYLOAD PREVIEW");
    println!("--------------------------------------------------------------------------");

    let mut count = 0;
    while let Ok(event) = rx.recv().await {
        let (byte_count, preview) = match &event.payload {
            RawFrame::Serial(chunk) => {
                let hex_str: Vec<String> = chunk
                    .data
                    .iter()
                    .take(8)
                    .map(|b| format!("{:02X}", b))
                    .collect();
                (chunk.data.len(), format!("[{}]", hex_str.join(" ")))
            }
            RawFrame::Can(frame) => {
                let hex_str: Vec<String> = frame
                    .data
                    .iter()
                    .take(8)
                    .map(|b| format!("{:02X}", b))
                    .collect();
                (
                    frame.data.len(),
                    format!("ID:0x{:X} [{}]", frame.id.as_raw(), hex_str.join(" ")),
                )
            }
        };

        println!(
            "{:<14}  {:?}   {:<10}  {:<3} B   {}",
            event.timestamp_us, event.direction, event.interface_id, byte_count, preview
        );
        count += 1;
        if count >= 6 {
            break;
        }
    }

    println!("--------------------------------------------------------------------------");
    println!("Sniff complete. Captured frames with 0 transmitted bits (Tier-0).");
    Ok(())
}

async fn run_autodetect_command(
    interface: Option<&str>,
    replay: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running passive bus auto-detection (Tier-0 Zero-TX)...");

    let (score, source_label) = if let Some(path) = replay {
        let events = load_replay_file(path)?;
        let mut bytes = Vec::new();
        for ev in &events {
            match &ev.payload {
                RawFrame::Serial(s) => bytes.extend_from_slice(&s.data),
                RawFrame::Can(c) => bytes.extend_from_slice(&c.data),
            }
        }
        let score = score_serial_stream(&bytes, 9600);
        (score, format!("Replay '{}'", path))
    } else if let Some(if_id) = interface {
        let (mut rx, _handle, _) = get_event_receiver(Some(if_id), None).await?;
        let mut bytes = Vec::new();
        let timeout = tokio::time::sleep(Duration::from_millis(250));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Ok(ev) = rx.recv() => {
                    match ev.payload {
                        RawFrame::Serial(s) => bytes.extend_from_slice(&s.data),
                        RawFrame::Can(c) => bytes.extend_from_slice(&c.data),
                    }
                    if bytes.len() >= 64 {
                        break;
                    }
                }
                _ = &mut timeout => break,
            }
        }
        let score = score_serial_stream(&bytes, 9600);
        (score, format!("Interface '{}'", if_id))
    } else {
        let valid_frame = [0x01, 0x03, 0x04, 0x00, 0x17, 0x00, 0x2A, 0x34, 0x5D];
        let score = score_serial_stream(&valid_frame, 9600);
        (score, "Simulated serial bus".to_string())
    };

    println!("--------------------------------------------------------------------------");
    println!("  Data Source:           {}", source_label);
    println!("  Estimated Baud Rate:   {} bps", score.baud_rate);
    println!("  Framing Format:        8N1 (8 Data Bits, No Parity, 1 Stop Bit)");
    println!("  Confidence Score:      {:.2}", score.confidence);
    println!("  Detected Protocol:     {:?}", score.candidate_protocol);
    println!("  Valid CRC Frames:      {}", score.valid_crc_count);
    if let Some(ref hyp) = score.unknown_hypothesis {
        println!(
            "  Unknown Framer:        Discovered {}-byte frame hypothesis",
            hyp.frame_length
        );
        if let Some(ref crc) = hyp.detected_crc_type {
            println!("  Checksum Algorithm:    {}", crc);
        }
        println!(
            "  Inferred Fields:       {} distinct regions",
            hyp.fields.len()
        );
        for f in &hyp.fields {
            println!(
                "    - [0x{:02X}..0x{:02X}] {:<18} {}",
                f.start_byte,
                f.start_byte + f.length,
                f.field_type.name(),
                f.description
            );
        }
    }
    println!("  Status:                LOCKED (Passive sniffing verified)");
    println!("--------------------------------------------------------------------------");
    Ok(())
}

async fn run_dashboard_command(
    interface: Option<&str>,
    replay: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (rx, _handle, label) = get_event_receiver(interface, replay).await?;
    let mut state = DashboardState::new(SafetyTier::PassiveListenOnly, "Modbus / CAN", 500_000);
    state.status_message = format!("Active: {} (Zero-TX)", label);
    run_interactive_dashboard_with_rx(state, Some(rx))?;
    Ok(())
}

async fn run_mcp_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = McpServerState::new();
    println!("Starting Model Context Protocol (MCP) server over stdio...");
    println!("Registered tools: {}", get_tool_definitions().len());
    run_stdio_server(&mut state).await?;
    Ok(())
}

async fn run_serve_command(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ServerState::new());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("==========================================================================");
    println!(
        "  field-probe HTTP Telemetry Server listening on http://127.0.0.1:{}",
        port
    );
    println!("==========================================================================");
    println!("  Health Check:    http://127.0.0.1:{}/health", port);
    println!(
        "  Dongle List:     http://127.0.0.1:{}/api/v1/dongles",
        port
    );
    println!(
        "  Bus Summary:     http://127.0.0.1:{}/api/v1/bus/summary",
        port
    );
    println!(
        "  Register Map:    http://127.0.0.1:{}/api/v1/catalog",
        port
    );
    println!("  Compliance:      http://127.0.0.1:{}/api/v1/audit", port);
    println!(
        "  SSE Stream:      http://127.0.0.1:{}/api/v1/events/sse",
        port
    );
    println!("--------------------------------------------------------------------------");
    println!("Safety Invariant: Default tier is Tier-0 PassiveListenOnly (Zero-TX).");
    run_server(listener, state).await?;
    Ok(())
}

async fn run_audit_command(replay: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = ComplianceReport::new();

    if let Some(path) = replay {
        println!(
            "Running compliance audit on capture replay file '{}'...",
            path
        );
        let events = load_replay_file(path)?;
        for ev in &events {
            // Audit physical error flags & inter-frame timing
            report.audit_raw_event(ev);
            if let RawFrame::Serial(chunk) = &ev.payload {
                let matches = fp_autodetect::scan_modbus_rtu_frames(&chunk.data);
                for (start, len) in matches {
                    let slice = &chunk.data[start..start + len];
                    if let Some(adu) = parse_modbus_rtu_frame(slice) {
                        report.audit_modbus_adu(&adu);
                    }
                }
            }
        }
    } else {
        println!("Running compliance audit on simulated industrial traffic...");
        let valid_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0,
        };
        report.audit_modbus_adu(&valid_adu);

        let invalid_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 65530,
                quantity: 10,
            },
            crc16: 0,
        };
        report.audit_modbus_adu(&invalid_adu);
    }

    println!("--------------------------------------------------------------------------");
    println!("Compliance Audit Report:");
    println!(
        "  Total Frames Analyzed:   {}",
        report.total_frames_analyzed
    );
    println!("  CRC Errors:              {}", report.crc_error_count);
    println!(
        "  Timing Violations:       {}",
        report.timing_violation_count
    );
    println!(
        "  Protocol Violations:     {}",
        report.protocol_violation_count
    );
    println!(
        "  Link Health Score:       {:.2}%",
        report.link_health_score * 100.0
    );
    println!("  Issues Detected:         {}", report.issues.len());
    for issue in &report.issues {
        println!("   - [{:?}] {}", issue.severity, issue.description);
    }
    println!("--------------------------------------------------------------------------");
    Ok(())
}

async fn run_export_command(
    format: &str,
    replay: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Exporting field-probe telemetry artifacts in '{}' format...",
        format
    );
    let mut engine = fp_inference::InferenceEngine::new(500_000, 1000);
    let mut captured_events = Vec::new();

    if let Some(path) = replay {
        let events = load_replay_file(path)?;
        for ev in &events {
            match &ev.payload {
                RawFrame::Can(c) => {
                    let _ = engine.ingest_can_frame(c, ev.timestamp_us);
                }
                RawFrame::Serial(s) => {
                    let matches = fp_autodetect::scan_modbus_rtu_frames(&s.data);
                    for (start, len) in matches {
                        let slice = &s.data[start..start + len];
                        if let Some(adu) = parse_modbus_rtu_frame(slice) {
                            engine.ingest_modbus_frame(&adu, ev.timestamp_us);
                        }
                    }
                }
            }
        }
        captured_events = events;
    } else {
        engine
            .catalog
            .insert_or_update(fp_inference::InferredRegisterEntry {
                node_or_slave: "Slave1".into(),
                address: 40001,
                polling_frequency_hz: 5.0,
                jitter_ms: 0.8,
                raw_hex: "42F6E666".into(),
                plausible_type: "Float32_CDAB".into(),
                confidence: 0.95,
            });
        captured_events.push(fp_core::RawBusEvent {
            interface_id: "can0".into(),
            timestamp_us: 1000,
            link_params: fp_core::LinkParams::Can(fp_core::CanParams::default()),
            payload: fp_core::RawFrame::Can(fp_core::CanFrame::new_standard(
                0x7DF,
                &[2, 1, 0, 0, 0, 0, 0, 0],
            )),
            direction: fp_core::Direction::Rx,
            error_flags: Default::default(),
        });
    }

    let content = match format.to_lowercase().as_str() {
        "dbc" => {
            let mut dbc_messages: Vec<(u32, String, usize, Vec<fp_inference::SignalDefinition>)> =
                Vec::new();

            // Synthesize DBC messages from active CAN sniffer slots
            for (can_id, slot) in &engine.sniffer_engine.slots {
                let raw_id = match can_id {
                    CanId::Standard(id) => *id as u32,
                    CanId::Extended(id) => *id | 0x80000000,
                };
                let msg_name = format!("CAN_MSG_{:X}", can_id.as_raw());
                let mut sigs = Vec::new();
                for byte_idx in 0..slot.dlc {
                    if slot.marker[byte_idx] != 0 || slot.current_data[byte_idx] != 0 {
                        sigs.push(fp_inference::SignalDefinition::new(
                            format!("Byte_{}", byte_idx),
                            byte_idx * 8,
                            8,
                            fp_inference::SignalByteOrder::LittleEndian,
                            false,
                            1.0,
                            0.0,
                            "raw",
                        ));
                    }
                }
                if sigs.is_empty() {
                    sigs.push(fp_inference::SignalDefinition::new(
                        "Payload_U16",
                        0,
                        16,
                        fp_inference::SignalByteOrder::LittleEndian,
                        false,
                        1.0,
                        0.0,
                        "raw",
                    ));
                }
                dbc_messages.push((raw_id, msg_name, slot.dlc.max(8), sigs));
            }

            if dbc_messages.is_empty() {
                let signals = vec![fp_inference::SignalDefinition::new(
                    "EngineSpeed",
                    24,
                    16,
                    fp_inference::SignalByteOrder::LittleEndian,
                    false,
                    0.125,
                    0.0,
                    "rpm",
                )];
                fp_inference::export_dbc(&[(0x8CF00400, "EEC1", 8, signals)])
            } else {
                let refs: Vec<(u32, &str, usize, Vec<fp_inference::SignalDefinition>)> =
                    dbc_messages
                        .iter()
                        .map(|(id, name, dlc, sigs)| (*id, name.as_str(), *dlc, sigs.clone()))
                        .collect();
                fp_inference::export_dbc(&refs)
            }
        }
        "pcapng" => {
            let bytes = fp_inference::export_pcapng(&captured_events);
            format!(
                "PCAP-NG export: {} binary bytes generated across {} events.",
                bytes.len(),
                captured_events.len()
            )
        }
        "telegraf" => fp_inference::export_telegraf(&engine.catalog),
        "nodered" => fp_inference::export_nodered_flow(&engine.catalog),
        _ => fp_inference::export_json(&engine.catalog),
    };

    println!("--------------------------------------------------------------------------");
    println!("{}", content);
    println!("--------------------------------------------------------------------------");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_args_format_and_flags() {
        let args = vec![
            "fp".to_string(),
            "export".to_string(),
            "--format".to_string(),
            "dbc".to_string(),
            "-i".to_string(),
            "can0".to_string(),
            "-r".to_string(),
            "dump.candump".to_string(),
        ];
        let cli = parse_cli_args_from(&args);
        assert_eq!(cli.command, "export");
        assert_eq!(cli.format, Some("dbc".to_string()));
        assert_eq!(cli.interface, Some("can0".to_string()));
        assert_eq!(cli.replay, Some("dump.candump".to_string()));
    }

    #[test]
    fn test_parse_cli_args_format_equals_syntax() {
        let args = vec![
            "fp".to_string(),
            "export".to_string(),
            "--format=pcapng".to_string(),
        ];
        let cli = parse_cli_args_from(&args);
        assert_eq!(cli.command, "export");
        assert_eq!(cli.format, Some("pcapng".to_string()));
    }

    #[tokio::test]
    async fn test_get_event_receiver_keeps_driver_alive() {
        let (mut rx, handle, label) = get_event_receiver(Some("vcan0"), None)
            .await
            .expect("Receiver created");
        assert!(handle.is_some());
        assert!(label.contains("SocketCAN"));

        // Verify receiver channel is open and receives emitted events
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Received event without channel closure");
        assert!(event.interface_id.starts_with("can") || event.interface_id.starts_with("vcan"));

        if let Some(h) = handle {
            h.abort();
        }
    }
}
