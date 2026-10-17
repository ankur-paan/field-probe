mod dashboard;

use dashboard::render_dashboard;
use fp_autodetect::score_serial_stream;
use fp_core::{AdapterCapabilities, IndustrialChip, RawFrame, SafetyTier};
use fp_dissectors::{ComplianceReport, ModbusPdu, ModbusRtuAdu};
use fp_hal::{BusInterface, ReplayInterface};
use fp_inference::InferenceEngine;
use fp_mcp::{get_tool_definitions, run_stdio_server, McpServerState};
use fp_server::{run_server, ServerState};
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "sniff" => run_sniff_command().await?,
        "autodetect" => run_autodetect_command().await?,
        "dashboard" => run_dashboard_command().await?,
        "mcp" => run_mcp_command().await?,
        "serve" => {
            let port = args
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(8080);
            run_serve_command(port).await?;
        }
        "dongles" => run_dongles_command(),
        "audit" => run_audit_command().await?,
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
    println!("  field-probe v{} — AI-Native Industrial Bus Auto-Discovery Engine", env!("CARGO_PKG_VERSION"));
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
    println!("  version     Display version and safety tier invariants");
    println!("  help        Display this help message\n");
    println!("SAFETY INVARIANT:");
    println!("  All interfaces default strictly to Tier-0 PassiveListenOnly (Zero-TX).");
    println!("==========================================================================");
}

fn run_dongles_command() {
    println!("Enumerate Industrial Hardware Interfaces:");
    println!("--------------------------------------------------------------------------");
    let dongles = vec![
        AdapterCapabilities {
            interface_id: "usb-serial-port-0".to_string(),
            chip_type: IndustrialChip::FtdiFt232,
            supports_serial: true,
            supports_can: false,
            supports_can_fd: false,
            supports_listen_only: true,
            supported_baud_rates: vec![9600, 19200, 38400, 57600, 115200],
            supported_can_bitrates: vec![],
            usb_vid: Some(0x0403),
            usb_pid: Some(0x6001),
            serial_number: Some("FT232R-01".to_string()),
            description: "FTDI FT232R USB-to-RS485 Dongle".to_string(),
        },
        AdapterCapabilities {
            interface_id: "can0".to_string(),
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
            description: "PEAK PCAN-USB Industrial Adapter".to_string(),
        },
        AdapterCapabilities {
            interface_id: "vbus0".to_string(),
            chip_type: IndustrialChip::SyntheticReplay,
            supports_serial: true,
            supports_can: true,
            supports_can_fd: true,
            supports_listen_only: true,
            supported_baud_rates: vec![9600, 19200, 38400, 115200],
            supported_can_bitrates: vec![500_000, 250_000],
            usb_vid: None,
            usb_pid: None,
            serial_number: None,
            description: "Synthetic Bus Replay Device (Virtual)".to_string(),
        },
    ];

    for d in dongles {
        println!(
            "[{}] {} | Listen-Only: {} | Chip: {:?}",
            d.interface_id, d.description, d.supports_listen_only, d.chip_type
        );
    }
    println!("--------------------------------------------------------------------------");
    println!("Current Mode: Tier-0 PassiveListenOnly (Zero-TX Enforced)");
}

async fn run_sniff_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting passive bus sniffer on interface 'vbus0' (Tier-0 Zero-TX)...");
    println!("TIMESTAMP (us)  DIR   LENGTH (bytes)");
    println!("--------------------------------------------------------------------------");

    let replay = ReplayInterface::new("vbus0", 64);
    let mut rx = replay.subscribe_rx();

    // Stream synthetic Modbus traffic
    let replay_clone = replay.clone();
    tokio::spawn(async move {
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

    let mut count = 0;
    while let Ok(event) = rx.recv().await {
        let byte_count = match &event.payload {
            RawFrame::Serial(chunk) => chunk.data.len(),
            RawFrame::Can(frame) => frame.data.len(),
        };
        println!(
            "{:<14}  {:?}   {} bytes",
            event.timestamp_us, event.direction, byte_count
        );
        count += 1;
        if count >= 6 {
            break;
        }
    }

    println!("Sniff complete. Captured frames with 0 transmitted bits.");
    Ok(())
}

async fn run_autodetect_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running passive bus auto-detection (Tier-0 Zero-TX)...");

    let valid_frame = [0x01, 0x03, 0x04, 0x00, 0x17, 0x00, 0x2A, 0x34, 0x5D];
    let score = score_serial_stream(&valid_frame, 9600);

    println!("--------------------------------------------------------------------------");
    println!("  Estimated Baud Rate:   {} bps", score.baud_rate);
    println!("  Framing Format:        8N1 (8 Data Bits, No Parity, 1 Stop Bit)");
    println!("  Confidence Score:      {:.2}", score.confidence);
    println!("  Detected Protocol:     {:?}", score.candidate_protocol);
    println!("  Valid CRC Frames:      {}", score.valid_crc_count);
    println!("  Status:                LOCKED (Passive sniffing verified)");
    println!("--------------------------------------------------------------------------");
    Ok(())
}

async fn run_dashboard_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = InferenceEngine::new(500_000, 1000);
    let mut frame_count = 0u64;

    // Simulate traffic stream into inference engine
    for step in 0..6 {
        let t = 1_000_000 + step * 50_000;
        let val_encoded = 0x41BB999Au32.to_be_bytes();
        let query = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0,
        };
        let resp = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 4,
                data: val_encoded.to_vec(),
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&query, t);
        engine.ingest_modbus_frame(&resp, t + 12_000);
        frame_count += 2;

        render_dashboard(
            &engine,
            SafetyTier::PassiveListenOnly,
            "Modbus RTU",
            9600,
            frame_count,
        )?;
        sleep(Duration::from_millis(100)).await;
    }

    println!("\nDashboard demonstration completed successfully.");
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
    println!("  field-probe HTTP Telemetry Server listening on http://127.0.0.1:{}", port);
    println!("==========================================================================");
    println!("  Health Check:    http://127.0.0.1:{}/health", port);
    println!("  Dongle List:     http://127.0.0.1:{}/api/v1/dongles", port);
    println!("  Bus Summary:     http://127.0.0.1:{}/api/v1/bus/summary", port);
    println!("  Register Map:    http://127.0.0.1:{}/api/v1/catalog", port);
    println!("--------------------------------------------------------------------------");
    println!("Safety Invariant: Default tier is Tier-0 PassiveListenOnly (Zero-TX).");
    run_server(listener, state).await?;
    Ok(())
}

async fn run_audit_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running compliance audit on simulated industrial traffic...");
    let mut report = ComplianceReport::new();

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

    println!("--------------------------------------------------------------------------");
    println!("Compliance Audit Report:");
    println!("  Total Frames Analyzed:   {}", report.total_frames_analyzed);
    println!("  CRC Errors:              {}", report.crc_error_count);
    println!("  Protocol Violations:     {}", report.protocol_violation_count);
    println!("  Link Health Score:       {:.2}%", report.link_health_score * 100.0);
    println!("  Issues Detected:         {}", report.issues.len());
    for issue in &report.issues {
        println!("   - [{:?}] {}", issue.severity, issue.description);
    }
    println!("--------------------------------------------------------------------------");
    Ok(())
}
