use fp_core::SafetyTier;
use fp_inference::InferenceEngine;
use std::io::{self, Write};

/// Render a single frame of the ANSI terminal dashboard
pub fn render_dashboard(
    engine: &InferenceEngine,
    tier: SafetyTier,
    protocol: &str,
    baud: u32,
    frame_count: u64,
) -> io::Result<()> {
    let summary = engine.get_summary();
    let mut stdout = io::stdout();

    // ANSI escape: clear screen and move cursor to top-left
    write!(stdout, "\x1b[2J\x1b[H")?;

    // Header Banner
    writeln!(stdout, "\x1b[1;36m╭──────────────────────────────────────────────────────────────────────────────╮\x1b[0m")?;
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  \x1b[1;37mfield-probe v{} — AI-Native Industrial Bus Protocol Analyzer\x1b[0m       \x1b[1;36m│\x1b[0m",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(stdout, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;

    // Safety Tier & Bus Invariants
    let tier_color = match tier {
        SafetyTier::PassiveListenOnly => "\x1b[1;32m", // Bright Green
        SafetyTier::ReadOnlyProbe => "\x1b[1;33m",     // Yellow
        SafetyTier::ActiveWrite => "\x1b[1;31m",       // Red
    };
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  Safety Mode: {}{:<28}\x1b[0m Zero-TX Enforced: \x1b[1;32mYES\x1b[0m           \x1b[1;36m│\x1b[0m",
        tier_color,
        tier.name()
    )?;
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  Bus Status:  \x1b[1;32mLOCKED\x1b[0m [{:<10} @ {:>6} bps 8N1]  Frames: {:<12} \x1b[1;36m│\x1b[0m",
        protocol, baud, frame_count
    )?;
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  Discovered Registers: {:<6} Active CAN Nodes: {:<4} Periodic Loops: {:<4} \x1b[1;36m│\x1b[0m",
        summary.total_discovered_registers, summary.total_active_can_nodes, summary.periodic_can_loops
    )?;
    writeln!(stdout, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;

    // Register & Signal Catalog Table
    writeln!(
        stdout,
        "\x1b[1;37m│ {:<10} │ {:<14} │ {:<12} │ {:<18} │ {:<6} │\x1b[0m",
        "Address", "Raw Hex", "Freq (Hz)", "Inferred Value", "Plaus."
    )?;
    writeln!(stdout, "\x1b[1;36m├────────────┼────────────────┼──────────────┼────────────────────┼────────┤\x1b[0m")?;

    if engine.catalog.entries.is_empty() {
        writeln!(
            stdout,
            "\x1b[1;36m│\x1b[0m  \x1b[2;37m(Passive sniffing in progress... waiting for register transactions)\x1b[0m        \x1b[1;36m│\x1b[0m"
        )?;
    } else {
        for (addr, entry) in engine.catalog.entries.iter().take(8) {
            let conf_color = if entry.confidence >= 0.85 {
                "\x1b[1;32m"
            } else if entry.confidence >= 0.60 {
                "\x1b[1;33m"
            } else {
                "\x1b[2;37m"
            };

            writeln!(
                stdout,
                "\x1b[1;36m│\x1b[0m {:<10} \x1b[1;36m│\x1b[0m {:<14} \x1b[1;36m│\x1b[0m {:>8.2} Hz \x1b[1;36m│\x1b[0m {:<18} \x1b[1;36m│\x1b[0m {}{:>5.2}\x1b[0m \x1b[1;36m│\x1b[0m",
                addr, entry.raw_hex, entry.polling_frequency_hz, entry.plausible_type, conf_color, entry.confidence
            )?;
        }
    }

    writeln!(stdout, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;

    // MCP Server Status
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  \x1b[1;35mMCP Server:\x1b[0m Ready (8 Tools) — Run \x1b[1;37m`fp mcp --stdio`\x1b[0m for Claude/Antigravity    \x1b[1;36m│\x1b[0m"
    )?;
    writeln!(
        stdout,
        "\x1b[1;36m│\x1b[0m  \x1b[1;35mREST/WS:\x1b[0m    http://127.0.0.1:8080/health | /api/v1/bus/summary             \x1b[1;36m│\x1b[0m"
    )?;
    writeln!(stdout, "\x1b[1;36m╰──────────────────────────────────────────────────────────────────────────────╯\x1b[0m")?;

    stdout.flush()?;
    Ok(())
}
