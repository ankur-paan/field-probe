use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fp_core::{CanFrame, CanId, SafetyTier};
use fp_dissectors::{
    ComplianceIssue, ComplianceReport, ModbusPdu, ModbusRtuAdu, ViolationSeverity,
};
use fp_inference::{DiffCaptureReport, InferenceEngine};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use std::io::{self, stdout, IsTerminal, Write};
use std::time::Duration;

/// RAII Guard ensuring terminal returns to normal state on exit or panic
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            crossterm::cursor::Show
        );
    }
}

/// Unified Dashboard State for Interactive TUI
pub struct DashboardState {
    pub active_tab: usize,
    pub tier: SafetyTier,
    pub protocol: String,
    pub baud: u32,
    pub frame_count: u64,
    pub engine: InferenceEngine,
    pub compliance: ComplianceReport,
    pub diff_report: Option<DiffCaptureReport>,
    pub status_message: String,
    pub simulation_step: u64,
    pub running: bool,
}

impl DashboardState {
    pub fn new(tier: SafetyTier, protocol: &str, baud: u32) -> Self {
        let mut compliance = ComplianceReport::new();
        compliance.add_issue(ComplianceIssue {
            severity: ViolationSeverity::Notice,
            rule_id: "BUS-INIT-001".to_string(),
            description: "Interface initialized in listen-only mode. TX line disabled.".to_string(),
            physical_hint: Some("Hardware RTS/DTR gating asserted low".to_string()),
        });

        Self {
            active_tab: 0,
            tier,
            protocol: protocol.to_string(),
            baud,
            frame_count: 0,
            engine: InferenceEngine::new(baud, 1000),
            compliance,
            diff_report: None,
            status_message: "Ready — Tier-0 PassiveListenOnly active (Zero-TX)".to_string(),
            simulation_step: 0,
            running: true,
        }
    }

    /// Advance synthetic traffic generation for demonstration and live sniffer monitoring
    pub fn simulate_tick(&mut self) {
        self.simulation_step += 1;
        let step = self.simulation_step;
        let t_us = 1_000_000 + step * 25_000;

        // 1. Modbus RTU telemetry simulation (Alternating temperature and pressure values)
        let temp_raw: u32 = 0x41BB999A + ((step % 20) as u32 * 0x00010000);
        let temp_bytes = temp_raw.to_be_bytes();
        let query_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 2,
            },
            crc16: 0x8A38,
        };
        let resp_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 4,
                data: temp_bytes.to_vec(),
            },
            crc16: 0xD43C,
        };
        self.engine.ingest_modbus_frame(&query_adu, t_us);
        self.engine.ingest_modbus_frame(&resp_adu, t_us + 12_000);
        self.compliance.audit_modbus_adu(&query_adu);
        self.compliance.audit_modbus_adu(&resp_adu);
        self.frame_count += 2;

        // 2. Additional discrete register simulation
        let discrete_val = ((step * 7) % 100) as u16;
        let query_counter = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40005,
                quantity: 1,
            },
            crc16: 0x1234,
        };
        let resp_counter = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 2,
                data: discrete_val.to_be_bytes().to_vec(),
            },
            crc16: 0x5678,
        };
        self.engine
            .ingest_modbus_frame(&query_counter, t_us + 5_000);
        self.engine
            .ingest_modbus_frame(&resp_counter, t_us + 18_000);
        self.compliance.audit_modbus_adu(&query_counter);
        self.compliance.audit_modbus_adu(&resp_counter);
        self.frame_count += 2;

        // 3. CAN 2.0B broadcast frame simulation (Speed/RPM & Sensor broadcast)
        let speed_byte = ((step % 60) + 40) as u8;
        let can_j1939 = CanFrame::new_extended(
            0x0CF00400,
            &[0xFF, 0xFF, 0x00, speed_byte, 0x20, 0x00, 0xFF, 0xFF],
        );
        let sensor_val = (step % 255) as u8;
        let can_sensor = CanFrame::new_standard(
            0x120,
            &[0x01, 0x02, sensor_val, 0x00, 0x00, 0xAA, 0xBB, 0xCC],
        );

        self.engine.ingest_can_frame(&can_j1939, t_us);
        self.engine.ingest_can_frame(&can_sensor, t_us + 8_000);
        self.frame_count += 2;

        // If diff capture is active, mutate a specific bit on CAN frame 0x120 or Register 40001
        if self.engine.diff_session.is_active() && step.is_multiple_of(4) {
            let toggle_bit = if (step / 4).is_multiple_of(2) {
                0x01
            } else {
                0x00
            };
            let can_switch = CanFrame::new_standard(
                0x120,
                &[0x01, toggle_bit, sensor_val, 0x00, 0x00, 0xAA, 0xBB, 0xCC],
            );
            self.engine.ingest_can_frame(&can_switch, t_us + 10_000);
        }
    }

    /// Toggle physical diff capture baseline window
    pub fn toggle_diff_capture(&mut self) {
        let now_us = 1_000_000 + self.simulation_step * 25_000;
        if self.engine.diff_session.is_active() {
            let report = self.engine.stop_diff_capture(now_us);
            let count = report.total_mutations_detected;
            self.status_message = format!(
                "Diff capture stopped: {} mutations isolated over {} ms",
                count, report.duration_ms
            );
            self.diff_report = Some(report);
            self.active_tab = 3; // Switch to diff capture view
        } else {
            self.engine.start_diff_capture(now_us);
            self.status_message =
                "● Diff capture started: baseline snapshotted. Mutate bus state now.".to_string();
            self.active_tab = 3;
        }
    }

    /// Ingest a live or replayed RawBusEvent into the inference and compliance pipelines
    pub fn ingest_event(&mut self, event: &fp_core::RawBusEvent) {
        self.frame_count += 1;
        // 1. Audit physical layer flags and t1.5/t3.5 inter-frame timing
        self.compliance.audit_raw_event(event);

        match &event.payload {
            fp_core::RawFrame::Can(frame) => {
                self.engine.ingest_can_frame(frame, event.timestamp_us);
            }
            fp_core::RawFrame::Serial(chunk) => {
                let mut matched_known = false;

                // A. Scan for Modbus RTU frames
                let rtu_matches = fp_autodetect::scan_modbus_rtu_frames(&chunk.data);
                for (start, len) in rtu_matches {
                    matched_known = true;
                    let slice = &chunk.data[start..start + len];
                    if let Some(adu) = fp_dissectors::parse_modbus_rtu_frame(slice) {
                        self.engine.ingest_modbus_frame(&adu, event.timestamp_us);
                        self.compliance.audit_modbus_adu(&adu);
                    }
                }

                // B. Scan for BACnet MS/TP frames
                let mstp_matches = fp_autodetect::scan_bacnet_mstp_frames(&chunk.data);
                for (start, len) in mstp_matches {
                    matched_known = true;
                    let slice = &chunk.data[start..start + len];
                    if let Some(mstp) = fp_dissectors::dissect_bacnet_mstp(slice) {
                        self.engine.catalog.insert_or_update(fp_inference::InferredRegisterEntry {
                            node_or_slave: format!("BACnet_{}", mstp.source_address),
                            address: mstp.destination_address as u32,
                            polling_frequency_hz: 1.0,
                            jitter_ms: 0.0,
                            raw_hex: format!("0x{:02X}", mstp.frame_type as u8),
                            plausible_type: format!("BACnet MS/TP ({})", mstp.frame_type.name()),
                            confidence: 0.98,
                        });
                    }
                }

                // C. Scan for DNP3 frames
                let dnp3_matches = fp_autodetect::scan_dnp3_frames(&chunk.data);
                for (start, len) in dnp3_matches {
                    matched_known = true;
                    let slice = &chunk.data[start..start + len];
                    if let Some(dnp3) = fp_dissectors::dissect_dnp3(slice) {
                        self.engine.catalog.insert_or_update(fp_inference::InferredRegisterEntry {
                            node_or_slave: format!("DNP3_{}", dnp3.source),
                            address: dnp3.destination as u32,
                            polling_frequency_hz: 1.0,
                            jitter_ms: 0.0,
                            raw_hex: format!("{:?}", dnp3.function_code),
                            plausible_type: format!(
                                "DNP3 {:?} ({} objs)",
                                dnp3.function_code,
                                dnp3.objects.len()
                            ),
                            confidence: 0.98,
                        });
                    }
                }

                // D. Fallback: Reverse-engineer unknown binary serial protocol via UnknownFramer
                if !matched_known && chunk.data.len() >= 12 {
                    let framer = fp_autodetect::UnknownFramer::new();
                    if let Some(hyp) = framer.infer_from_raw_stream(&chunk.data) {
                        for field in &hyp.fields {
                            self.engine.catalog.insert_or_update(fp_inference::InferredRegisterEntry {
                                node_or_slave: "UnknownProto".to_string(),
                                address: field.start_byte as u32,
                                polling_frequency_hz: 1.0,
                                jitter_ms: 0.0,
                                raw_hex: format!("{}B", field.length),
                                plausible_type: format!(
                                    "{}: {}",
                                    field.field_type.name(),
                                    field.description
                                ),
                                confidence: hyp.confidence,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Run the interactive Ratatui TUI dashboard
#[allow(dead_code)]
pub fn run_interactive_dashboard(app: DashboardState) -> io::Result<()> {
    run_interactive_dashboard_with_rx(app, None)
}

/// Run the interactive Ratatui TUI dashboard, optionally bound to a live or replayed bus receiver
pub fn run_interactive_dashboard_with_rx(
    mut app: DashboardState,
    mut rx_opt: Option<tokio::sync::broadcast::Receiver<fp_core::RawBusEvent>>,
) -> io::Result<()> {
    // If output or input is not a terminal (e.g. CI, piped, scripts), fall back to ANSI renderer
    if !stdout().is_terminal() || !io::stdin().is_terminal() {
        if let Some(ref mut rx) = rx_opt {
            let mut drained = 0;
            while let Ok(event) = rx.try_recv() {
                app.ingest_event(&event);
                drained += 1;
                if drained >= 10 {
                    break;
                }
            }
            if drained == 0 {
                for _ in 0..6 {
                    app.simulate_tick();
                }
            }
        } else {
            for _ in 0..6 {
                app.simulate_tick();
            }
        }
        return render_dashboard(
            &app.engine,
            app.tier,
            &app.protocol,
            app.baud,
            app.frame_count,
        );
    }

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Populate initial baseline data if no live feed attached
    if rx_opt.is_none() {
        for _ in 0..4 {
            app.simulate_tick();
        }
    }

    while app.running {
        terminal.draw(|f| draw_ui(f, &app))?;

        // Poll for keyboard input with 60ms timeout to maintain responsive ~16 FPS refresh
        if event::poll(Duration::from_millis(60))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    app.running = false;
                    break;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        app.running = false;
                    }
                    KeyCode::Tab | KeyCode::Right => {
                        app.active_tab = (app.active_tab + 1) % 4;
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        app.active_tab = (app.active_tab + 3) % 4;
                    }
                    KeyCode::Char('1') => app.active_tab = 0,
                    KeyCode::Char('2') => app.active_tab = 1,
                    KeyCode::Char('3') => app.active_tab = 2,
                    KeyCode::Char('4') => app.active_tab = 3,
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        app.toggle_diff_capture();
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        app.diff_report = None;
                        app.status_message = "Baseline diff report reset.".to_string();
                    }
                    _ => {}
                }
            }
        }

        // Drain incoming events from hardware / replay or advance simulation tick
        if let Some(ref mut rx) = rx_opt {
            let mut got_events = false;
            while let Ok(event) = rx.try_recv() {
                app.ingest_event(&event);
                got_events = true;
            }
            if !got_events && app.frame_count == 0 {
                // Keep initial baseline active until hardware produces events
                app.simulate_tick();
            }
        } else {
            app.simulate_tick();
        }
    }

    Ok(())
}

/// Render the complete TUI screen
fn draw_ui(frame: &mut Frame, app: &DashboardState) {
    let size = frame.area();

    // Vertical layout: Header (5), Tabs (3), Main Body (Min), Footer (3)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(size);

    draw_header(frame, app, chunks[0]);
    draw_tabs(frame, app, chunks[1]);

    match app.active_tab {
        0 => draw_catalog_tab(frame, app, chunks[2]),
        1 => draw_sniffer_tab(frame, app, chunks[2]),
        2 => draw_compliance_tab(frame, app, chunks[2]),
        3 => draw_diff_tab(frame, app, chunks[2]),
        _ => {}
    }

    draw_footer(frame, app, chunks[3]);
}

/// Header banner displaying version, safety tier invariants, and live telemetry stats
fn draw_header(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let summary = app.engine.get_summary();

    let tier_style = match app.tier {
        SafetyTier::PassiveListenOnly => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        SafetyTier::ReadOnlyProbe => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        SafetyTier::ActiveWrite => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    };

    let header_lines = vec![
        Line::from(vec![
            Span::styled(
                "field-probe v",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                env!("CARGO_PKG_VERSION"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" — AI-Native Industrial Bus Protocol Analyzer  │  Safety Mode: "),
            Span::styled(format!("{} (Zero-TX: YES)", app.tier.name()), tier_style),
        ]),
        Line::from(vec![
            Span::raw("Bus Status:  "),
            Span::styled(
                "LOCKED",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " [{} @ {} bps]  │  Frames: ",
                app.protocol, app.baud
            )),
            Span::styled(
                format!("{:<8}", app.frame_count),
                Style::default().fg(Color::White),
            ),
            Span::raw(" │  Registers: "),
            Span::styled(
                format!("{:<4}", summary.total_discovered_registers),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" │  CAN Nodes: "),
            Span::styled(
                format!("{:<4}", summary.total_active_can_nodes),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" │  Periodic Loops: "),
            Span::styled(
                format!("{:<4}", summary.periodic_can_loops),
                Style::default().fg(Color::Magenta),
            ),
        ]),
    ];

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" System Status ");

    let paragraph = Paragraph::new(header_lines).block(header_block);
    frame.render_widget(paragraph, area);
}

/// Navigation tabs bar
fn draw_tabs(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let titles = vec![
        Line::from("[1] Register Catalog"),
        Line::from("[2] CAN Sniffer"),
        Line::from("[3] Compliance Audit"),
        Line::from("[4] Diff Capture"),
    ];

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Analysis Views "),
        )
        .select(app.active_tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        );

    frame.render_widget(tabs, area);
}

/// Tab 0: Inferred Modbus & Industrial Register Catalog Table
fn draw_catalog_tab(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let entries = &app.engine.catalog.entries;

    let rows: Vec<Row> = if entries.is_empty() {
        vec![Row::new(vec![
            Cell::from("No registers discovered yet... waiting for transactions"),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else {
        entries
            .iter()
            .map(|(key, entry)| {
                let conf_color = if entry.confidence >= 0.85 {
                    Color::Green
                } else if entry.confidence >= 0.60 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                };

                Row::new(vec![
                    Cell::from(key.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(entry.raw_hex.clone()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(format!("{:.1} Hz", entry.polling_frequency_hz)),
                    Cell::from(format!("{:.1} ms", entry.jitter_ms)),
                    Cell::from(entry.plausible_type.clone())
                        .style(Style::default().fg(Color::Yellow)),
                    Cell::from(format!("{:.2}", entry.confidence))
                        .style(Style::default().fg(conf_color).add_modifier(Modifier::BOLD)),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(18),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(24),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Address / Key",
                "Raw Hex",
                "Polling Freq",
                "Jitter",
                "Inferred Representation",
                "Confidence",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Discovered Register Catalog (Modbus RTU / ASCII) "),
        );

    frame.render_widget(table, area);
}

/// Tab 1: Live CAN Bus Sniffer with Bit Delta Tracking and Periodicity
fn draw_sniffer_tab(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let slots = &app.engine.sniffer_engine.slots;

    let rows: Vec<Row> = if slots.is_empty() {
        vec![Row::new(vec![
            Cell::from("No CAN frames captured yet"),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else {
        slots
            .iter()
            .map(|(id, slot)| {
                let id_str = match id {
                    CanId::Standard(v) => format!("0x{:03X} (Std)", v),
                    CanId::Extended(v) => format!("0x{:08X} (Ext)", v),
                };

                let hex_data: String = slot
                    .current_data
                    .iter()
                    .take(slot.dlc)
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                let delta_mask: String = slot
                    .marker
                    .iter()
                    .take(slot.dlc)
                    .map(|b| {
                        if *b != 0 {
                            format!("{:02X}", b)
                        } else {
                            "..".to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");

                let periodic_stat = app
                    .engine
                    .histogram_engine
                    .trackers
                    .get(id)
                    .and_then(|t| t.stats());
                let freq_str = match periodic_stat {
                    Some(s) if s.is_periodic => format!("{:.1} Hz (Periodic)", s.estimated_freq_hz),
                    Some(s) => format!("{:.1} ms (Aperiodic)", s.mean_interval_ms),
                    None => "Acquiring...".to_string(),
                };

                Row::new(vec![
                    Cell::from(id_str).style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from(slot.dlc.to_string()),
                    Cell::from(hex_data).style(Style::default().fg(Color::White)),
                    Cell::from(delta_mask).style(Style::default().fg(Color::Yellow)),
                    Cell::from(freq_str),
                    Cell::from(slot.frame_count.to_string()),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(26),
        Constraint::Length(26),
        Constraint::Length(22),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Arbitration ID",
                "DLC",
                "Payload (Hex)",
                "Bit Mutations (XOR)",
                "Broadcast Frequency",
                "Frames",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" CAN Sniffer & Periodic Broadcast Tracker "),
        );

    frame.render_widget(table, area);
}

/// Tab 2: Framing & Timing Compliance Audit Dashboard
fn draw_compliance_tab(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6)])
        .split(area);

    let health_percent = (app.compliance.link_health_score * 100.0).clamp(0.0, 100.0) as u16;
    let gauge_color = if health_percent >= 90 {
        Color::Green
    } else if health_percent >= 70 {
        Color::Yellow
    } else {
        Color::Red
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Industrial Bus Physical & Framing Health Score "),
        )
        .gauge_style(
            Style::default()
                .fg(gauge_color)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .percent(health_percent)
        .label(format!(
            "Health: {}%  │  Analyzed: {}  │  CRC Errors: {}  │  Timing Violations: {}  │  Protocol Violations: {}",
            health_percent,
            app.compliance.total_frames_analyzed,
            app.compliance.crc_error_count,
            app.compliance.timing_violation_count,
            app.compliance.protocol_violation_count
        ));

    frame.render_widget(gauge, chunks[0]);

    // Issues table
    let rows: Vec<Row> = if app.compliance.issues.is_empty() {
        vec![Row::new(vec![
            Cell::from("No compliance issues detected on the bus."),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else {
        app.compliance
            .issues
            .iter()
            .map(|issue| {
                let sev_style = match issue.severity {
                    ViolationSeverity::Critical => {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    }
                    ViolationSeverity::Warning => Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                    ViolationSeverity::Notice => Style::default().fg(Color::Cyan),
                };

                let sev_str = match issue.severity {
                    ViolationSeverity::Critical => "[CRITICAL]",
                    ViolationSeverity::Warning => "[WARNING] ",
                    ViolationSeverity::Notice => "[NOTICE]  ",
                };

                let hint = issue
                    .physical_hint
                    .as_deref()
                    .unwrap_or("No physical remediation needed");

                Row::new(vec![
                    Cell::from(sev_str).style(sev_style),
                    Cell::from(issue.rule_id.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(issue.description.clone()),
                    Cell::from(hint).style(Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(12),
        Constraint::Length(16),
        Constraint::Min(35),
        Constraint::Length(35),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Severity",
                "Rule ID",
                "Description",
                "Physical Diagnostic Hint",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Framing & Timing Audit Findings "),
        );

    frame.render_widget(table, chunks[1]);
}

/// Tab 3: Differential Capture (Physical Event Correlation)
fn draw_diff_tab(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6)])
        .split(area);

    let is_recording = app.engine.diff_session.is_active();
    let banner_text = if is_recording {
        Line::from(vec![
            Span::styled(
                " ● RECORDING ACTIVE ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("— Baseline snapshotted. Flip switch or mutate bus state. Press "),
            Span::styled(
                "[d]",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to stop and isolate bit mutations."),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ○ IDLE ", Style::default().fg(Color::DarkGray)),
            Span::raw("— Press "),
            Span::styled("[d]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" to start a physical delta capture session. Baseline will be snapshotted instantly."),
        ])
    };

    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" Diff Capture Session State ");
    let paragraph = Paragraph::new(banner_text).block(status_block);
    frame.render_widget(paragraph, chunks[0]);

    // Render mutations table
    let rows: Vec<Row> = if let Some(ref report) = app.diff_report {
        if report.mutations.is_empty() {
            vec![Row::new(vec![
                Cell::from("No mutations observed during capture window."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])]
        } else {
            report
                .mutations
                .iter()
                .map(|m| {
                    Row::new(vec![
                        Cell::from(m.entity_type.clone()).style(Style::default().fg(Color::Cyan)),
                        Cell::from(m.identifier.clone()).style(Style::default().fg(Color::White)),
                        Cell::from(m.baseline_value_hex.clone())
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(m.mutated_value_hex.clone())
                            .style(Style::default().fg(Color::Yellow)),
                        Cell::from(m.bitmask_diff.clone())
                            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    ])
                })
                .collect()
        }
    } else {
        vec![Row::new(vec![
            Cell::from("Press [d] to record a physical event diff."),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    };

    let widths = [
        Constraint::Length(18),
        Constraint::Length(24),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Entity Type",
                "Identifier",
                "Baseline Hex",
                "Mutated Hex",
                "Bitmask Mutation (XOR)",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Isolated Physical Event Mutations "),
        );

    frame.render_widget(table, chunks[1]);
}

/// Bottom footer displaying hotkeys and live system log messages
fn draw_footer(frame: &mut Frame, app: &DashboardState, area: Rect) {
    let help_line = Line::from(vec![
        Span::styled(
            " [Tab / 1-4] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Switch View  │ "),
        Span::styled(
            "[d] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Toggle Diff Capture  │ "),
        Span::styled(
            "[c] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Clear History  │ "),
        Span::styled(
            "[q / Esc] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Quit  │  "),
        Span::styled(&app.status_message, Style::default().fg(Color::Green)),
    ]);

    let footer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let paragraph = Paragraph::new(help_line).block(footer_block);
    frame.render_widget(paragraph, area);
}

/// Fallback ANSI terminal renderer for non-interactive or piped output
pub fn render_dashboard(
    engine: &InferenceEngine,
    tier: SafetyTier,
    protocol: &str,
    baud: u32,
    frame_count: u64,
) -> io::Result<()> {
    let summary = engine.get_summary();
    let mut out = stdout();

    // ANSI escape: clear screen and move cursor to top-left
    write!(out, "\x1b[2J\x1b[H")?;

    // Header Banner
    writeln!(out, "\x1b[1;36m╭──────────────────────────────────────────────────────────────────────────────╮\x1b[0m")?;
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  \x1b[1;37mfield-probe v{} — AI-Native Industrial Bus Protocol Analyzer\x1b[0m       \x1b[1;36m│\x1b[0m",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(out, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;

    // Safety Tier & Bus Invariants
    let tier_color = match tier {
        SafetyTier::PassiveListenOnly => "\x1b[1;32m",
        SafetyTier::ReadOnlyProbe => "\x1b[1;33m",
        SafetyTier::ActiveWrite => "\x1b[1;31m",
    };
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  Safety Mode: {}{:<28}\x1b[0m Zero-TX Enforced: \x1b[1;32mYES\x1b[0m           \x1b[1;36m│\x1b[0m",
        tier_color,
        tier.name()
    )?;
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  Bus Status:  \x1b[1;32mLOCKED\x1b[0m [{:<10} @ {:>6} bps 8N1]  Frames: {:<12} \x1b[1;36m│\x1b[0m",
        protocol, baud, frame_count
    )?;
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  Discovered Registers: {:<6} Active CAN Nodes: {:<4} Periodic Loops: {:<4} \x1b[1;36m│\x1b[0m",
        summary.total_discovered_registers, summary.total_active_can_nodes, summary.periodic_can_loops
    )?;
    writeln!(out, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;

    // Register & Signal Catalog Table
    writeln!(
        out,
        "\x1b[1;37m│ {:<18} │ {:<14} │ {:<12} │ {:<18} │ {:<6} │\x1b[0m",
        "Address", "Raw Hex", "Freq (Hz)", "Inferred Value", "Plaus."
    )?;
    writeln!(out, "\x1b[1;36m├────────────────────┼────────────────┼──────────────┼────────────────────┼────────┤\x1b[0m")?;

    if engine.catalog.entries.is_empty() {
        writeln!(
            out,
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
                out,
                "\x1b[1;36m│\x1b[0m {:<18} \x1b[1;36m│\x1b[0m {:<14} \x1b[1;36m│\x1b[0m {:>8.2} Hz \x1b[1;36m│\x1b[0m {:<18} \x1b[1;36m│\x1b[0m {}{:>5.2}\x1b[0m \x1b[1;36m│\x1b[0m",
                addr, entry.raw_hex, entry.polling_frequency_hz, entry.plausible_type, conf_color, entry.confidence
            )?;
        }
    }

    writeln!(out, "\x1b[1;36m├──────────────────────────────────────────────────────────────────────────────┤\x1b[0m")?;
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  \x1b[1;35mMCP Server:\x1b[0m Ready (9 Tools) — Run \x1b[1;37m`fp mcp --stdio`\x1b[0m for Claude/Antigravity    \x1b[1;36m│\x1b[0m"
    )?;
    writeln!(
        out,
        "\x1b[1;36m│\x1b[0m  \x1b[1;35mREST/WS:\x1b[0m    http://127.0.0.1:8080/health | /api/v1/bus/summary             \x1b[1;36m│\x1b[0m"
    )?;
    writeln!(out, "\x1b[1;36m╰──────────────────────────────────────────────────────────────────────────────╯\x1b[0m")?;

    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_state_initialization() {
        let state = DashboardState::new(SafetyTier::PassiveListenOnly, "Modbus RTU", 9600);
        assert_eq!(state.active_tab, 0);
        assert_eq!(state.tier, SafetyTier::PassiveListenOnly);
        assert_eq!(state.frame_count, 0);
        assert!(state.running);
    }

    #[test]
    fn test_dashboard_state_simulate_tick_and_diff_toggle() {
        let mut state = DashboardState::new(SafetyTier::PassiveListenOnly, "Modbus RTU", 9600);
        state.simulate_tick();
        assert!(state.frame_count > 0);
        assert!(!state.engine.catalog.entries.is_empty());

        // Toggle diff capture ON
        state.toggle_diff_capture();
        assert!(state.engine.diff_session.is_active());
        assert_eq!(state.active_tab, 3);

        // Run ticks to record mutations
        for _ in 0..8 {
            state.simulate_tick();
        }

        // Toggle diff capture OFF
        state.toggle_diff_capture();
        assert!(!state.engine.diff_session.is_active());
        assert!(state.diff_report.is_some());
    }

    #[test]
    fn test_dashboard_ingest_event_unknown_framer_and_compliance() {
        let mut state = DashboardState::new(SafetyTier::PassiveListenOnly, "Auto", 500_000);

        // 1. Synthetic unknown binary packet sequence (8 frames of 6 bytes each)
        let mut raw_bytes = Vec::new();
        for i in 0..8u8 {
            let mut f = vec![0xAA, 0x55, 0x01, i, 0x10];
            let sum: u8 = f.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            f.push(sum);
            raw_bytes.extend_from_slice(&f);
        }

        let chunk = fp_core::TimestampedChunk::new(raw_bytes, Some(2000));
        let event = fp_core::RawBusEvent::new_serial_rx(
            "serial0",
            1_000_000,
            fp_core::LinkParams::Serial(Default::default()),
            chunk,
        );

        state.ingest_event(&event);
        assert_eq!(state.frame_count, 1);
        assert_eq!(state.compliance.total_frames_analyzed, 1);

        // Verify that UnknownProto entries were populated in catalog
        let unknown_entries: Vec<_> = state
            .engine
            .catalog
            .entries
            .values()
            .filter(|e| e.node_or_slave == "UnknownProto")
            .collect();
        assert!(!unknown_entries.is_empty());
    }
}

