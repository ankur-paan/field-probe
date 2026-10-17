# field-probe

> **AI-Native, Non-Intrusive Industrial Bus Protocol Analyzer & MCP Telemetry Engine in Pure Rust.**

[![CI Quality Gate](https://github.com/ankur-paan/field-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/ankur-paan/field-probe/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/Docs-fieldprobe.indramqtt.com-blue.svg)](https://fieldprobe.indramqtt.com)
[![Safety Default](https://img.shields.io/badge/Safety_Default-Tier--0_PassiveListen-success.svg)](#2-strict-tier-0-zero-tx-safety-invariants)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-yellow.svg)](./LICENSE)

---

## 1. Overview

Arriving at an unmapped industrial cabinet, PLC rack, or vehicle harness with missing register maps, unknown baud rates, and live machinery carries extreme operational risk. Transmitting arbitrary diagnostic frames or poll packets can fault sensitive equipment or trigger safety trips.

`field-probe` solves this through a **two-phase architecture**:
1. **Zero-TX Passive Sniffing:** Hardware transceivers remain tri-stated or locked in listen-only mode by default. The engine passively identifies baud rate, parity, framing, active node IDs, and register maps from ambient wire traffic.
2. **AI-Native Telemetry & MCP Engine:** Exposes 9 structured diagnostic tools via the **Model Context Protocol (MCP)** and asynchronous HTTP/SSE APIs, enabling autonomous coding agents (Claude, Cursor, Antigravity) to audit network compliance, infer physical telemetry, and export SCADA artifacts.

```
                   Differential Industrial Bus (RS-485 / CAN / CAN-FD)
                 ───────────────────────────────┬───────────────────────────────
                                                │ (Passive Tap / Listen-Only)
                                                ▼
                                    ┌───────────────────────┐
                                    │ Hardware Adapters     │
                                    │ - FTDI FT232R/FT4232  │
                                    │ - PEAK PCAN-USB       │
                                    │ - Lawicel SLCAN       │
                                    │ - Synthetic Replay    │
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │ fp-core & fp-hal      │  ◄── Tier-0 Zero-TX Invariant
                                    │ Hardware Abstraction  │
                                    └───────────┬───────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
      ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
      │ fp-autodetect        │      │ fp-dissectors        │      │ fp-inference         │
      │ - Sliding CRC-16     │      │ - Modbus RTU/TCP     │      │ - Cansniffer Deltas  │
      │ - BACnet CRC-8 / DNP3│      │ - CAN 2.0 / CAN-FD   │      │ - Welford Jitter     │
      │ - Silence Intervals  │      │ - J1939 / CANopen    │      │ - Float32 Plausib.   │
      └──────────┬───────────┘      └──────────┬───────────┘      └──────────┬───────────┘
                 │                             │                             │
                 └─────────────────────────────┼─────────────────────────────┘
                                               │
                                    ┌──────────▼───────────┐
                                    │ fp-mcp & fp-server   │
                                    │ JSON-RPC 2.0 & SSE   │
                                    └──────────┬───────────┘
                                               │
                 ┌─────────────────────────────┴─────────────────────────────┐
                 ▼                                                           ▼
      ┌──────────────────────┐                                    ┌──────────────────────┐
      │ Autonomous AI Agents │                                    │ Engineers & SCADA    │
      │ Claude / Antigravity │                                    │ Terminal TUI / Web   │
      └──────────────────────┘                                    └──────────────────────┘
```

---

## 2. Strict Tier-0 Zero-TX Safety Invariants

Field operations demand ironclad safety boundaries:

- **Hardware Default Invariant:** Connected adapters (`ReplayInterface`, `SerialDriver`, `SocketCanDriver`, `SlcanCodec`) **MUST** power on and initialize in `SafetyTier::PassiveListenOnly` (Tier 0).
- **Zero Transmissions Allowed:** Transceiver TX pins are kept high-impedance (tri-state) or CAN listen-only error acknowledgment suppression is engaged.
- **Permit-Gated Active Probing:** Elevating to Tier 1 (`ReadOnlyProbe`) or Tier 2 (`ActiveWrite`) requires a cryptographically valid `SafetyPermit` signed with a non-expired UTC timestamp and explicit scope.

---

## 3. Workspace Crates Architecture

The repository contains 10 decoupled Cargo workspace crates:

| Crate | Responsibility |
|---|---|
| [`fp-core`](./crates/fp-core) | Foundational domain models: `SafetyTier`, `SafetyPermit`, `LinkParams`, `RawBusEvent`, `CanFrame`. |
| [`fp-hal`](./crates/fp-hal) | Asynchronous `BusInterface` trait, deterministic `ReplayInterface`, SLCAN, serial, and SocketCAN drivers with non-blocking async loops. |
| [`fp-store`](./crates/fp-store) | High-throughput, bounded circular in-memory buffer (`CaptureBuffer`) for loss-free zero-allocation ring logging. |
| [`fp-autodetect`](./crates/fp-autodetect) | Non-intrusive baud rate hunter, sliding-window CRC-16/CRC-8/LRC scanners, silence interval calculators, and Netzob unknown sequence framer. |
| [`fp-dissectors`](./crates/fp-dissectors) | Zero-panic `nom` dissectors for Modbus RTU/TCP, CAN 2.0/FD, SAE J1939 (BAM/CMDT), ISO-TP, UDS, CANopen, DNP3, and BACnet MS/TP. |
| [`fp-crypto`](./crates/fp-crypto) | Shannon entropy scoring (>7.2 bits/byte detector), SecOC AUTOSAR authentication, and thread-safe symmetric `KeyRing`. |
| [`fp-inference`](./crates/fp-inference) | Cansniffer bit-delta tracking, SavvyCAN Welford jitter, Float32 ABCD/CDAB plausibility ranking, decrypted payload unpacking, and mutation isolation. |
| [`fp-mcp`](./crates/fp-mcp) | Model Context Protocol server exposing the 9 core industrial diagnostic and export tools over stdio JSON-RPC 2.0. |
| [`fp-server`](./crates/fp-server) | Asynchronous HTTP REST & Server-Sent Events (SSE) telemetry server with binary PCAP-NG export. |
| [`fp-cli`](./crates/fp-cli) | Terminal User Interface (`fp dashboard`), sniffer, autodetector, compliance auditor, artifact exporter, and CLI dispatcher. |

---

## 4. Quickstart & CLI Commands

Install and run `fp` locally:

```bash
# Build the entire workspace
cargo build --release

# 1. Launch the interactive ANSI Terminal Dashboard
cargo run -p fp-cli -- dashboard

# 2. Launch Dashboard on a specific interface or in replay mode
cargo run -p fp-cli -- dashboard --interface can0
cargo run -p fp-cli -- dashboard --replay capture.candump

# 3. Automatically identify baud rate and protocol from bus traffic
cargo run -p fp-cli -- autodetect

# 4. Stream incoming bus frames with microsecond timestamps
cargo run -p fp-cli -- sniff

# 5. Enumerate connected USB/CAN/Serial hardware dongles
cargo run -p fp-cli -- dongles

# 6. Start the Model Context Protocol stdio server for AI agents
cargo run -p fp-cli -- mcp

# 7. Start the HTTP and SSE telemetry server (default port 8080)
cargo run -p fp-cli -- serve 8080

# 8. Execute framing and timing compliance checks
cargo run -p fp-cli -- audit

# 9. Export discovered bus artifacts directly to disk
cargo run -p fp-cli -- export --format dbc
cargo run -p fp-cli -- export --format pcapng
cargo run -p fp-cli -- export --format telegraf
```

---

## 5. Model Context Protocol (MCP) Diagnostic Tools

AI coding agents interface with `field-probe` via stdio using 9 structured tools:

| MCP Tool | Operation | Safety Tier |
|---|---|---|
| `list_dongles` | Enumerate connected adapters, chipsets, and active safety tiers. | Tier 0 |
| `auto_detect_bus` | Run passive baud rate, parity, and protocol classification. | Tier 0 |
| `get_bus_summary` | Return protocol, baud rate, framing, bus load %, error rate, and active nodes. | Tier 0 |
| `get_register_catalog` | Return discovered registers, polling frequencies, raw hex, and top inferred data types. | Tier 0 |
| `run_compliance_audit` | Audit captured frames against official timing ($t_{1.5}$, $t_{3.5}$) and framing standards. | Tier 0 |
| `correlate_physical_change` | Isolate registers mutated during an operator physical switch or setpoint change. | Tier 0 |
| `load_security_key` | Register an AES key or certificate into `KeyRing` for encrypted payload analysis. | Tier 0 |
| `request_active_probe` | Transmit a safe diagnostic query (e.g. Modbus Device ID FC 0x2B) on an idle bus (HMAC signature required). | Tier 1 (Permit Required) |
| `export_bus_artifacts` | Export register catalog into Vector DBC, PCAP-NG, Telegraf, Node-RED, or JSON. | Tier 0 |

---

## 6. HTTP REST & Telemetry Endpoints

The `fp-server` daemon provides live machine-readable telemetry:

- `GET /health` — Operational status and Tier-0 Zero-TX verification.
- `GET /api/v1/dongles` — Dynamically enumerated hardware adapters and listen-only capabilities.
- `GET /api/v1/bus/summary` — Active protocol, baud rate, node count, and link health score.
- `GET /api/v1/catalog` — Discovered register map, polling frequencies, and plausibility scores.
- `GET /api/v1/audit` — Compliance audit report, CRC errors, protocol violations, and link health.
- `GET /api/v1/export/{format}` — Direct SCADA artifact export (`dbc`, binary `pcapng`, `telegraf`, `nodered`, `json`).
- `GET /api/v1/events/sse` — Real-time Server-Sent Events (SSE) telemetry stream.

---

## 7. Supported Protocols & Hardware

- **Serial Protocols:** Modbus RTU, Modbus ASCII, Modbus Device ID (MEI FC 0x2B/0x0E), BACnet MS/TP, DNP3, and Netzob unknown sequence framing.
- **CAN Protocols:** CAN 2.0A (11-bit standard), CAN 2.0B (29-bit extended), CAN-FD, SAE J1939 (single-frame & BAM/CMDT transport), CANopen (NMT & SDO), ISO-TP (ISO 15765-2), and UDS (ISO 14229).
- **Supported Dongles:** FTDI FT232R / FT4232, Silicon Labs CP210x, PEAK PCAN-USB, Lawicel SLCAN, Linux SocketCAN (`can0`, `vcan0`), and Synthetic Replay (`.pcapng`, `.candump`).

---

## 8. Interactive Documentation Site

The interactive documentation site is located in [`docs/`](./docs):
- Clean, minimal light theme built with **React + Vite**.
- Includes 10 custom visual SVG architecture diagrams (100% documentation page coverage).
- Hosted live at: **[fieldprobe.indramqtt.com](https://fieldprobe.indramqtt.com)**

To run the documentation locally:
```bash
cd docs
npm install
npm run dev
```

---

## 9. Quality Verification & Testing

Verify workspace integrity:

```bash
# Run 100+ automated unit, integration, and property-based fuzz tests
cargo test --workspace

# Enforce zero clippy warnings
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 10. License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
