# field-probe Technical Documentation

> Official technical specifications, architecture records, and operator guides for `field-probe`.

---

## 1. Documentation Index

This directory contains technical specifications, architecture records, and operator guides for `field-probe`.

| Document | Description | Visual Diagram |
|---|---|---|
| [01. System Overview](./01_SYSTEM_OVERVIEW.md) | Mission, architecture, and crate responsibilities | `system_architecture.svg` |
| [02. Safety Invariants](./02_SAFETY_INVARIANTS.md) | Tier-0 Zero-TX default and permit validation | `safety_tiers.svg` |
| [03. Protocol Timing & Specs](./03_PROTOCOL_HEURISTICS.md) | Modbus timing constants, CRC tables, and CAN heuristics | `modbus_timing.svg` |
| [Open-Source Inspiration](./FOSS_INSPIRATION.md) | Proven algorithm designs from Wireshark, SavvyCAN, can-utils | Architecture |
| [04. Hardware Layer](./04_HARDWARE_LAYER.md) | `fp-hal` BusInterface and deterministic ReplayInterface | `hal_replay.svg` |
| [05. Dissectors & Compliance](./05_DISSECTORS_AND_COMPLIANCE.md) | Zero-panic parsers and standard compliance auditing | `crc_scanner.svg` |
| [06. Register Inference](./06_REGISTER_INFERENCE.md) | Multi-representation value decoder and plausibility ranking | `word_orders.svg` |
| [07. MCP Tools](./07_MCP_TOOLS.md) | Model Context Protocol tool schemas for AI agents | `mcp_sequence.svg` |
| [08. Field CLI & Workflows](./08_CLI_AND_FIELD_WORKFLOWS.md) | Terminal user interface and cabinet wiring guide | `field_wiring.svg` |
| [09. HTTP & Telemetry API](./09_HTTP_TELEMETRY_API.md) | REST endpoints and real-time telemetry streaming | `http_telemetry.svg` |

---

## 2. Reading Guidance

- **For Field Engineers:** Start with [08. Field CLI & Workflows](./08_CLI_AND_FIELD_WORKFLOWS.md) and [02. Safety Invariants](./02_SAFETY_INVARIANTS.md).
- **For AI Agent Integration:** Read [07. MCP Tools](./07_MCP_TOOLS.md) and [03. Protocol Heuristics](./03_PROTOCOL_HEURISTICS.md).
- **For Firmware & Core Developers:** Read [01. System Overview](./01_SYSTEM_OVERVIEW.md) through [06. Register Inference](./06_REGISTER_INFERENCE.md).
