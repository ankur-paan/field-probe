# 07. Model Context Protocol Tools (fp-mcp)

> **Topic:** The 9 core Model Context Protocol diagnostic and export tools for AI agents.

---

## 1. Description

The `fp-mcp` crate implements the Model Context Protocol (MCP) server.  
Autonomous AI agents (Claude, Cursor, Codex) connect to `field-probe` over stdio or SSE.  
Agents use tools to inspect hardware, identify buses, audit network health, and export SCADA configurations.

---

## 2. Interaction Sequence

The diagram below shows an agent discovering an unknown bus:

![MCP Interaction Sequence](./assets/mcp_sequence.svg)

---

## 3. The 10 Core Diagnostic Tools

| Tool Name | Operation | Safety Tier |
|---|---|---|
| `list_dongles` | Enumerate connected adapters and active safety tiers | Tier 0 |
| `auto_detect_bus` | Run passive baud rate and protocol identification | Tier 0 |
| `get_bus_summary` | Return protocol, baud rate, framing, error rate, active nodes | Tier 0 |
| `get_register_catalog` | Return discovered registers, polling frequencies, inferred types | Tier 0 |
| `run_compliance_audit` | Audit captured frames against official timing standards | Tier 0 |
| `correlate_physical_change` | Isolate registers mutated during an operator physical action | Tier 0 |
| `load_security_key` | Register symmetric keys or certificates into KeyRing | Tier 0 |
| `request_active_probe` | Transmit safe read query on an idle bus (requires cryptographic permit and HMAC signature when operator key is loaded) | Tier 1 (Permit Required) |
| `export_bus_artifacts` | Export register catalog into Vector DBC, PCAP-NG, Telegraf, Node-RED, or JSON | Tier 0 |
| `load_bus_database` | Load Vector CANdb++ (.dbc) file to decode raw CAN IDs into physical signals | Tier 0 |

---

## 4. Security & Cryptographic Enforcement

1. **Shared KeyRing:**  
   The MCP server shares its internal `KeyRing` handle directly with `InferenceEngine`.  
   When an AI agent registers a secret key via `load_security_key`, the inference engine immediately uses that key to decrypt high-entropy Modbus payloads and unpack engineering registers.

2. **Active Probe Signature Verification:**  
   When an operator secret key (`KeyType::OperatorSecret`) exists in `KeyRing`, `request_active_probe` mandates an HMAC cryptographic signature in the request parameters.  
   Requests lacking a valid signature fail immediately with a safety invariant violation.

---

## 5. Input Schemas

Each tool provides a strict JSON Schema:

```json
{
  "name": "load_bus_database",
  "description": "Load a Vector DBC (.dbc) database file to decode CAN message frames into named engineering signals.",
  "parameters": {
    "type": "object",
    "properties": {
      "content": {
        "type": "string",
        "description": "Full text content of the Vector CANdb++ (.dbc) file"
      }
    },
    "required": ["content"]
  }
}
```

```json
{
  "name": "export_bus_artifacts",
  "description": "Export the discovered register catalog and CAN signals into Vector DBC, Wireshark PCAP-NG, Telegraf Influx line protocol, Node-RED flow, or JSON.",
  "parameters": {
    "type": "object",
    "properties": {
      "interface_id": { "type": "string" },
      "format": {
        "type": "string",
        "enum": ["dbc", "pcapng", "telegraf", "json", "nodered"],
        "description": "Target export format"
      }
    },
    "required": ["format"]
  }
}
```

---

## 6. Multi-Protocol Telemetry Ingestion via MCP

When an AI agent invokes `get_register_catalog`, `field-probe` aggregates discovered entities across all active fieldbuses into a unified semantic registry:

```json
{
  "total_entries": 6,
  "registers": [
    {
      "node_or_slave": "J1939:0x05",
      "address": 127488,
      "polling_frequency_hz": 10.0,
      "jitter_ms": 1.2,
      "raw_hex": "00 10 27 96 00 32 FF FF",
      "plausible_type": "NMEA2000 Rapid: Inst=0, RPM=2500.00, Boost=15.0 kPa, Trim=50%",
      "confidence": 1.0
    },
    {
      "node_or_slave": "DeviceNet:Node10",
      "address": 1110,
      "polling_frequency_hz": 20.0,
      "jitter_ms": 0.5,
      "raw_hex": "DE AD BE EF",
      "plausible_type": "DeviceNet Poll: SlavePollResponse",
      "confidence": 0.95
    },
    {
      "node_or_slave": "J1708:128",
      "address": 84,
      "polling_frequency_hz": 5.0,
      "jitter_ms": 2.1,
      "raw_hex": "MID:128 PID:84",
      "plausible_type": "J1587 Engine #1: RoadSpeed: 88.50 km/h",
      "confidence": 1.0
    },
    {
      "node_or_slave": "BACnet:42",
      "address": 25941,
      "polling_frequency_hz": 1.0,
      "jitter_ms": 0.1,
      "raw_hex": "01 02 03",
      "plausible_type": "BACnet AnalogInput #101: present-value = 23.75",
      "confidence": 1.0
    },
    {
      "node_or_slave": "MBus:5",
      "address": 12345678,
      "polling_frequency_hz": 0.1,
      "jitter_ms": 0.0,
      "raw_hex": "12 34",
      "plausible_type": "M-Bus Heat Meter #12345678: Mfg=KAM, Medium=Heat",
      "confidence": 1.0
    },
    {
      "node_or_slave": "KNX:1.1.2",
      "address": 2305,
      "polling_frequency_hz": 0.2,
      "jitter_ms": 0.0,
      "raw_hex": "01",
      "plausible_type": "KNX -> 1/1/1 Service=GroupValueWrite, Payload=[01]",
      "confidence": 1.0
    }
  ]
}
```


