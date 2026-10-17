# 07. Model Context Protocol Tools (fp-mcp)

> **Topic:** The 8 core Model Context Protocol diagnostic tools for AI agents.

---

## 1. Description

The `fp-mcp` crate implements the Model Context Protocol (MCP) server.  
Autonomous AI agents (Claude, Cursor, Codex) connect to `field-probe` over stdio or SSE.  
Agents use tools to inspect hardware, identify buses, and audit network health.

---

## 2. Interaction Sequence

The diagram below shows an agent discovering an unknown bus:

![MCP Interaction Sequence](./assets/mcp_sequence.svg)

---

## 3. The 8 Core Diagnostic Tools

| Tool Name | Operation | Safety Tier |
|---|---|---|
| `list_dongles` | Enumerate connected adapters and active safety tiers | Tier 0 |
| `auto_detect_bus` | Run passive baud rate and protocol identification | Tier 0 |
| `get_bus_summary` | Return protocol, baud rate, framing, error rate, active nodes | Tier 0 |
| `get_register_catalog` | Return discovered registers, polling frequencies, inferred types | Tier 0 |
| `run_compliance_audit` | Audit captured frames against official timing standards | Tier 0 |
| `correlate_physical_change` | Isolate registers mutated during an operator physical action | Tier 0 |
| `load_security_key` | Register symmetric keys or certificates into KeyRing | Tier 0 |
| `request_active_probe` | Transmit safe read query on an idle bus | Tier 1 (Permit Required) |

---

## 4. Input Schemas

Each tool provides a strict JSON Schema:

```json
{
  "name": "auto_detect_bus",
  "description": "Run passive Tier-0 baud rate, parity, and protocol identification on a dongle.",
  "parameters": {
    "type": "object",
    "properties": {
      "interface_id": { "type": "string" },
      "dwell_ms": { "type": "number", "default": 1500 }
    },
    "required": ["interface_id"]
  }
}
```
