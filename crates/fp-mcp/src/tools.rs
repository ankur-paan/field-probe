use serde::{Deserialize, Serialize};

/// Tool identifiers for the 8 core Model Context Protocol capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpToolName {
    ListDongles,
    AutoDetectBus,
    GetBusSummary,
    GetRegisterCatalog,
    RunComplianceAudit,
    CorrelatePhysicalChange,
    LoadSecurityKey,
    RequestActiveProbe,
    ExportBusArtifacts,
}

impl McpToolName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ListDongles => "list_dongles",
            Self::AutoDetectBus => "auto_detect_bus",
            Self::GetBusSummary => "get_bus_summary",
            Self::GetRegisterCatalog => "get_register_catalog",
            Self::RunComplianceAudit => "run_compliance_audit",
            Self::CorrelatePhysicalChange => "correlate_physical_change",
            Self::LoadSecurityKey => "load_security_key",
            Self::RequestActiveProbe => "request_active_probe",
            Self::ExportBusArtifacts => "export_bus_artifacts",
        }
    }
}

/// JSON Schema definition for an MCP tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Return full schema definitions for all 8 MCP tools
pub fn get_tool_definitions() -> Vec<McpToolDefinition> {
    vec![
        McpToolDefinition {
            name: "list_dongles".to_string(),
            description: "List connected serial/CAN hardware interfaces and their current safety tier.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
            }),
        },
        McpToolDefinition {
            name: "auto_detect_bus".to_string(),
            description: "Run passive Tier-0 baud rate, parity, and protocol identification on a dongle.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" },
                    "dwell_ms": { "type": "number", "default": 1500 }
                },
                "required": ["interface_id"]
            }),
        },
        McpToolDefinition {
            name: "get_bus_summary".to_string(),
            description: "Return detected protocol, baud rate, framing, bus load %, error rate, and active nodes/slaves.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" }
                },
                "required": ["interface_id"]
            }),
        },
        McpToolDefinition {
            name: "get_register_catalog".to_string(),
            description: "Return discovered registers/CAN IDs, polling frequencies, raw hex, and top-ranked inferred data types + values.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" }
                },
                "required": ["interface_id"]
            }),
        },
        McpToolDefinition {
            name: "run_compliance_audit".to_string(),
            description: "Compare captured traffic against Modbus/CAN/BACnet standard timing and framing rules; return violations and physical layer health hints.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" },
                    "sample_duration_s": { "type": "number", "default": 10 }
                },
                "required": ["interface_id"]
            }),
        },
        McpToolDefinition {
            name: "correlate_physical_change".to_string(),
            description: "Capture baseline for N seconds, prompt user to trigger a physical change, and return registers/bits that mutated.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" },
                    "baseline_seconds": { "type": "number", "default": 5 }
                },
                "required": ["interface_id"]
            }),
        },
        McpToolDefinition {
            name: "load_security_key".to_string(),
            description: "Register an encryption/MAC key (AES, TLS cert, seed) into fp-crypto to unlock encrypted payloads.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "key_id": { "type": "string" },
                    "key_type": { "type": "string", "enum": ["Aes128", "Aes256", "TlsCertificate", "XorMask", "CustomSeed"] },
                    "target_scope": { "type": "string" },
                    "secret_hex": { "type": "string" }
                },
                "required": ["key_id", "key_type", "target_scope", "secret_hex"]
            }),
        },
        McpToolDefinition {
            name: "request_active_probe".to_string(),
            description: "(Requires Tier-1/Tier-2 permit) Send a specific read request (e.g., Modbus FC 0x2B/0x0E Device ID or register scan) when passive listening sees an idle bus.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "interface_id": { "type": "string" },
                    "permit_id": { "type": "string" },
                    "payload_hex": { "type": "string" }
                },
                "required": ["interface_id", "permit_id", "payload_hex"]
            }),
        },
        McpToolDefinition {
            name: "export_bus_artifacts".to_string(),
            description: "Export the discovered register catalog and CAN signals into Vector DBC, Wireshark PCAP-NG, Telegraf Influx line protocol, Node-RED flow, or JSON.".to_string(),
            input_schema: serde_json::json!({
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
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tools_defined() {
        let tools = get_tool_definitions();
        assert_eq!(tools.len(), 9);
    }
}
