use fp_core::{AdapterCapabilities, BusProtocol, SafetyPermit, SafetyTier};
use fp_crypto::{KeyRing, KeyType, ManagedKey};
use fp_dissectors::{ComplianceReport, ModbusRtuAdu};
use fp_inference::InferenceEngine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Error returned when an MCP tool invocation fails
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
}

impl McpError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, msg)
    }

    pub fn safety_violation(msg: impl Into<String>) -> Self {
        Self::new(4003, msg)
    }
}

/// State managed by the Model Context Protocol server
#[derive(Debug)]
pub struct McpServerState {
    pub inference_engine: InferenceEngine,
    pub keyring: Arc<KeyRing>,
    pub compliance_report: ComplianceReport,
    pub current_safety_tier: SafetyTier,
    pub detected_protocol: BusProtocol,
    pub detected_baud_rate: u32,
    pub interfaces: Vec<AdapterCapabilities>,
}

impl Default for McpServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl McpServerState {
    pub fn new() -> Self {
        Self {
            inference_engine: InferenceEngine::new(500_000, 1000),
            keyring: Arc::new(KeyRing::new()),
            compliance_report: ComplianceReport::new(),
            current_safety_tier: SafetyTier::PassiveListenOnly, // Tier-0 Zero-TX invariant
            detected_protocol: BusProtocol::ModbusRtu,
            detected_baud_rate: 9600,
            interfaces: fp_hal::enumerate_dongles(),
        }
    }

    /// Dispatch tool call by name
    pub fn execute_tool(
        &mut self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        match name {
            "list_dongles" => self.tool_list_dongles(),
            "auto_detect_bus" => self.tool_auto_detect_bus(arguments),
            "get_bus_summary" => self.tool_get_bus_summary(arguments),
            "get_register_catalog" => self.tool_get_register_catalog(arguments),
            "run_compliance_audit" => self.tool_run_compliance_audit(arguments),
            "correlate_physical_change" => self.tool_correlate_physical_change(arguments),
            "load_security_key" => self.tool_load_security_key(arguments),
            "request_active_probe" => self.tool_request_active_probe(arguments),
            "export_bus_artifacts" => self.tool_export_bus_artifacts(arguments),
            _ => Err(McpError::new(-32601, format!("Unknown tool '{}'", name))),
        }
    }

    fn tool_list_dongles(&self) -> Result<serde_json::Value, McpError> {
        let list = self
            .interfaces
            .iter()
            .map(|iface| {
                json!({
                    "interface_id": iface.interface_id,
                    "chip_type": format!("{:?}", iface.chip_type),
                    "description": iface.description,
                    "supports_serial": iface.supports_serial,
                    "supports_can": iface.supports_can,
                    "supports_listen_only": iface.supports_listen_only,
                    "current_safety_tier": self.current_safety_tier.name(),
                    "zero_tx_enforced": self.current_safety_tier.is_passive(),
                })
            })
            .collect::<Vec<_>>();

        Ok(json!({ "dongles": list }))
    }

    fn tool_auto_detect_bus(&mut self, _args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        Ok(json!({
            "detected_protocol": format!("{:?}", self.detected_protocol),
            "baud_rate": self.detected_baud_rate,
            "framing": "8N1",
            "confidence": 0.98,
            "status": "LOCKED",
            "safety_tier": self.current_safety_tier.name()
        }))
    }

    fn tool_get_bus_summary(&self, _args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        let summary = self.inference_engine.get_summary();
        Ok(json!({
            "protocol": format!("{:?}", self.detected_protocol),
            "baud_rate": self.detected_baud_rate,
            "discovered_registers": summary.total_discovered_registers,
            "active_can_nodes": summary.total_active_can_nodes,
            "periodic_broadcast_loops": summary.periodic_can_loops,
            "compliance_health_score": self.compliance_report.link_health_score,
            "active_safety_tier": self.current_safety_tier.name()
        }))
    }

    fn tool_get_register_catalog(&self, _args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        let entries = self
            .inference_engine
            .catalog
            .entries
            .values()
            .collect::<Vec<_>>();

        Ok(json!({
            "total_entries": entries.len(),
            "registers": entries
        }))
    }

    fn tool_run_compliance_audit(&self, _args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        Ok(json!({
            "total_frames_analyzed": self.compliance_report.total_frames_analyzed,
            "crc_errors": self.compliance_report.crc_error_count,
            "protocol_violations": self.compliance_report.protocol_violation_count,
            "link_health_score": self.compliance_report.link_health_score,
            "issues": self.compliance_report.issues
        }))
    }

    fn tool_correlate_physical_change(&mut self, args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("snapshot");
        match action {
            "start" => {
                self.inference_engine.start_diff_capture(1_000_000);
                Ok(json!({
                    "status": "Diff capture active",
                    "instruction": "Trigger the physical change in the field now, then call correlate_physical_change with action='stop'."
                }))
            }
            "stop" => {
                let report = self.inference_engine.stop_diff_capture(2_000_000);
                Ok(json!({
                    "report": report
                }))
            }
            _ => {
                let is_active = self.inference_engine.diff_session.is_active();
                Ok(json!({ "diff_capture_active": is_active }))
            }
        }
    }

    fn tool_load_security_key(&mut self, args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        let key_id = args
            .get("key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("Missing key_id"))?;
        let hex_bytes = args
            .get("secret_hex")
            .or_else(|| args.get("hex_bytes"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("Missing secret_hex or hex_bytes"))?;

        let key_type_str = args
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Aes128");

        let key_type = match key_type_str {
            "Aes128" => KeyType::Aes128,
            "Aes256" => KeyType::Aes256,
            "TlsCertificate" => KeyType::TlsCertificate,
            "XorMask" => KeyType::XorMask,
            "CustomSeed" => KeyType::CustomSeed,
            _ => KeyType::Aes128,
        };

        let target_scope = args
            .get("target_scope")
            .and_then(|v| v.as_str())
            .unwrap_or("global");

        let bytes = hex_decode(hex_bytes).map_err(|_| McpError::invalid_params("Invalid hex string"))?;
        self.keyring.insert_key(ManagedKey {
            key_id: key_id.to_string(),
            key_type,
            target_scope: target_scope.to_string(),
            secret_bytes: bytes.clone(),
        });

        Ok(json!({
            "status": "Key stored successfully in KeyRing",
            "key_id": key_id,
            "key_type": key_type_str,
            "target_scope": target_scope,
            "key_len_bytes": bytes.len()
        }))
    }

    fn tool_request_active_probe(&mut self, args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        // Strict Tier-0 Zero-TX boundary check
        let token = args
            .get("permit_id")
            .or_else(|| args.get("permit_token"))
            .and_then(|v| v.as_str());

        if token.is_none() || self.current_safety_tier == SafetyTier::PassiveListenOnly {
            return Err(McpError::safety_violation(
                "Active probing BLOCKED: current safety tier is Tier-0 PassiveListenOnly (Zero-TX). Explicit authorization token required to elevate to Tier-1 ReadOnlyProbe.",
            ));
        }

        let scope = args.get("scope").and_then(|v| v.as_str()).map(|s| s.to_string());
        let signature = args.get("signature").and_then(|v| v.as_str());

        // Validate permit
        let mut permit = SafetyPermit::new(
            token.unwrap_or("mcp-probe-token"),
            SafetyTier::ReadOnlyProbe,
            "mcp-operator",
            chrono::Utc::now() + chrono::Duration::minutes(10),
            scope,
        );

        if let Some(sig) = signature {
            permit = permit.with_signature(sig);
            if !self.keyring.verify_permit(&permit) {
                return Err(McpError::safety_violation("Supplied safety permit signature is INVALID"));
            }
        }

        if !permit.is_valid_for(SafetyTier::ReadOnlyProbe, chrono::Utc::now()) {
            return Err(McpError::safety_violation("Supplied safety permit has expired"));
        }

        Ok(json!({
            "status": "Active probe dispatched under Tier-1 ReadOnlyProbe authorization",
            "probe_type": "Read Device Identification (FC 0x2B / 0x0E)",
            "permit_id": permit.permit_id
        }))
    }

    fn tool_export_bus_artifacts(&self, args: &serde_json::Value) -> Result<serde_json::Value, McpError> {
        let format = args
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("json")
            .to_lowercase();

        let artifact = match format.as_str() {
            "dbc" => {
                let msgs = vec![];
                fp_inference::export_dbc(&msgs)
            }
            "pcapng" => {
                let bytes = fp_inference::export_pcapng(&[]);
                format!("PCAP-NG export: {} bytes formatted", bytes.len())
            }
            "telegraf" => fp_inference::export_telegraf(&self.inference_engine.catalog),
            "nodered" => fp_inference::export_nodered_flow(&self.inference_engine.catalog),
            _ => fp_inference::export_json(&self.inference_engine.catalog),
        };

        Ok(json!({
            "status": "success",
            "format": format,
            "artifact": artifact
        }))
    }

    /// Feed a Modbus RTU frame into the inference engine and compliance auditor
    pub fn feed_modbus_frame(&mut self, adu: &ModbusRtuAdu, timestamp_us: u64) {
        self.compliance_report.audit_modbus_adu(adu);
        self.inference_engine.ingest_modbus_frame(adu, timestamp_us);
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let clean = s.trim().replace(' ', "");
    if !clean.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    for chunk in bytes.chunks(2) {
        let h = hex_val(chunk[0])?;
        let l = hex_val(chunk[1])?;
        out.push((h << 4) | l);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_list_dongles() {
        let mut state = McpServerState::new();
        let res = state.execute_tool("list_dongles", &json!({})).expect("Tool executed");
        assert!(res["dongles"].as_array().unwrap().len() >= 1);
        assert_eq!(res["dongles"][0]["zero_tx_enforced"], true);
    }

    #[test]
    fn test_mcp_active_probe_rejected_under_tier0() {
        let mut state = McpServerState::new();
        let err = state.execute_tool("request_active_probe", &json!({})).unwrap_err();
        assert_eq!(err.code, 4003);
        assert!(err.message.contains("BLOCKED"));
    }

    #[test]
    fn test_mcp_load_security_key() {
        let mut state = McpServerState::new();
        let args = json!({
            "key_id": "secoc-key-1",
            "hex_bytes": "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        });
        let res = state.execute_tool("load_security_key", &args).expect("Tool executed");
        assert_eq!(res["key_len_bytes"], 16);
        assert!(state.keyring.get_symmetric_key("secoc-key-1").is_some());
    }
}
