use fp_core::{AdapterCapabilities, BusProtocol, SafetyTier};
use fp_dissectors::ComplianceReport;
use fp_inference::InferenceEngine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Server health and runtime status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub active_interfaces: usize,
    pub active_safety_tier: SafetyTier,
}

/// Shared application state for HTTP and WebSocket telemetry handlers
#[derive(Clone)]
pub struct ServerState {
    pub inference_engine: Arc<RwLock<InferenceEngine>>,
    pub compliance_report: Arc<RwLock<ComplianceReport>>,
    pub safety_tier: SafetyTier,
    pub detected_protocol: BusProtocol,
    pub detected_baud_rate: u32,
    pub dongles: Vec<AdapterCapabilities>,
    pub start_time: Instant,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            inference_engine: Arc::new(RwLock::new(InferenceEngine::new(500_000, 1000))),
            compliance_report: Arc::new(RwLock::new(ComplianceReport::new())),
            safety_tier: SafetyTier::PassiveListenOnly,
            detected_protocol: BusProtocol::ModbusRtu,
            detected_baud_rate: 9600,
            dongles: fp_hal::enumerate_dongles(),
            start_time: Instant::now(),
        }
    }

    pub fn handle_health(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": self.start_time.elapsed().as_secs(),
            "safety_tier": self.safety_tier.name(),
            "zero_tx_enforced": self.safety_tier.is_passive()
        })
    }

    pub fn handle_dongles(&self) -> serde_json::Value {
        let list = self
            .dongles
            .iter()
            .map(|d| {
                json!({
                    "interface_id": d.interface_id,
                    "chip_type": format!("{:?}", d.chip_type),
                    "description": d.description,
                    "supports_serial": d.supports_serial,
                    "supports_can": d.supports_can,
                    "supports_listen_only": d.supports_listen_only,
                    "current_tier": self.safety_tier.name(),
                    "zero_tx_enforced": self.safety_tier.is_passive()
                })
            })
            .collect::<Vec<_>>();

        json!({ "dongles": list })
    }

    pub async fn handle_bus_summary(&self) -> serde_json::Value {
        let engine = self.inference_engine.read().await;
        let summary = engine.get_summary();
        let report = self.compliance_report.read().await;

        json!({
            "protocol": format!("{:?}", self.detected_protocol),
            "baud_rate": self.detected_baud_rate,
            "framing": "8N1",
            "total_registers": summary.total_discovered_registers,
            "active_can_nodes": summary.total_active_can_nodes,
            "periodic_broadcast_loops": summary.periodic_can_loops,
            "link_health_score": report.link_health_score,
            "safety_tier": self.safety_tier.name()
        })
    }

    pub async fn handle_catalog(&self) -> serde_json::Value {
        let engine = self.inference_engine.read().await;
        let entries = engine.catalog.entries.values().cloned().collect::<Vec<_>>();

        json!({
            "total_entries": entries.len(),
            "registers": entries
        })
    }
}
