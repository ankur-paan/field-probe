use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Inferred entry in the register/signal catalog
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferredRegisterEntry {
    pub node_or_slave: String,
    pub address: u32,
    pub polling_frequency_hz: f32,
    pub jitter_ms: f32,
    pub raw_hex: String,
    pub plausible_type: String,
    pub confidence: f32,
}

/// Catalog holding discovered signals and registers across all bus nodes
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterCatalog {
    pub entries: HashMap<String, InferredRegisterEntry>,
}

impl RegisterCatalog {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert_or_update(&mut self, entry: InferredRegisterEntry) {
        let key = format!("{}:{}", entry.node_or_slave, entry.address);
        self.entries.insert(key, entry);
    }
}
