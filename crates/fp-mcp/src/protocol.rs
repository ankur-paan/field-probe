use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    handler::McpServerState,
    tools::get_tool_definitions,
};

/// Incoming JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Outgoing JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorPayload {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Process a single incoming JSON-RPC message string and return JSON-RPC response string (if response needed)
pub fn process_json_rpc(state: &mut McpServerState, raw_json: &str) -> Option<String> {
    let req: JsonRpcRequest = match serde_json::from_str(raw_json) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcErrorPayload {
                    code: -32700,
                    message: format!("Parse error: {}", e),
                    data: None,
                }),
            };
            return serde_json::to_string(&err_resp).ok();
        }
    };

    // Notifications (id is None) do not return responses
    let id = req.id.clone();

    let resp = match req.method.as_str() {
        "initialize" => {
            let result = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": "field-probe-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            });
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: id.unwrap_or(serde_json::Value::Null),
                result: Some(result),
                error: None,
            }
        }
        "notifications/initialized" => {
            return None;
        }
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: id.unwrap_or(serde_json::Value::Null),
            result: Some(json!({})),
            error: None,
        },
        "tools/list" => {
            let tools = get_tool_definitions();
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: id.unwrap_or(serde_json::Value::Null),
                result: Some(json!({ "tools": tools })),
                error: None,
            }
        }
        "tools/call" => {
            let tool_name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = req.params.get("arguments").cloned().unwrap_or(json!({}));

            match state.execute_tool(tool_name, &arguments) {
                Ok(content) => JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: id.unwrap_or(serde_json::Value::Null),
                    result: Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": serde_json::to_string_pretty(&content).unwrap_or_default()
                            }
                        ],
                        "isError": false
                    })),
                    error: None,
                },
                Err(err) => JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: id.unwrap_or(serde_json::Value::Null),
                    result: Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": err.message
                            }
                        ],
                        "isError": true
                    })),
                    error: None,
                },
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: id.unwrap_or(serde_json::Value::Null),
            result: None,
            error: Some(JsonRpcErrorPayload {
                code: -32601,
                message: format!("Method not found: {}", req.method),
                data: None,
            }),
        },
    };

    serde_json::to_string(&resp).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_initialize_request() {
        let mut state = McpServerState::new();
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp_str = process_json_rpc(&mut state, init_req).expect("Response generated");
        let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
        assert_eq!(resp["result"]["serverInfo"]["name"], "field-probe-mcp");
    }

    #[test]
    fn test_process_tools_list() {
        let mut state = McpServerState::new();
        let list_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp_str = process_json_rpc(&mut state, list_req).expect("Response generated");
        let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
        let tools = resp["result"]["tools"].as_array().expect("Tools array");
        assert_eq!(tools.len(), 8);
    }

    #[test]
    fn test_process_tools_call_list_dongles() {
        let mut state = McpServerState::new();
        let call_req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_dongles","arguments":{}}}"#;
        let resp_str = process_json_rpc(&mut state, call_req).expect("Response generated");
        let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
        assert_eq!(resp["result"]["isError"], false);
    }
}
