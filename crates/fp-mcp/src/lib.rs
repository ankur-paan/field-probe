//! `fp-mcp`
//!
//! Model Context Protocol (MCP) server implementation exposing 8 industrial bus diagnostic tools.

pub mod handler;
pub mod protocol;
pub mod stdio;
pub mod tools;

pub use handler::{McpError, McpServerState};
pub use protocol::{process_json_rpc, JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse};
pub use stdio::{run_reader_writer, run_stdio_server};
pub use tools::{get_tool_definitions, McpToolDefinition, McpToolName};
