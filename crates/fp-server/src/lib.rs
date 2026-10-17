//! `fp-server`
//!
//! HTTP REST and WebSocket/SSE telemetry server for `field-probe`.

pub mod api;
pub mod http;

pub use api::{ServerState, ServerStatus};
pub use http::run_server;
