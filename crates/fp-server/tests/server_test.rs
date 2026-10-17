use fp_dissectors::{ModbusPdu, ModbusRtuAdu};
use fp_server::{run_server, ServerState};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_fp_server_health_and_dongles_endpoints() {
    let state = Arc::new(ServerState::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(run_server(listener, Arc::clone(&state)));

    // 1. Test /health
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8(response_bytes).unwrap();

    assert!(response_str.contains("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let json_val: Value = serde_json::from_str(&response_str[json_start..]).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["zero_tx_enforced"], true);

    // 2. Test /api/v1/dongles
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/dongles HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8(response_bytes).unwrap();

    assert!(response_str.contains("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let json_val: Value = serde_json::from_str(&response_str[json_start..]).unwrap();
    let dongles = json_val["dongles"].as_array().unwrap();
    assert_eq!(dongles.len(), 1);
    assert_eq!(dongles[0]["supports_listen_only"], true);
    assert_eq!(dongles[0]["zero_tx_enforced"], true);

    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_fp_server_bus_summary_and_catalog() {
    let state = Arc::new(ServerState::new());

    // Ingest traffic into inference engine
    {
        let mut engine = state.inference_engine.write().await;
        let query = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 40001,
                quantity: 1,
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&query, 1_000_000);

        let resp = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 2,
                data: vec![0x12, 0x34],
            },
            crc16: 0,
        };
        engine.ingest_modbus_frame(&resp, 1_010_000);
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(run_server(listener, Arc::clone(&state)));

    // Test /api/v1/bus/summary
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/bus/summary HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8(response_bytes).unwrap();

    assert!(response_str.contains("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let json_val: Value = serde_json::from_str(&response_str[json_start..]).unwrap();
    assert_eq!(json_val["baud_rate"], 9600);
    assert_eq!(json_val["total_registers"], 1);

    // Test /api/v1/catalog
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/catalog HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8(response_bytes).unwrap();

    assert!(response_str.contains("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let json_val: Value = serde_json::from_str(&response_str[json_start..]).unwrap();
    assert_eq!(json_val["total_entries"], 1);

    server_handle.abort();
}
