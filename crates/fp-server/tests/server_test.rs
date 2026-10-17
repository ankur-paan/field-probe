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
    assert!(!dongles.is_empty());
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

#[tokio::test]
async fn test_fp_server_sse_streaming() {
    use fp_core::{CanFrame, Direction, LinkParams, RawBusEvent, RawFrame, SerialParams};
    use tokio::io::AsyncBufReadExt;

    let state = Arc::new(ServerState::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(run_server(listener, Arc::clone(&state)));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/events/sse HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let (reader, _writer) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(reader).lines();

    // Verify SSE header
    let status_line = lines.next_line().await.unwrap().expect("Status line");
    assert!(status_line.contains("200 OK"));

    // Consume remaining headers until empty line
    loop {
        let line = lines.next_line().await.unwrap().expect("Header line");
        if line.is_empty() {
            break;
        }
    }

    // Read initial comment
    let comment = lines.next_line().await.unwrap().expect("Initial comment");
    assert_eq!(comment, ": connected");

    // Read empty line after comment
    let _ = lines.next_line().await.unwrap();

    // Broadcast a test event
    let test_event = RawBusEvent {
        interface_id: "can0".to_string(),
        timestamp_us: 123456,
        link_params: LinkParams::Serial(SerialParams::default()),
        payload: RawFrame::Can(CanFrame::new_standard(0x123, &[0xAA, 0xBB])),
        direction: Direction::Rx,
        error_flags: Default::default(),
    };
    state.broadcast_event(test_event);

    // Read SSE event
    let data_line = lines.next_line().await.unwrap().expect("SSE data line");
    assert!(data_line.starts_with("data: "));
    assert!(data_line.contains("123456"));
    assert!(data_line.contains("can0"));

    server_handle.abort();
}

#[tokio::test]
async fn test_fp_server_audit_and_export_endpoints() {
    let state = Arc::new(ServerState::new());

    // Record an audit issue
    {
        let mut report = state.compliance_report.write().await;
        let adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 65530,
                quantity: 10,
            },
            crc16: 0,
        };
        report.audit_modbus_adu(&adu);
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(run_server(listener, Arc::clone(&state)));

    // 1. Test /api/v1/audit
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/audit HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8_lossy(&response_bytes);
    assert!(response_str.contains("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let json_val: Value = serde_json::from_str(&response_str[json_start..]).unwrap();
    assert_eq!(json_val["total_frames_analyzed"], 1);
    assert_eq!(json_val["protocol_violations"], 1);

    // 2. Test /api/v1/export/pcapng
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/export/pcapng HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut pcap_response = Vec::new();
    stream.read_to_end(&mut pcap_response).await.unwrap();
    let header_end = pcap_response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap();
    let header_str = String::from_utf8_lossy(&pcap_response[..header_end]);
    assert!(header_str.contains("HTTP/1.1 200 OK"));
    assert!(header_str.contains("Content-Type: application/vnd.tcpdump.pcap"));
    let binary_body = &pcap_response[header_end + 4..];
    // PCAP-NG Section Header Block magic: 0x0A0D0D0A
    assert_eq!(&binary_body[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);

    // 3. Test /api/v1/export/json
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/export/json HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut json_response = Vec::new();
    stream.read_to_end(&mut json_response).await.unwrap();
    let json_str = String::from_utf8_lossy(&json_response);
    assert!(json_str.contains("HTTP/1.1 200 OK"));
    assert!(json_str.contains("Content-Type: application/json"));

    server_handle.abort();
}
