use fp_dissectors::{ModbusPdu, ModbusRtuAdu};
use fp_mcp::{run_reader_writer, McpServerState};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_mcp_client_full_field_session_over_stdio() {
    let mut state = McpServerState::new();

    // 1. Feed synthetic Modbus RTU traffic simulating a noisy industrial bus
    // Valid query & response pair
    let query = ModbusRtuAdu {
        slave_id: 1,
        pdu: ModbusPdu::ReadHoldingRegistersQuery {
            start_addr: 40001,
            quantity: 2,
        },
        crc16: 0,
    };
    state.feed_modbus_frame(&query, 1_000_000);

    // Response yielding 23.45 in Float32 (CDAB)
    let resp = ModbusRtuAdu {
        slave_id: 1,
        pdu: ModbusPdu::ReadResponse {
            function_code: 0x03,
            byte_count: 4,
            data: vec![0x99, 0x9A, 0x41, 0xBB],
        },
        crc16: 0,
    };
    state.feed_modbus_frame(&resp, 1_015_000);

    // Also feed an invalid query to trigger compliance diagnostics
    let overflow_query = ModbusRtuAdu {
        slave_id: 1,
        pdu: ModbusPdu::ReadHoldingRegistersQuery {
            start_addr: 65530,
            quantity: 10,
        },
        crc16: 0,
    };
    state.feed_modbus_frame(&overflow_query, 1_050_000);

    // 2. Set up duplex pipes simulating process stdio
    let (client_read, mut server_write) = tokio::io::duplex(8192);
    let (server_read, mut client_write) = tokio::io::duplex(8192);

    let server_task = tokio::spawn(async move {
        let buf_reader = tokio::io::BufReader::new(server_read);
        let _ = run_reader_writer(&mut state, buf_reader, &mut server_write).await;
    });

    let mut client_lines = tokio::io::BufReader::new(client_read).lines();

    // STEP A: Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    client_write
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let init_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Init response");
    let init_resp: serde_json::Value = serde_json::from_str(&init_resp_str).unwrap();
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "field-probe-mcp");

    // STEP B: List Tools
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    client_write
        .write_all(format!("{}\n", list_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let list_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("List response");
    let list_resp: serde_json::Value = serde_json::from_str(&list_resp_str).unwrap();
    let tools = list_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 9);

    // STEP C: Call auto_detect_bus
    let detect_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "auto_detect_bus",
            "arguments": { "interface_id": "usb-serial-port-0" }
        }
    });
    client_write
        .write_all(format!("{}\n", detect_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let detect_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Detect response");
    let detect_resp: serde_json::Value = serde_json::from_str(&detect_resp_str).unwrap();
    assert_eq!(detect_resp["result"]["isError"], false);
    let detect_text = detect_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(detect_text.contains("ModbusRtu"));

    // STEP D: Call get_register_catalog
    let cat_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_register_catalog",
            "arguments": { "interface_id": "usb-serial-port-0" }
        }
    });
    client_write
        .write_all(format!("{}\n", cat_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let cat_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Catalog response");
    let cat_resp: serde_json::Value = serde_json::from_str(&cat_resp_str).unwrap();
    let cat_text = cat_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(cat_text.contains("Float32 (CDAB"));

    // STEP E: Call run_compliance_audit
    let audit_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "run_compliance_audit",
            "arguments": { "interface_id": "usb-serial-port-0" }
        }
    });
    client_write
        .write_all(format!("{}\n", audit_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let audit_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Audit response");
    let audit_resp: serde_json::Value = serde_json::from_str(&audit_resp_str).unwrap();
    let audit_text = audit_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(audit_text.contains("MODBUS-001-ADDR-OVERFLOW"));

    // STEP F: Verify Tier-0 Zero-TX blocks unpermitted active probing
    let probe_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "request_active_probe",
            "arguments": {}
        }
    });
    client_write
        .write_all(format!("{}\n", probe_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let probe_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Probe response");
    let probe_resp: serde_json::Value = serde_json::from_str(&probe_resp_str).unwrap();
    assert_eq!(probe_resp["result"]["isError"], true);
    assert!(probe_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("BLOCKED"));

    // STEP G: Call export_bus_artifacts (Telegraf & JSON)
    let export_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "export_bus_artifacts",
            "arguments": { "format": "telegraf" }
        }
    });
    client_write
        .write_all(format!("{}\n", export_req).as_bytes())
        .await
        .unwrap();
    client_write.flush().await.unwrap();

    let export_resp_str = client_lines
        .next_line()
        .await
        .unwrap()
        .expect("Export response");
    let export_resp: serde_json::Value = serde_json::from_str(&export_resp_str).unwrap();
    let export_text = export_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(export_text.contains("industrial_register"));

    // Clean teardown
    drop(client_write);
    let _ = server_task.await;
}
