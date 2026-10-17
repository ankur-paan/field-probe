use crate::api::ServerState;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

/// Start the HTTP telemetry and SSE streaming server on the specified bound TcpListener
pub async fn run_server(listener: TcpListener, state: Arc<ServerState>) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _remote_addr)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, state_clone).await {
                        error!("HTTP connection error: {:?}", err);
                    }
                });
            }
            Err(err) => {
                error!("Listener accept error: {:?}", err);
                return Err(err);
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, state: Arc<ServerState>) -> std::io::Result<()> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    // Read remaining headers until empty line
    let mut header = String::new();
    loop {
        header.clear();
        if buf_reader.read_line(&mut header).await? == 0 || header == "\r\n" || header == "\n" {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        let resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    if method != "GET" {
        let resp = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Handle Server-Sent Events (SSE) live event streaming
    if path == "/api/v1/events/sse" {
        let sse_headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        writer.write_all(sse_headers.as_bytes()).await?;
        writer.write_all(b": connected\n\n").await?;
        writer.flush().await?;

        let mut rx = state.subscribe_events();
        loop {
            tokio::select! {
                ev_res = rx.recv() => {
                    match ev_res {
                        Ok(ev) => {
                            let json_line = serde_json::to_string(&ev).unwrap_or_default();
                            let sse_msg = format!("data: {}\n\n", json_line);
                            if writer.write_all(sse_msg.as_bytes()).await.is_err() {
                                break;
                            }
                            if writer.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        return Ok(());
    }

    // Handle Export endpoints
    if let Some(format) = path.strip_prefix("/api/v1/export/") {
        let (content_type, body_bytes) = state.handle_export(format).await;
        let response_headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            content_type,
            body_bytes.len()
        );
        writer.write_all(response_headers.as_bytes()).await?;
        writer.write_all(&body_bytes).await?;
        writer.flush().await?;
        return Ok(());
    }

    let (status_code, body) = match path {
        "/health" => (200, state.handle_health()),
        "/api/v1/dongles" => (200, state.handle_dongles()),
        "/api/v1/bus/summary" => (200, state.handle_bus_summary().await),
        "/api/v1/catalog" => (200, state.handle_catalog().await),
        "/api/v1/audit" => (200, state.handle_audit().await),
        _ => {
            let not_found = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            writer.write_all(not_found.as_bytes()).await?;
            return Ok(());
        }
    };

    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let response_headers = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_code,
        body_bytes.len()
    );

    writer.write_all(response_headers.as_bytes()).await?;
    writer.write_all(&body_bytes).await?;
    writer.flush().await?;

    Ok(())
}
