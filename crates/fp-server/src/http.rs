use crate::api::ServerState;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

/// Start the HTTP telemetry server on the specified bound TcpListener
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

    let (status_code, body) = match path {
        "/health" => (200, state.handle_health()),
        "/api/v1/dongles" => (200, state.handle_dongles()),
        "/api/v1/bus/summary" => (200, state.handle_bus_summary().await),
        "/api/v1/catalog" => (200, state.handle_catalog().await),
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
