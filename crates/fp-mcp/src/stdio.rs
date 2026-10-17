use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::{handler::McpServerState, protocol::process_json_rpc};

/// Run the MCP server over generic async stream reader and writer
pub async fn run_reader_writer<R, W>(
    state: &mut McpServerState,
    reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(resp_json) = process_json_rpc(state, trimmed) {
            writer.write_all(resp_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

/// Run the MCP server over standard process input and output
pub async fn run_stdio_server(state: &mut McpServerState) -> io::Result<()> {
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    run_reader_writer(state, stdin, stdout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_stdio_loop_with_duplex() {
        let mut state = McpServerState::new();

        let (client_read, mut server_write) = tokio::io::duplex(4096);
        let (server_read, mut client_write) = tokio::io::duplex(4096);

        let server_handle = tokio::spawn(async move {
            let buf_reader = tokio::io::BufReader::new(server_read);
            run_reader_writer(&mut state, buf_reader, &mut server_write).await
        });

        // Client writes JSON-RPC initialize
        let init_req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
        client_write.write_all(init_req.as_bytes()).await.unwrap();
        client_write.flush().await.unwrap();

        // Client reads response
        let mut client_lines = tokio::io::BufReader::new(client_read).lines();
        let resp_line = client_lines.next_line().await.unwrap().expect("Response line");

        let resp: serde_json::Value = serde_json::from_str(&resp_line).expect("Valid JSON");
        assert_eq!(resp["result"]["serverInfo"]["name"], "field-probe-mcp");

        // Close stream
        drop(client_write);
        let _ = server_handle.await;
    }
}
