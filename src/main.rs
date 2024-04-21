use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use std::io::{Error, ErrorKind};
use tokio::io::copy_bidirectional;
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::read_to_string;
use camino::Utf8PathBuf;
use toml::{self, from_str};
use std::sync::Arc;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Duration;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to config
    #[clap(short, long)]
    config: Utf8PathBuf
}

#[derive(Deserialize, Debug)]
struct Config {
    bind: Server,
    routes: Option<HashMap<String, Server>>,
}

#[derive(Deserialize, Debug)]
struct Server {
    host: String,
    port: u16
}

fn load_config(path: Utf8PathBuf) -> io::Result<Config> {
    let config_str = read_to_string(path)?;
    let config = from_str::<Config>(&config_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    env_logger::init();
    let args = Args::parse();
    let config = load_config(args.config)?;
    let bind = format!("{}:{}", config.bind.host, config.bind.port);
    let listener = TcpListener::bind(&bind).await?;
    log::info!("Listening for connections on {}", bind);
    let config = Arc::new(config);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&active_connections);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let count = counter.load(Ordering::SeqCst);
            log::info!("Active connections: {}", count);
        }
    });

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let config = Arc::clone(&config);
                let active_connections = Arc::clone(&active_connections);
                tokio::spawn(async move {
                    if let Err(e) = process(socket, addr, active_connections, config).await {
                        log::error!("Error processing connection: {}", e);
                    }
                });
            },
            Err(e) => log::error!("Failed to accept connection: {}", e),
        }
    }
}

async fn process(mut inbound: TcpStream, addr: SocketAddr, active_connections: Arc<AtomicUsize>, config: Arc<Config>) -> io::Result<()> {
    log::info!("Connection accepted from {}", addr);

    let mut buffer = [0; 4096];

    log::debug!("Awaiting TLS request from client!");
    let n = inbound.read(&mut buffer).await?;
    if n == 0 {
        inbound.shutdown().await?;
        return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed by client before TLS request"));
    }
    log::debug!("Received data from client: {:?}", hex::encode(&buffer[..n]));
    
    if buffer[..n] == [0, 0, 0, 8, 4, 210, 22, 47] {
        log::info!("Handshake initiated!");
        log::debug!("Received TLS request from client!");
        log::debug!("Sending TLS response to client!");
        inbound.write_all(b"S").await?;
    } else {         
        inbound.shutdown().await?;
        return Err(Error::new(ErrorKind::UnexpectedEof, "Invalid initial handshake data"));
    }

    log::debug!("Awaiting TLS handshake ClientHello from client!");
    let n = inbound.read(&mut buffer).await?;
    if n == 0 {
        inbound.shutdown().await?;
        return Err(Error::new(ErrorKind::UnexpectedEof, "No data received during handshake ClientHello"));
    }
    log::debug!("Received data from client: {:?}", hex::encode(&buffer[..n]));
    
    log::debug!("Received TLS handshake ClientHello from client!");
    log::debug!("Parsing TLS handshake ClientHello for server hostname!");
    let server_name = parse_client_hello(&buffer[..n]);
    log::debug!("Extracted server hostname {} from TLS handshake ClientHello!", server_name);
    log::info!("Matching {} with route for {}", addr, server_name);
    let server = config.routes.as_ref()
                            .and_then(|routes| routes.get(&server_name))
                            .unwrap_or(&config.bind);

    log::debug!("Matched server hostname {} with route to server: {}:{}!", server_name, server.host, server.port);
    log::info!("Routing from {} to {}:{} for {}", server_name, server.host, server.port, addr);
    let mut outbound = TcpStream::connect(format!("{}:{}", server.host, server.port)).await?;
    log::info!("Connection with {}:{} established for {}", server.host, server.port, addr);

    log::debug!("Sending TLS request to server!");
    outbound.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).await?;
    
    log::debug!("Awaiting TLS response from server!");
    let mut response = [0; 1];
    
    outbound.read_exact(&mut response).await?;
    log::debug!("Received data from server: {:?}", hex::encode(response));
    
    if response == [83] {
        log::debug!("Received TLS response from server!");
        log::debug!("Forwarding TLS handshake ClientHello to server!");
        outbound.write_all(&buffer[..n]).await?;
    }
    
    log::debug!("Awaiting TLS handshake ServerHello from server!");
    let n = outbound.read(&mut buffer).await?;
    if n == 0 {
        outbound.shutdown().await?;
        inbound.shutdown().await?;
        return Err(Error::new(ErrorKind::UnexpectedEof, "No ServerHello received"));
    }
    log::debug!("Received data from server: {:?}", hex::encode(&buffer[..n]));
    log::debug!("Received TLS handshake ServerHello from server!");
    log::debug!("Forwarding TLS handshake ServerHello to client!");
    inbound.write_all(&buffer[..n]).await?;

    log::info!("Handshake complete!");

    let n = inbound.read(&mut buffer).await?;
    if n == 0 {
        outbound.shutdown().await?; 
        return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); 
    }
    outbound.write_all(&buffer[..n]).await?;
    let m = outbound.read(&mut buffer).await?;
    if m == 0 { inbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); }
    inbound.write_all(&buffer[..m]).await?;
    let n = inbound.read(&mut buffer).await?;
    if n == 0 { outbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); }
    outbound.write_all(&buffer[..n]).await?;
    let m = outbound.read(&mut buffer).await?;
    if m == 0 { inbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); }
    inbound.write_all(&buffer[..m]).await?;

    let m = outbound.read(&mut buffer).await?;
    if m == 0 { inbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!"));}
    inbound.write_all(&buffer[..m]).await?;
    let n = inbound.read(&mut buffer).await?;
    if n == 0 { outbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); }
    outbound.write_all(&buffer[..n]).await?;
    let m = outbound.read(&mut buffer).await?;
    if m == 0 { inbound.shutdown().await?; return Err(Error::new(ErrorKind::UnexpectedEof,"Something went wrong!")); }
    inbound.write_all(&buffer[..m]).await?;
    let n = inbound.read(&mut buffer).await?;
    if n == 0 { outbound.shutdown().await?; return Ok(()); }
    outbound.write_all(&buffer[..n]).await?;

    log::info!("Forwarding all messages...");

    active_connections.fetch_add(1, Ordering::SeqCst);

    let copy_result = copy_bidirectional(&mut inbound, &mut outbound).await;

    match copy_result {
        Ok((from_client, from_server)) => {
            log::info!("Transferred {} bytes from client to server and {} bytes from server to client for {}", from_client, from_server, addr);
        },
        Err(e) => {
            active_connections.fetch_sub(1, Ordering::SeqCst);
            log::error!("Error during data transfer for {}: {}", addr, e);
            inbound.shutdown().await?;
            outbound.shutdown().await?;
        }
    }

    inbound.shutdown().await?;
    outbound.shutdown().await?;
    active_connections.fetch_sub(1, Ordering::SeqCst);
    log::info!("Connection with {} closed.", addr);
    Ok(())
}

const SESSION_ID_OFFSET: usize = 43;

fn parse_client_hello(buf: &[u8]) -> String {
    let session_id_length = buf[SESSION_ID_OFFSET] as usize;
    let cipher_suites_length = get_u16(&buf[SESSION_ID_OFFSET + 1 + session_id_length..]) as usize;
    let compression_methods_length = buf[SESSION_ID_OFFSET + 1 + session_id_length + 2 + cipher_suites_length] as usize;
    let extensions_length = get_u16(&buf[SESSION_ID_OFFSET + 1 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length..]) as usize;
    let extensions_start = SESSION_ID_OFFSET + 1 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length + 2;

    let tls_handshake_extensions = &buf[extensions_start..extensions_start + extensions_length];
    parse_server_name(tls_handshake_extensions)
}

fn get_u16(slice: &[u8]) -> u16 {
    u16::from_be_bytes([slice[0], slice[1]])
}

fn parse_server_name(extensions: &[u8]) -> String {
    if let Some(pos) = extensions.windows(2).position(|window| window == [0, 0]) {
        let server_name_list_length = get_u16(&extensions[pos + 4..]) as usize;
        if server_name_list_length > 3 {
            let server_name_length = get_u16(&extensions[pos + 7..]) as usize;
            let server_name_start = pos + 9;
            let server_name_end = server_name_start + server_name_length;
            std::str::from_utf8(&extensions[server_name_start..server_name_end])
                .unwrap_or_default()
                .trim_matches(char::from(0))
                .to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

