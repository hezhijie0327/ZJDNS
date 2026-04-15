use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::ServerName;
use trust_dns_proto::op::Message;

use crate::types::UpstreamServer;
use crate::security::build_tls_client_config;

#[derive(Clone)]
pub struct QueryClient {
    http: Client,
    timeout: Duration,
}

impl QueryClient {
    pub fn new() -> Self {
        QueryClient {
            http: Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("build reqwest client"),
            timeout: Duration::from_secs(3),
        }
    }

    pub async fn execute_query(&self, request: &Message, server: &UpstreamServer) -> Result<Message> {
        let protocol = server.normalized_protocol();
        let bytes = request.to_vec().context("serialize outgoing query")?;
        let response_bytes = match protocol.as_str() {
            "udp" => self.send_udp(&server.address, &bytes).await?,
            "tcp" => self.send_tcp(&server.address, &bytes).await?,
            "tls" | "dot" => self.send_tls(&server.address, server, &bytes).await?,
            "https" | "doh" => self.send_doh(&server.address, server, &bytes).await?,
            "quic" | "http3" => return Err(anyhow!("unsupported protocol: {}", protocol)),
            _ => self.send_udp(&server.address, &bytes).await?,
        };
        Message::from_vec(&response_bytes).context("parse upstream response")
    }

    async fn send_udp(&self, address: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(bytes, address).await?;
        let mut buf = vec![0u8; 8192];
        let (n, _) = timeout(self.timeout, socket.recv_from(&mut buf)).await??;
        Ok(buf[..n].to_vec())
    }

    async fn send_tcp(&self, address: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut stream = timeout(self.timeout, TcpStream::connect(address)).await??;
        let len = (bytes.len() as u16).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &len).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, bytes).await?;
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf).await?;
        let size = u16::from_be_bytes(len_buf) as usize;
        let mut buffer = vec![0u8; size];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer).await?;
        Ok(buffer)
    }

    async fn send_tls(&self, address: &str, server: &UpstreamServer, bytes: &[u8]) -> Result<Vec<u8>> {
        let (host, _) = address.split_once(':').ok_or_else(|| anyhow!("invalid TLS upstream address"))?;
        let stream = timeout(self.timeout, TcpStream::connect(address)).await??;
        let config = build_tls_client_config(server.skip_tls_verify)?;
        let connector = TlsConnector::from(Arc::new(config));
        let dnsname = ServerName::try_from(host).map_err(|_| anyhow!("invalid server name"))?;
        let mut tls_stream = connector.connect(dnsname, stream).await?;
        let len = (bytes.len() as u16).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, &len).await?;
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, bytes).await?;
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut len_buf).await?;
        let size = u16::from_be_bytes(len_buf) as usize;
        let mut buffer = vec![0u8; size];
        tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut buffer).await?;
        Ok(buffer)
    }

    async fn send_doh(&self, address: &str, _server: &UpstreamServer, bytes: &[u8]) -> Result<Vec<u8>> {
        let request = self
            .http
            .post(address)
            .header("content-type", "application/dns-message")
            .body(bytes.to_vec())
            .send()
            .await?;
        if !request.status().is_success() {
            return Err(anyhow!("DoH HTTP error: {}", request.status()));
        }
        let bytes = request.bytes().await?;
        Ok(bytes.to_vec())
    }
}

pub struct QueryManager {
    upstream: Vec<UpstreamServer>,
    client: QueryClient,
}

impl QueryManager {
    pub fn new(upstream: Vec<UpstreamServer>, client: QueryClient) -> Self {
        QueryManager { upstream, client }
    }

    pub async fn query(&self, request: Message) -> Result<Message> {
        let mut tasks = Vec::new();
        for upstream in &self.upstream {
            let message = request.clone();
            let upstream = upstream.clone();
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                client.execute_query(&message, &upstream).await
            }));
        }

        for task in tasks {
            if let Ok(Ok(response)) = task.await {
                return Ok(response);
            }
        }

        Err(anyhow!("all upstream queries failed"))
    }
}
