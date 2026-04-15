use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use trust_dns_proto::op::{Message, MessageType, Query};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::cache::{CacheManager, MemoryCache, RedisCache};
use crate::cidr::CidrManager;
use crate::query::{QueryClient, QueryManager};
use crate::rewrite::RewriteManager;
use crate::security::load_tls_config;
use crate::types::ServerConfig;
use crate::utils::{build_cache_key, normalize_domain};

pub struct DNSServer {
    pub config: ServerConfig,
    pub cache: Arc<dyn CacheManager>,
    pub query_manager: QueryManager,
    pub rewrite_manager: RewriteManager,
    #[allow(dead_code)]
    pub cidr_manager: Option<CidrManager>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl DNSServer {
    pub async fn new(config: ServerConfig) -> Result<Arc<Self>> {
        let rewrite_manager = RewriteManager::new();
        rewrite_manager.load_rules(&config.rewrite).context("load rewrite rules")?;

        let cidr_manager = if config.cidr.is_empty() {
            None
        } else {
            Some(CidrManager::load(&config.cidr).context("load cidr config")?)
        };

        let cache: Arc<dyn CacheManager> = if config.redis.address.is_empty() {
            Arc::new(MemoryCache::new(config.server.memory_cache_size))
        } else {
            let redis_cache = RedisCache::new(&config).await.context("init redis cache")?;
            Arc::new(redis_cache)
        };

        let tls_config = if config.server.tls.self_signed || (!config.server.tls.cert_file.is_empty() && !config.server.tls.key_file.is_empty()) {
            Some(load_tls_config(&config.server.tls).context("load TLS config")?)
        } else {
            None
        };

        let query_client = QueryClient::new();
        let query_manager = QueryManager::new(config.upstream.clone(), query_client);

        Ok(Arc::new(DNSServer {
            config,
            cache,
            query_manager,
            rewrite_manager,
            cidr_manager,
            tls_config,
        }))
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("SERVER: Starting ZJDNS server on port {}", self.config.server.port);

        let udp_server = self.clone();
        tokio::spawn(async move {
            if let Err(err) = udp_server.run_udp().await {
                error!("UDP server error: {err}");
            }
        });

        let tcp_server = self.clone();
        tokio::spawn(async move {
            if let Err(err) = tcp_server.run_tcp().await {
                error!("TCP server error: {err}");
            }
        });

        if let Some(tls_config) = self.tls_config.clone() {
            let dot_server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = dot_server.run_dot(tls_config).await {
                    error!("DoT server error: {err}");
                }
            });
        }

        let shutdown = tokio::signal::ctrl_c();
        shutdown.await.context("listen for shutdown")?;

        info!("SERVER: Shutdown requested, exiting");
        Ok(())
    }

    async fn run_udp(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.server.port);
        let socket = Arc::new(UdpSocket::bind(&addr).await.context("bind UDP socket")?);
        info!("UDP: listening on {}", addr);
        let mut buf = vec![0u8; 8192];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await?;
            let packet = buf[..len].to_vec();
            let server = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Ok(response) = server.handle_packet(packet).await {
                    let _ = socket.send_to(&response, peer).await;
                }
            });
        }
    }

    async fn run_tcp(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.server.port);
        let listener = TcpListener::bind(&addr).await.context("bind TCP socket")?;
        info!("TCP: listening on {}", addr);
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = server.handle_tcp_connection(stream).await {
                    error!("TCP connection {} error: {err}", peer);
                }
            });
        }
    }

    async fn run_dot(self: Arc<Self>, tls_config: Arc<rustls::ServerConfig>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.server.tls.port);
        let listener = TcpListener::bind(&addr).await.context("bind DoT socket")?;
        info!("DoT: listening on {}", addr);
        let acceptor = TlsAcceptor::from(tls_config);
        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server = self.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(err) = server.handle_tls_stream(tls_stream).await {
                            error!("DoT stream {} error: {err}", peer);
                        }
                    }
                    Err(err) => error!("DoT TLS accept {}: {err}", peer),
                }
            });
        }
    }

    async fn handle_tcp_connection(self: Arc<Self>, mut stream: TcpStream) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return Ok(());
            }
            let length = u16::from_be_bytes(len_buf) as usize;
            let mut buffer = vec![0u8; length];
            stream.read_exact(&mut buffer).await?;
            let response = self.clone().handle_packet(buffer).await?;
            let response_len = response.len() as u16;
            stream.write_all(&response_len.to_be_bytes()).await?;
            stream.write_all(&response).await?;
        }
    }

    async fn handle_tls_stream<T>(self: Arc<Self>, mut stream: T) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return Ok(());
            }
            let length = u16::from_be_bytes(len_buf) as usize;
            let mut buffer = vec![0u8; length];
            stream.read_exact(&mut buffer).await?;
            let response = self.handle_packet(buffer).await?;
            let response_len = response.len() as u16;
            stream.write_all(&response_len.to_be_bytes()).await?;
            stream.write_all(&response).await?;
        }
    }

    async fn handle_packet(&self, packet: Vec<u8>) -> Result<Vec<u8>> {
        let request = Message::from_vec(&packet).context("parse DNS request")?;
        let query = request.queries().first().cloned();
        let response = self.process_request(request, query).await?;
        let bytes = response.to_vec().context("serialize DNS response")?;
        if bytes.len() > 65535 {
            return Err(anyhow!("DNS response too large"));
        }
        Ok(bytes)
    }

    async fn process_request(&self, request: Message, query: Option<Query>) -> Result<Message> {
        let mut response = Message::new();
        response.set_id(request.id());
        response.set_op_code(request.op_code());
        response.set_message_type(MessageType::Response);
        response.set_recursion_available(true);
        response.set_checking_disabled(request.checking_disabled());

        if let Some(query) = query {
            response.add_query(query.clone());
            let domain = normalize_domain(&query.name().to_ascii());
            if let Some(rewrite_response) = self.rewrite_manager.rewrite(&domain, query.query_type(), query.query_class())? {
                let mut answer = rewrite_response;
                answer.set_id(request.id());
                return Ok(answer);
            }

            let cache_key = build_cache_key(&query, &None, false, "");
            if let Some((bytes, expired)) = self.cache.get(&cache_key).await? {
                if !expired {
                    return Message::from_vec(&bytes).context("parse cached response");
                }
            }

            let mut upstream_request = Message::new();
            upstream_request.add_query(query.clone());
            upstream_request.set_recursion_desired(true);
            let result = self.query_manager.query(upstream_request).await;
            let answer_msg = result?;
            let bytes = answer_msg.to_vec()?;
            let ttl = answer_msg.queries().first().map(|_| 30).unwrap_or(30);
            self.cache.set(&cache_key, &bytes, ttl, false, None).await?;
            return Ok(answer_msg);
        }

        response.set_response_code(trust_dns_proto::op::ResponseCode::FormErr);
        Ok(response)
    }
}
