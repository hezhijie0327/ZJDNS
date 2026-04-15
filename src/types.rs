#![allow(dead_code)]

use std::str::FromStr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use trust_dns_proto::rr::{dns_class::DNSClass, Record, RecordType};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub redis: RedisSettings,
    #[serde(default)]
    pub upstream: Vec<UpstreamServer>,
    #[serde(default)]
    pub rewrite: Vec<RewriteRule>,
    #[serde(default)]
    pub cidr: Vec<CIDRConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServerSettings {
    #[serde(default = "default_dns_port")]
    pub port: String,
    #[serde(default)]
    pub pprof: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_ecs_subnet")]
    pub default_ecs_subnet: String,
    #[serde(default = "default_memory_cache_size")]
    pub memory_cache_size: usize,
    #[serde(default)]
    pub ddr: DDRSettings,
    #[serde(default)]
    pub tls: TLSSettings,
    #[serde(default)]
    pub features: FeatureFlags,
    #[serde(default)]
    pub latency_probe: Vec<LatencyProbeStep>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DDRSettings {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TLSSettings {
    #[serde(default = "default_dot_port")]
    pub port: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub self_signed: bool,
    #[serde(default)]
    pub https: HTTPSSettings,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HTTPSSettings {
    #[serde(default = "default_doh_port")]
    pub port: String,
    #[serde(default = "default_query_path")]
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FeatureFlags {
    #[serde(default)]
    pub force_dnssec: bool,
    #[serde(default)]
    pub hijack_protection: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RedisSettings {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: u32,
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamServer {
    pub address: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub skip_tls_verify: bool,
    #[serde(default)]
    pub match_tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LatencyProbeStep {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RewriteRule {
    pub name: String,
    #[serde(default)]
    pub normalized_name: String,
    #[serde(default)]
    pub response_code: Option<u16>,
    #[serde(default)]
    pub records: Vec<DNSRecordConfig>,
    #[serde(default)]
    pub additional: Vec<DNSRecordConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DNSRecordConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub ttl: u32,
    pub content: String,
    #[serde(default)]
    pub response_code: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CIDRConfig {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub rules: Vec<String>,
    pub tag: String,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Vec<u8>,
    pub expires_at: Instant,
    pub validated: bool,
    pub ecs_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ECSOption {
    pub address: String,
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
}

#[derive(Debug, Clone)]
pub struct CookieOption {
    pub client_cookie: Vec<u8>,
    pub server_cookie: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EDEOption {
    pub info_code: u16,
    pub extra_text: String,
}

#[derive(Debug)]
pub struct RewriteResult {
    pub should_rewrite: bool,
    pub response_code: u16,
    pub records: Vec<Record>,
    pub additional: Vec<Record>,
}

impl UpstreamServer {
    pub fn normalized_protocol(&self) -> String {
        let protocol = self.protocol.to_lowercase();
        if protocol.is_empty() {
            return "udp".to_string();
        }
        protocol
    }

    pub fn is_recursive(&self) -> bool {
        self.address == "builtin_recursive"
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            server: ServerSettings::default(),
            redis: RedisSettings::default(),
            upstream: vec![],
            rewrite: vec![],
            cidr: vec![],
        }
    }
}

fn default_dns_port() -> String {
    "53".to_string()
}

fn default_dot_port() -> String {
    "853".to_string()
}

fn default_doh_port() -> String {
    "443".to_string()
}

fn default_query_path() -> String {
    "/dns-query".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_ecs_subnet() -> String {
    "auto".to_string()
}

fn default_memory_cache_size() -> usize {
    10000
}

fn default_redis_prefix() -> String {
    "zjdns:".to_string()
}

impl DNSRecordConfig {
    pub fn record_type(&self) -> RecordType {
        RecordType::from_str(&self.r#type.to_uppercase()).unwrap_or(RecordType::A)
    }

    pub fn record_class(&self) -> DNSClass {
        if self.class.is_empty() {
            DNSClass::IN
        } else {
            DNSClass::from_str(&self.class.to_uppercase()).unwrap_or(DNSClass::IN)
        }
    }
}

impl RewriteResult {
    pub fn default() -> Self {
        RewriteResult {
            should_rewrite: false,
            response_code: 0,
            records: Vec::new(),
            additional: Vec::new(),
        }
    }
}
