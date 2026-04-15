use std::collections::HashSet;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use url::Url;

use crate::types::{CIDRConfig, DDRSettings, DNSRecordConfig, FeatureFlags, HTTPSSettings, LatencyProbeStep, RedisSettings, RewriteRule, ServerConfig, ServerSettings, TLSSettings, UpstreamServer};

pub async fn load_config(path: Option<&str>) -> Result<ServerConfig> {
    let mut config = if let Some(path) = path {
        let data = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read config: {}", path))?;
        serde_json::from_str(&data).context("parse config")?
    } else {
        get_default_config()
    };

    validate_config(&mut config).await?;
    Ok(config)
}

pub fn generate_example_config() -> Result<String> {
    let config = get_default_config();
    serde_json::to_string_pretty(&config).context("generate example config")
}

async fn validate_config(config: &mut ServerConfig) -> Result<()> {
    let valid_levels = ["error", "warn", "info", "debug"];
    let log_level = config.server.log_level.to_lowercase();
    if !log_level.is_empty() && !valid_levels.contains(&log_level.as_str()) {
        config.server.log_level = "info".to_string();
    }

    if !config.server.default_ecs_subnet.is_empty() {
        let ecs = config.server.default_ecs_subnet.to_lowercase();
        let valid_presets = ["auto", "auto_v4", "auto_v6"];
        if !valid_presets.contains(&ecs.as_str()) {
            if ecs.parse::<ipnet::IpNet>().is_err() {
                return Err(anyhow!("invalid ECS subnet: {}", config.server.default_ecs_subnet));
            }
        }
    }

    let mut tags = HashSet::new();
    for cidr in &config.cidr {
        if cidr.tag.trim().is_empty() {
            return Err(anyhow!("CIDR config tag cannot be empty"));
        }
        if !tags.insert(cidr.tag.clone()) {
            return Err(anyhow!("duplicate CIDR tag: {}", cidr.tag));
        }
        if cidr.file.is_empty() && cidr.rules.is_empty() {
            return Err(anyhow!("CIDR config {}: either 'file' or 'rules' must be specified", cidr.tag));
        }
        if !cidr.file.is_empty() && !is_valid_file_path(&cidr.file).await {
            return Err(anyhow!("CIDR config {}: file not found: {}", cidr.tag, cidr.file));
        }
    }

    for (i, upstream) in config.upstream.iter_mut().enumerate() {
        let protocol = upstream.normalized_protocol();
        if !upstream.server_name.is_empty() && protocol == "udp" {
            // no-op
        }

        if upstream.is_recursive() {
            continue;
        }

        match protocol.as_str() {
            "udp" | "tcp" => {
                let _ = split_host_port(&upstream.address).ok_or_else(|| anyhow!("upstream server {} address invalid: {}", i, upstream.address))?;
            }
            "tls" | "dot" => {
                let _ = split_host_port(&upstream.address).ok_or_else(|| anyhow!("upstream server {} address invalid: {}", i, upstream.address))?;
                if upstream.server_name.is_empty() {
                    return Err(anyhow!("upstream server {} using {} requires server_name", i, upstream.protocol));
                }
            }
            "https" | "doh" => {
                Url::from_str(&upstream.address)
                    .with_context(|| format!("upstream server {} address invalid", i))?;
                if upstream.server_name.is_empty() {
                    return Err(anyhow!("upstream server {} using {} requires server_name", i, upstream.protocol));
                }
            }
            "quic" | "http3" => {
                Url::from_str(&upstream.address)
                    .with_context(|| format!("upstream server {} address invalid", i))?;
                if upstream.server_name.is_empty() {
                    return Err(anyhow!("upstream server {} using {} requires server_name", i, upstream.protocol));
                }
            }
            _ => return Err(anyhow!("upstream server {} protocol invalid: {}", i, upstream.protocol)),
        }
        for match_tag in &upstream.match_tags {
            let clean_tag = match_tag.trim_start_matches('!');
            if !tags.contains(clean_tag) {
                return Err(anyhow!("upstream server {}: match tag '{}' not found", i, match_tag));
            }
        }
    }

    if !config.redis.address.is_empty() {
        if split_host_port(&config.redis.address).is_none() {
            return Err(anyhow!("redis address invalid: {}", config.redis.address));
        }
    }

    if config.server.memory_cache_size == 0 {
        config.server.memory_cache_size = 10000;
    }

    for (i, step) in config.server.latency_probe.iter_mut().enumerate() {
        let protocol = step.protocol.to_lowercase();
        if protocol.is_empty() {
            return Err(anyhow!("latency_probe step {}: protocol cannot be empty", i));
        }
        match protocol.as_str() {
            "ping" | "icmp" => step.protocol = "ping".to_string(),
            "tcp" => {
                if step.port == 0 {
                    step.port = 80;
                }
            }
            "udp" => {
                if step.port == 0 {
                    step.port = 53;
                }
            }
            _ => return Err(anyhow!("latency_probe step {}: unsupported protocol {}", i, step.protocol)),
        }
        if step.timeout == 0 {
            step.timeout = 100;
        }
    }

    if config.server.tls.self_signed && (!config.server.tls.cert_file.is_empty() || !config.server.tls.key_file.is_empty()) {
        // ignore cert/key when self-signed enabled
    }

    if !config.server.tls.self_signed && (!config.server.tls.cert_file.is_empty() || !config.server.tls.key_file.is_empty()) {
        if config.server.tls.cert_file.is_empty() || config.server.tls.key_file.is_empty() {
            return Err(anyhow!("config: cert and key files must be configured together"));
        }
        if !is_valid_file_path(&config.server.tls.cert_file).await {
            return Err(anyhow!("config: cert file not found: {}", config.server.tls.cert_file));
        }
        if !is_valid_file_path(&config.server.tls.key_file).await {
            return Err(anyhow!("config: key file not found: {}", config.server.tls.key_file));
        }
    }

    Ok(())
}

fn split_host_port(addr: &str) -> Option<(&str, u16)> {
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port = parts[0].parse().ok()?;
    Some((parts[1], port))
}

async fn is_valid_file_path(path: &str) -> bool {
    if path.contains("..") || path.starts_with("/etc/") || path.starts_with("/proc/") || path.starts_with("/sys/") {
        return false;
    }
    tokio::fs::metadata(path).await.is_ok()
}

fn get_default_config() -> ServerConfig {
    ServerConfig {
        server: ServerSettings {
            port: "53".to_string(),
            pprof: "6060".to_string(),
            log_level: "info".to_string(),
            default_ecs_subnet: "auto".to_string(),
            memory_cache_size: 10000,
            ddr: DDRSettings {
                domain: "dns.example.com".to_string(),
                ipv4: "127.0.0.1".to_string(),
                ipv6: "::1".to_string(),
            },
            tls: TLSSettings {
                port: "853".to_string(),
                https: HTTPSSettings {
                    port: "443".to_string(),
                    endpoint: "/dns-query".to_string(),
                },
                ..Default::default()
            },
            features: FeatureFlags {
                force_dnssec: true,
                hijack_protection: true,
            },
            latency_probe: vec![
                LatencyProbeStep { protocol: "ping".to_string(), port: 0, timeout: 100 },
                LatencyProbeStep { protocol: "tcp".to_string(), port: 80, timeout: 100 },
                LatencyProbeStep { protocol: "tcp".to_string(), port: 443, timeout: 100 },
                LatencyProbeStep { protocol: "udp".to_string(), port: 53, timeout: 100 },
            ],
            ..Default::default()
        },
        redis: RedisSettings {
            address: "127.0.0.1:6379".to_string(),
            password: String::new(),
            database: 0,
            key_prefix: "zjdns:".to_string(),
        },
        upstream: vec![
            UpstreamServer { address: "223.5.5.5:53".to_string(), protocol: "tcp".to_string(), server_name: String::new(), skip_tls_verify: false, match_tags: vec![] },
            UpstreamServer { address: "223.6.6.6:53".to_string(), protocol: "udp".to_string(), server_name: String::new(), skip_tls_verify: false, match_tags: vec![] },
            UpstreamServer { address: "223.5.5.5:853".to_string(), protocol: "tls".to_string(), server_name: "dns.alidns.com".to_string(), skip_tls_verify: false, match_tags: vec![] },
            UpstreamServer { address: "223.6.6.6:853".to_string(), protocol: "quic".to_string(), server_name: "dns.alidns.com".to_string(), skip_tls_verify: true, match_tags: vec![] },
            UpstreamServer { address: "https://223.5.5.5:443/dns-query".to_string(), protocol: "https".to_string(), server_name: "dns.alidns.com".to_string(), skip_tls_verify: false, match_tags: vec![] },
            UpstreamServer { address: "https://223.6.6.6:443/dns-query".to_string(), protocol: "http3".to_string(), server_name: "dns.alidns.com".to_string(), skip_tls_verify: false, match_tags: vec![] },
            UpstreamServer { address: "builtin_recursive".to_string(), protocol: String::new(), server_name: String::new(), skip_tls_verify: false, match_tags: vec![] },
        ],
        rewrite: vec![
            RewriteRule {
                name: "blocked.example.com".to_string(),
                normalized_name: String::new(),
                response_code: None,
                records: vec![DNSRecordConfig { name: String::new(), r#type: "A".to_string(), class: "IN".to_string(), ttl: 10, content: "127.0.0.1".to_string(), response_code: None }],
                additional: vec![],
            },
            RewriteRule {
                name: "ipv6.blocked.example.com".to_string(),
                normalized_name: String::new(),
                response_code: None,
                records: vec![DNSRecordConfig { name: String::new(), r#type: "AAAA".to_string(), class: "IN".to_string(), ttl: 10, content: "::1".to_string(), response_code: None }],
                additional: vec![],
            },
        ],
        cidr: vec![
            CIDRConfig { file: "whitelist.txt".to_string(), rules: vec![], tag: "file".to_string() },
            CIDRConfig { file: String::new(), rules: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string(), "2001:db8::/32".to_string()], tag: "rules".to_string() },
            CIDRConfig { file: "blacklist.txt".to_string(), rules: vec!["127.0.0.1/32".to_string()], tag: "mixed".to_string() },
        ],
    }
}
