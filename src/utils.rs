#![allow(dead_code)]

use std::net::IpAddr;
use trust_dns_proto::op::Query;

use crate::types::ECSOption;

pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

pub fn build_cache_key(query: &Query, ecs: &Option<ECSOption>, request_dnssec: bool, prefix: &str) -> String {
    let mut key = String::with_capacity(128);
    key.push_str(prefix);
    key.push_str("dns:");
    key.push_str(&query.name().to_ascii().trim_end_matches('.').to_lowercase());
    key.push('|');
    key.push_str(&format!("{}", query.query_type()));
    if request_dnssec {
        key.push_str("|dnssec");
    }
    if let Some(ecs) = ecs {
        key.push_str("|ecs=");
        key.push_str(&ecs.address);
        key.push('/');
        key.push_str(&ecs.source_prefix.to_string());
    }
    key
}

pub fn min_ttl(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 10;
    }
    10
}

pub fn parse_socket_addr(addr: &str) -> Option<std::net::SocketAddr> {
    addr.parse().ok()
}

pub fn ip_matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
        return net.contains(&ip);
    }
    false
}

pub fn safe_path(path: &str) -> bool {
    if path.contains("..") {
        return false;
    }
    !path.starts_with("/etc/") && !path.starts_with("/proc/") && !path.starts_with("/sys/")
}
