#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;

use crate::types::CIDRConfig;

pub struct CidrManager {
    networks: HashMap<String, Vec<IpNet>>,
}

impl CidrManager {
    pub fn load(configs: &[CIDRConfig]) -> Result<Self> {
        let mut networks = HashMap::new();
        for config in configs {
            let mut list = Vec::new();
            for entry in &config.rules {
                let entry = entry.trim();
                if entry.is_empty() || entry.starts_with('#') {
                    continue;
                }
                let net = entry.parse::<IpNet>().with_context(|| format!("invalid cidr rule: {}", entry))?;
                list.push(net);
            }
            if !config.file.is_empty() {
                let content = std::fs::read_to_string(&config.file)
                    .with_context(|| format!("read cidr file: {}", config.file))?;
                for line in content.lines() {
                    let item = line.trim();
                    if item.is_empty() || item.starts_with('#') {
                        continue;
                    }
                    let net = item.parse::<IpNet>().with_context(|| format!("invalid cidr entry: {}", item))?;
                    list.push(net);
                }
            }
            if list.is_empty() {
                return Err(anyhow!("no valid CIDR entries for tag {}", config.tag));
            }
            networks.insert(config.tag.clone(), list);
        }
        Ok(CidrManager { networks })
    }

    pub fn matches(&self, ip: IpAddr, match_tags: &[String]) -> Result<bool> {
        if match_tags.is_empty() {
            return Ok(true);
        }

        for tag in match_tags {
            let negate = tag.starts_with('!');
            let key = if negate { tag.trim_start_matches('!') } else { tag.as_str() };
            let nets = self
                .networks
                .get(key)
                .with_context(|| format!("cidr tag not found: {}", key))?;
            let contains = nets.iter().any(|net| net.contains(&ip));
            if negate {
                if contains {
                    return Ok(false);
                }
            } else if !contains {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
