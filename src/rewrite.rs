use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::Result;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::{dns_class::DNSClass, rdata::TXT, Name, RData, Record, RecordType};

use crate::types::{DNSRecordConfig, RewriteRule};
use crate::utils::normalize_domain;

pub struct RewriteManager {
    rules: HashMap<String, RewriteRule>,
}

impl RewriteManager {
    pub fn new() -> Self {
        RewriteManager {
            rules: HashMap::new(),
        }
    }

    pub fn load_rules(&self, rules: &[RewriteRule]) -> Result<()> {
        let mut store = self.rules.clone();
        for rule in rules {
            if rule.name.len() > 253 {
                continue;
            }
            let normalized = normalize_domain(&rule.name);
            let mut rule = rule.clone();
            rule.normalized_name = normalized.clone();
            store.insert(normalized, rule);
        }
        Ok(())
    }

    pub fn rewrite(&self, domain: &str, qtype: RecordType, qclass: DNSClass) -> Result<Option<Message>> {
        let normalized = normalize_domain(domain);
        if let Some(rule) = self.rules.get(&normalized) {
            let mut response = Message::new();
            response.set_message_type(MessageType::Response);
            response.set_op_code(OpCode::Query);
            response.set_recursion_available(true);
            response.set_id(0);

            if let Some(code) = rule.response_code {
                response.set_response_code(ResponseCode::from_low(code as u8));
                return Ok(Some(response));
            }

            for record in &rule.records {
                if let Some(rr) = self.build_record(domain, record, qtype, qclass)? {
                    response.add_answer(rr);
                }
            }
            for record in &rule.additional {
                if let Some(rr) = self.build_record(domain, record, qtype, qclass)? {
                    response.add_additional(rr);
                }
            }
            return Ok(Some(response));
        }
        Ok(None)
    }

    fn build_record(
        &self,
        domain: &str,
        record: &DNSRecordConfig,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Option<Record>> {
        if record.r#type.is_empty() {
            return Ok(None);
        }
        let record_type = RecordType::from_str(&record.r#type.to_uppercase())?;
        let record_class = if record.class.is_empty() {
            DNSClass::IN
        } else {
            DNSClass::from_str(&record.class.to_uppercase())?
        };

        if !record.response_code.map_or(true, |_code| record_type == qtype && record_class == qclass) {
            return Ok(None);
        }

        let name = if record.name.is_empty() { domain.to_string() } else { record.name.clone() };
        let name = Name::from_str(&name)?;
        let rdata = match record_type {
            RecordType::A => {
                let ip = record.content.parse::<Ipv4Addr>().ok();
                if let Some(ip) = ip {
                    RData::A(ip)
                } else {
                    return Ok(None);
                }
            }
            RecordType::AAAA => {
                let ip = record.content.parse::<Ipv6Addr>().ok();
                if let Some(ip) = ip {
                    RData::AAAA(ip)
                } else {
                    return Ok(None);
                }
            }
            RecordType::CNAME => {
                let cname = Name::from_str(&record.content)?;
                RData::CNAME(cname)
            }
            RecordType::TXT => {
                RData::TXT(TXT::new(vec![record.content.clone()]))
            }
            _ => {
                return Ok(None);
            }
        };

        let mut rr = Record::new();
        rr.set_name(name);
        rr.set_dns_class(record_class);
        rr.set_rr_type(record_type);
        rr.set_ttl(record.ttl.max(1));
        rr.set_data(Some(rdata));
        Ok(Some(rr))
    }
}
