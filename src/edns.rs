#![allow(dead_code)]

use crate::types::ECSOption;
use trust_dns_proto::op::Message;

pub fn parse_ecs(_message: &Message) -> Option<ECSOption> {
    // EDNS parsing and ECS extraction are not yet implemented in the Rust migration.
    // This placeholder keeps the same shape as the original project and can be extended.
    None
}

pub fn add_default_edns(_message: &mut Message, _ecs: Option<&ECSOption>) {
    // Extended EDNS handling will be added later.
}
