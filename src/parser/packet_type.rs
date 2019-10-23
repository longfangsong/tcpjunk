use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum PacketType {
    IPV4,
    IPV6,
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            PacketType::IPV4 => "IPV4",
            PacketType::IPV6 => "IPV6",
        })
    }
}

lazy_static! {
    pub(crate) static ref PACKET_TYPES: HashMap<u16, PacketType> = {
        let mut m = HashMap::new();
        m.insert(0x0800, PacketType::IPV4);
        m.insert(0x86dd, PacketType::IPV6);
        m
    };
}