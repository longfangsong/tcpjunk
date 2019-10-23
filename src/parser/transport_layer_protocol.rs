use std::collections::HashMap;

use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub(crate) enum TransportLayerProtocol {
    ICMP,
    TCP,
    UDP,
}

impl TransportLayerProtocol {
    pub fn to_u16(&self) -> u16 {
        match self {
            TransportLayerProtocol::ICMP => 0x01,
            TransportLayerProtocol::TCP => 0x06,
            TransportLayerProtocol::UDP => 0x11
        }
    }
}


lazy_static! {
    pub(crate) static ref TRANSPORT_LAYER_PROTOCOL: HashMap<u8, TransportLayerProtocol> = {
        let mut m = HashMap::new();
        m.insert(0x01, TransportLayerProtocol::ICMP);
        m.insert(0x06, TransportLayerProtocol::TCP);
        m.insert(0x11, TransportLayerProtocol::UDP);
        m
    };
}