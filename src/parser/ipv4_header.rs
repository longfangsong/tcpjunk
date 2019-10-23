use std::convert::TryInto;

use nom::bits::bits;
use nom::bits::complete::take;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map;
use nom::error::ErrorKind;
use nom::IResult;
use nom::sequence::tuple;
use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeStruct;
use ux::*;

use crate::parser::fragmentation::{fragmentation, Fragmentation};
use crate::parser::transport_layer_protocol::TRANSPORT_LAYER_PROTOCOL;
use crate::parser::transport_layer_protocol::TransportLayerProtocol;

#[derive(Debug)]
pub struct IPV4Header {
    version: u4,
    // must be b0100
    header_length: u4,
    differentiated_services_codepoint: u6,
    explicit_congestion_notification: u2,
    total_length: u16,
    identification: u16,
    fragmentation: Fragmentation,
    time_to_live: u8,
    protocol: TransportLayerProtocol,
    header_checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
}

impl Serialize for IPV4Header {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let mut state = serializer.serialize_struct("IPV4Header", 13)?;
        let version: u8 = self.version.into();
        state.serialize_field("version", &version)?;
        let header_length: u8 = self.header_length.into();
        state.serialize_field("header_length", &header_length)?;
        let differentiated_services_codepoint: u8 = self.differentiated_services_codepoint.into();
        state.serialize_field("differentiated_services_codepoint", &differentiated_services_codepoint)?;
        let explicit_congestion_notification: u8 = self.explicit_congestion_notification.into();
        state.serialize_field("explicit_congestion_notification", &explicit_congestion_notification)?;

        state.serialize_field("total_length", &self.total_length)?;
        state.serialize_field("identification", &self.identification)?;
        state.serialize_field("fragmentation", &self.fragmentation)?;
        state.serialize_field("time_to_live", &self.time_to_live)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("header_checksum", &self.header_checksum)?;
        state.serialize_field("checksum_right", &self.valid())?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("destination", &self.destination)?;

        state.end()
    }
}

impl IPV4Header {
    pub fn valid(&self) -> bool {
        let mut all_u16s = vec![];
        all_u16s.push(u16::from(self.version) << 12 | u16::from(self.header_length) << 8 | u16::from(self.differentiated_services_codepoint) << 2 | u16::from(self.explicit_congestion_notification));
        all_u16s.push(self.total_length);
        all_u16s.push(self.identification);
        all_u16s.push(self.fragmentation.clone().into());
        all_u16s.push(u16::from(self.time_to_live) << 8 | self.protocol.to_u16());
        all_u16s.push((self.source[0] as u16) << 8 | self.source[1] as u16);
        all_u16s.push((self.source[2] as u16) << 8 | self.source[3] as u16);
        all_u16s.push((self.destination[0] as u16) << 8 | self.destination[1] as u16);
        all_u16s.push((self.destination[2] as u16) << 8 | self.destination[3] as u16);
        let mut result = all_u16s.iter().map(|it| *it as u32).sum::<u32>();
        while result & 0xffff0000 != 0 {
            result = ((result & 0xffff0000) >> 16) + result & 0xffff;
        }
        (!((result & 0xffff) as u16)) == self.header_checksum
    }
}

pub fn ipv4_header(input: &[u8]) -> IResult<&[u8], IPV4Header> {
    let bit_parser1 = bits::<_, (u8, u8, u8, u8, u16, u16), ((&[u8], usize), ErrorKind), _, _>(
        tuple((
            take(4usize),
            take(4usize),
            take(6usize),
            take(2usize),
            take(16usize),
            take(16usize),
        ))
    );
    let bit_parser2 = bits::<_, (u8, u8, u16), ((&[u8], usize), ErrorKind), _, _>(
        tuple((take(8usize),
               take(8usize),
               take(16usize))));
    map(tuple((
        bit_parser1,
        fragmentation,
        bit_parser2,
        take_bytes(4usize),
        take_bytes(4usize)
    )), |(
             (version, header_length, differentiated_services_codepoint, explicit_congestion_notification, total_length, identification),
             fragmentation,
             (time_to_live, protocol, header_checksum),
             source,
             destination
         )| {
        let version = u4::new(version);
        let header_length = u4::new(header_length);
        let differentiated_services_codepoint = u6::new(differentiated_services_codepoint);
        let explicit_congestion_notification = u2::new(explicit_congestion_notification);
        let protocol = TRANSPORT_LAYER_PROTOCOL.get(&protocol).unwrap().clone();
        IPV4Header {
            version,
            header_length,
            differentiated_services_codepoint,
            explicit_congestion_notification,
            total_length,
            identification,
            fragmentation,
            time_to_live,
            protocol,
            header_checksum,
            source: source.try_into().expect("Convert failed"),
            destination: destination.try_into().expect("Convert failed"),
        }
    })(input)
}

#[test]
fn ethernet_header_test() {
    let source: [u8; 40] = [0x45, 0x00, 0x00, 0x28,
        0x44, 0xfa, 0x40, 0x00,
        0x2a, 0x06, 0xbc, 0x78,
        0xb6, 0x3d, 0xc8, 0x0b,
        0xc0, 0xa8, 0x10, 0x6c,
        0x01, 0xbb, 0xf1, 0xbe, 0x37, 0x8c, 0x0c, 0x60, 0x5b, 0x57, 0xe9, 0xbf, 0x50, 0x11
        , 0x04, 0x6c, 0xdf, 0x8c, 0x00, 0x00];
    println!("{:?}", ipv4_header(&source));
}

#[test]
fn check_checksum_test() {
    let source: [u8; 40] = [0x45, 0x00, 0x00, 0x28,
        0x44, 0xfa, 0x40, 0x00,
        0x2a, 0x06, 0xbc, 0x78,
        0xb6, 0x3d, 0xc8, 0x0b,
        0xc0, 0xa8, 0x10, 0x6c, 0x01, 0xbb, 0xf1, 0xbe, 0x37, 0x8c, 0x0c, 0x60, 0x5b, 0x57, 0xe9, 0xbf, 0x50, 0x11
        , 0x04, 0x6c, 0xdf, 0x8c, 0x00, 0x00];
    let header = ipv4_header(&source).unwrap().1;
    assert!(header.valid());
    let source: [u8; 40] = [0x45, 0x00, 0x00, 0x28,
        0x49, 0xfa, 0x40, 0x01,
        0x2a, 0x06, 0xbc, 0x78,
        0xb6, 0x3d, 0xc8, 0x0b,
        0xc0, 0xa8, 0x10, 0x6c,
        0x01, 0xbb, 0xf1, 0xbe,
        0x37, 0x8c, 0x0c, 0x60,
        0x5b, 0x57, 0xe9, 0xbf,
        0x50, 0x11, 0x04, 0x6c,
        0xdf, 0x8c, 0x00, 0x00];
    let header = ipv4_header(&source).unwrap().1;
    assert!(!header.valid());
    println!("{:?}", serde_json::to_string(&header).unwrap());
}