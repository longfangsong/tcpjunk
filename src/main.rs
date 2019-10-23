#[macro_use]
extern crate lazy_static;

use actix_web::{App, HttpServer, web};
use serde::{Deserialize, Serialize};

use crate::parser::ethernet_header::{ethernet_header, EthernetHeader};
use crate::parser::ipv4_header::ipv4_header;
use crate::parser::ipv4_header::IPV4Header;

mod parser;

#[derive(Deserialize, Debug)]
struct PackageData {
    data: Vec<u8>,
}

#[derive(Serialize)]
struct Resp<'a> {
    ethernet_header: Option<EthernetHeader>,
    ip_header: Option<IPV4Header>,
    rest: &'a [u8],
}

fn index(data: web::Json<PackageData>) -> String {
    let result = ethernet_header(&data.data[..]);
    let (rest, eth_header) = if result.is_ok() {
        let (r, eh) = result.unwrap();
        (r, Some(eh))
    } else {
        (&data.data[..], None)
    };
    if eth_header.is_some() {
        let result = ipv4_header(rest);
        let (rest, ip_header) = if result.is_ok() {
            let (r, ipv4_header) = result.unwrap();
            (r, Some(ipv4_header))
        } else {
            (&data.data[..], None)
        };
        let response = Resp {
            ethernet_header: eth_header,
            ip_header,
            rest,
        };
        serde_json::to_string(&response).unwrap()
    } else {
        let response = Resp {
            ethernet_header: None,
            ip_header: None,
            rest,
        };
        serde_json::to_string(&response).unwrap()
    }
}

fn main() {
    HttpServer::new(|| { App::new().service(web::resource("/").to(index)) })
        .bind("0.0.0.0:8080")
        .unwrap()
        .run()
        .unwrap();
}