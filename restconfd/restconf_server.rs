// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 13 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//
///
/// Functionality implementing the RESTCONF HTTP server.
///

const RESTCONF_ROOT: &str = "/restconf";
// const YANG_ROOT: &str = "/yang";

use crate::mgmtd::MgmtdSession;
use crate::native;
use crate::native::MgmtMsg;
use http::StatusCode;
use rouille::{Request, Response};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::ErrorKind;
use std::result::Result;
use tracing::debug;

//
// HTTP handlers
//

fn root_handler(_client: &MgmtdSession, _req: &Request) -> Response {
    debug!("Building hello world response");
    Response::html("<h1>Hello, World!</h1>")
}

fn uri_restconf_root(_client: &MgmtdSession, _req: &Request) -> Response {
    debug!("Building resetconf root response");
    let s = format!("<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><Link rel='restconf' href='{}'/></XRD>", &RESTCONF_ROOT);

    Response::from_data("application/xrd+xml", s)
}

fn restconf_root_handler(client: &mut MgmtdSession, req: &Request) -> Response {
    fn handler(client: &mut MgmtdSession, req: &Request) -> Result<Response, Box<dyn Error>> {
        let url = req.url();
        let uri = crate::uri::Uri::parse(&url)?;

        let yang_path = url.strip_prefix("/restconf").unwrap();
        // let yang_path = uri.segs[1..].join("/");

        debug!("XXX URI: {:?}", uri);

        let msg = native::MgmtMsgGetData::with_values(
            client.sess_id,
            client.next_req_id(),
            native::MGMT_MSG_FORMAT_JSON,
            native::GET_DATA_FLAG_STATE | native::GET_DATA_FLAG_CONFIG,
            native::GET_DATA_DEFAULTS_EXPLICIT,
            native::MGMT_MSG_DATASTORE_OPERATIONAL,
            yang_path,
        );
        let v = msg.encode()?;

        debug!("RESTCONF GET PATH: {}", yang_path);

        native::send_msg(&mut client.stream, &v)?;

        //
        // Wait for the reply
        //
        match native::recv_msg(&mut client.stream)? {
            MgmtMsg::TreeData(data_msg) => {
                Ok(Response::from_data("application/json", data_msg.result))
            }
            MgmtMsg::Error(emsg) => Err(Box::new(native::msg_to_error(&emsg)) as Box<dyn Error>),
            _ => Err(Box::new(std::io::Error::new(
                ErrorKind::Unsupported,
                "non-session-reply msg received",
            )) as Box<dyn Error>),
        }
    }
    match handler(client, req) {
        Ok(x) => x,
        Err(x) => Response::text(format!("Failed to process request: {}", x))
            .with_status_code(StatusCode::BAD_REQUEST.as_u16()),
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct UpdateItem {
    id: u32,
    name: String,
    value: i32,
}

fn update_item_handler(_client: &MgmtdSession, req: &Request) -> Response {
    debug!("Received update request: {:?}", req);

    // Here you would typically update the item in your database
    // For this example, we'll just return the received payload

    match rouille::input::json_input::<UpdateItem>(req) {
        Ok(json_object) => Response::json(&json_object),
        Err(e) => Response::text(format!("Failed to parse JSON: {}", e))
            .with_status_code(StatusCode::BAD_REQUEST.as_u16()),
    }
}

///
/// Run to completion serving HTTP (RESTCONF) requests.
///
pub fn run_restconf_server() {
    println!("Now listening on port 3000");

    rouille::start_server("0.0.0.0:3000", move |request| {
        let method = request.method();
        let url = request.url();
        let mut client = MgmtdSession::new().unwrap();

        debug!("Got new mgmtd client data {:?}", client);

        debug!("Got request URL: {}", url);

        match (method, &url as &str) {
            ("GET", "/") => root_handler(&client, request),
            ("GET", "/.well-known/host-meta") => uri_restconf_root(&client, request),
            ("GET", _) => {
                if url.starts_with("/restconf/") {
                    restconf_root_handler(&mut client, request)
                } else {
                    Response::empty_404()
                }
            }
            ("PUT", "/update") => update_item_handler(&client, request),
            _ => Response::empty_404(),
        }
    });
}
