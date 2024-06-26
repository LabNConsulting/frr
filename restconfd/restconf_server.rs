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

use rouille::{Request, Response};
use tracing::debug;

//
// Handlers
//

fn root_handler(_req: &Request) -> Response {
    debug!("Building hello world response");
    Response::html("<h1>Hello, World!</h1>")
}

fn uri_restconf_root(_req: &Request) -> Response {
    debug!("Building resetconf root response");
    let s = format!("<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><Link rel='restconf' href='{}'/></XRD>", &RESTCONF_ROOT);

    Response::from_data("application/xrd+xml", s)
}

fn restconf_root_handler(_req: &Request) -> Response {
    let json_output = r#"{"message": "Hello, World!"}"#;
    // let json_value: serde_json::Value = serde_json::from_str(json_output).unwrap();

    Response::from_data("application/json", json_output).with_status_code(200)
}

// #[derive(Deserialize, Serialize, Debug)]
// struct UpdateItem {
//     id: u32,
//     name: String,
//     value: i32,
// }

// fn update_item_handler(payload: String) -> impl IntoResponse {
//     println!("Received update request: {:?}", payload);

//     // Here you would typically update the item in your database
//     // For this example, we'll just return the received payload

//     match serde_json::from_str::<serde_json::Value>(&payload) {
//         Ok(json_object) => (StatusCode::OK, Json(json_object)),
//         Err(_) => (
//             StatusCode::BAD_REQUEST,
//             Json(serde_json::from_str(r#"{}"#).unwrap()),
//         ),
//     }
// }

///
/// Run to completion serving HTTP (RESTCONF) requests.
///

pub fn run_restconf_server() {
    println!("Now listening on port 8000");

    rouille::start_server("0.0.0.0:3000", move |request| {
        router!(request,
                (GET) ["/"] => {
                    root_handler(request)
                },
                (GET) ["/.well-known/host-meta"] => {
                    uri_restconf_root(request)
                },
                // (PUT) (/update) => {
                //     uri_restconf_root(request)
                // },
                (GET) [RESTCONF_ROOT] => {
                    restconf_root_handler(request)
                },
                _ => Response::empty_404()
        )
    });
}
