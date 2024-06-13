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

use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, put},
    Json, Router,
};
use serde_json;
use std::io::Result;
use tracing::debug;

async fn root_handler() -> Html<&'static str> {
    debug!("Building hello world response");
    Html("<h1>Hello, World!</h1>")
}

async fn uri_restconf_root() -> impl IntoResponse {
    debug!("Building resetconf root response");
    let s = format!("<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><Link rel='restconf' href='{}'/></XRD>", &RESTCONF_ROOT);
    ([(header::CONTENT_TYPE, "application/xrd+xml")], s)
}

async fn restconf_root_handler() -> impl IntoResponse {
    let json_output = r#"{"message": "Hello, World!"}"#;
    let json_value: serde_json::Value = serde_json::from_str(json_output).unwrap();

    (StatusCode::OK, axum::Json(json_value))
}

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
struct UpdateItem {
    id: u32,
    name: String,
    value: i32,
}

async fn update_item_handler(payload: String) -> impl IntoResponse {
    println!("Received update request: {:?}", payload);

    // Here you would typically update the item in your database
    // For this example, we'll just return the received payload

    match serde_json::from_str::<serde_json::Value>(&payload) {
        Ok(json_object) => (StatusCode::OK, Json(json_object)),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::from_str(r#"{}"#).unwrap()),
        ),
    }
}

///
/// Run to completion serving HTTP (RESTCONF) requests.
///
pub async fn run_restconf_server() -> Result<()> {
    /*
     * Create the axum web app using Router
     */
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/.well-known/host-meta", get(uri_restconf_root))
        .route("/update", put(update_item_handler))
        .route(RESTCONF_ROOT, get(restconf_root_handler));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    /*
     * run the app (async executor loop)
     */
    debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await
}
