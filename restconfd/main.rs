// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 8 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

pub mod cbor;
pub mod cstruct;

fn first_main() {
    cbor::test_cbor();
    cstruct::test_cstruct();
}

use axum::{response::Html, routing::get, Router};
use tracing::{debug, Level};

const RESTCONF_ROOT: &str = "/restconf/";
const YANG_ROOT: &str = "/yang/";

#[tokio::main]
async fn main() {
    first_main();

    /*
     * Enable some logging
     */
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    /*
     * Create the axum web app using Router
     */
    let app = Router::new().route("/", get(handler));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    /*
     * run the app (async executor loop)
     */
    debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> Html<&'static str> {
    debug!("Building hello world response");
    Html("<h1>Hello, World!</h1>")
}
