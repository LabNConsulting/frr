// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 8 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

#[macro_use]
extern crate rouille;

use tracing::debug;

#[path = "restconf_cbor.rs"]
pub mod cbor;
#[path = "restconf_cstruct.rs"]
pub mod cstruct;
#[path = "restconf_mgmtd.rs"]
pub mod mgmtd;
#[path = "restconf_msg.rs"]
pub mod msg;
#[path = "restconf_native.rs"]
pub mod native;
#[path = "restconf_server.rs"]
pub mod restconf;

/**
 * Perform some simple tests to demonstrate usage of various rust crates and
 * features.
 */
fn simple_test() {
    cbor::test_cbor();
    cstruct::test_cstruct();
}

/**
 * Setup the trace logging.
 */
fn setup_logging() {
    /*
     * Enable some logging
     */
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn main() {
    setup_logging();

    simple_test();

    let client = mgmtd::MgmtdSession::new();

    debug!("Got new mgmtd client data {:?}", client);

    restconf::run_restconf_server();

    debug!("At the end here's the client: {:?}", client);
}
