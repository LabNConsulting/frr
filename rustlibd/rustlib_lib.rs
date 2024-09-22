// SPDX-License-Identifier: GPL-2.0-or-later
//
// September 9 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

pub mod c_shim;

use tracing::debug;

///
/// Setup the trace logging.
///
fn setup_logging() {
    /*
     * Enable some logging
     */
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

///
/// Immediately after frr_preinit(&rustd_id, argv, argc) called.
///
pub fn rust_preinit(daemon: &c_shim::frr_daemon_info) {
    let _progname = unsafe {std::ffi::CStr::from_ptr(daemon.progname)};
    let progname = _progname.to_str().unwrap();

    setup_logging();
    debug!("rust_preinit: {}", progname)
}

///
/// Immediately after master = frr_init() called.
///
pub fn rust_init(master: *mut c_shim::event_loop) {
    debug!("rust_init: master: {:?}", master);
}

///
/// After frr_config_fork() immediately before frr_run() loop entered.
///
pub fn rust_prerun(master: *mut c_shim::event_loop) {
    debug!("rust_prerun: master: {:?}", master);
}
