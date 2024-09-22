// SPDX-License-Identifier: GPL-2.0-or-later
//
// September 22 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (c) 2024, LabN Consulting, L.L.C.
//
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[no_mangle]
pub extern "C" fn _rust_preinit(daemon: *const frr_daemon_info) {
    crate::rust_preinit(unsafe {&*daemon});
}

#[no_mangle]
pub extern "C" fn _rust_init(master: *mut event_loop) {
    crate::rust_init(master);
}

#[no_mangle]
pub extern "C" fn _rust_prerun(master: *mut event_loop) {
    crate::rust_prerun(master);
}
