#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// extern crate libc;

// use libc::c_char;
// use libc::c_int;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::mem;

mod second;
use crate::second::foo;

// struct thread_master *master;
// static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_SYS_ADMIN, ZCAP_NET_RAW};

// extern "C" {
//     static bfdd_di: frr_daemon_info;
// }
// static rustbin_di: frr_daemon_info = {
// 	flags = 0,

// 	const char *progname;
// 	const char *name = "rustbind";
// 	const char *logname = "rustbin";
// 	unsigned short instance;
// 	struct frrmod_runtime *module;

// 	char *vty_addr;
// 	int vty_port;
// 	char *vty_sock_path;
// 	bool dryrun;
// 	bool daemon_mode;
// 	bool terminal;
// 	enum frr_cli_mode cli_mode;

// 	struct thread *read_in;
// 	const char *config_file;
// 	const char *backup_config_file;
// 	const char *pid_file;
// // #ifdef HAVE_SQLITE3
// // 	const char *db_file;
// // #endif
// 	const char *vty_path;
// 	const char *module_path;
// 	const char *script_path;

// 	const char *pathspace;
// 	bool zpathspace;

// 	struct log_args_head early_logging[1];
// 	const char *early_loglevel;

// 	const char *proghelp;
// 	void (*printhelp)(FILE *target);
// 	const char *copyright;
// 	char startinfo[128];

// 	struct frr_signal_t *signals;
// 	size_t n_signals;

// 	struct zebra_privs_t *privs;

// 	const struct frr_yang_module_info *const *yang_modules;
// 	size_t n_yang_modules;

// 	bool log_always;

// 	/* Optional upper limit on the number of fds used in select/poll */
// 	uint32_t limit_fds;
// };

fn main() {
    // create a vector of zero terminated strings
    let args = std::env::args()
        .map(|arg| CString::new(arg).unwrap())
        .collect::<Vec<CString>>();

    // convert the strings to raw pointers
    let c_args = args
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const c_char>>();

    let mut di: frr_daemon_info = unsafe { mem::zeroed() };
    di.name = "rustbind".as_ptr() as *const i8;
    di.logname = "rustbin".as_ptr() as *const i8;
    unsafe { frr_preinit(&mut di, c_args.len() as i32, c_args.as_ptr() as *mut *mut i8) }
    let slice = unsafe { CStr::from_ptr(di.progname) };
    foo();
    println!("daemon name is {}", slice.to_str().unwrap());
}

