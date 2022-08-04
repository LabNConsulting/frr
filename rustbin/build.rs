extern crate bindgen;
// extern crate gcc;

use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use std::sync::{Arc, RwLock};

use std::collections::HashSet;

//
// This complexity is need to ignore a #define in netdb.h that is shadowing an
// anonymous enum in netinet/in.h
//
#[derive(Debug)]
struct MacroCallback {
    macros: Arc<RwLock<HashSet<String>>>,
}

impl ParseCallbacks for MacroCallback {
    fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
        self.macros.write().unwrap().insert(name.into());

        if name == "IPPORT_RESERVED" {
            return MacroParsingBehavior::Ignore;
        }

        MacroParsingBehavior::Default
    }
}

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=../build/lib/.libs/libfrr.so");

    // Tell cargo to tell rustc to link libfrr shared library.
    println!("cargo:rustc-link-lib=frr");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let macros = Arc::new(RwLock::new(HashSet::new()));

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_args(&[
            "-F/home/chopps/w/frrpub/build",
            "-F/home/chopps/w/frrpub",
            "-I/home/chopps/w/frrpub/lib",
        ])
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(MacroCallback {
            macros: macros.clone(),
        }))
        // Finish the builder and generate the bindings.
        .blocklist_type("IPPORT_.*")
        .blocklist_type("IPPORT_RESERVED")
        // avoid creating bindings for things with u128 which doesn't yet have a
        // stable FFI, for now.
        .blocklist_function("lyd_eval_xpath4")
        .blocklist_function("q[efg]cvt.*")
        .blocklist_function("strto.*")
        .blocklist_function("strfrom.*")
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
