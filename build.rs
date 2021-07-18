extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=c");
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .raw_line("use libc::passwd;")
        .raw_line("type quad_t = i64;")
        .allowlist_function("login_.*")
        .allowlist_function("secure_path")
        .allowlist_function("setclasscontext")
        .allowlist_function("setusercontext")
        .allowlist_type("login_cap_t")
        .allowlist_var("AUTH_.*")
        .allowlist_var("BI_.*")
        .allowlist_var("LOGIN_.*")
        .blocklist_type("passwd")
        .blocklist_type("quad_t")
        .generate()
        .expect("Unable to generate login_cap bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings for login_cap!");
}

