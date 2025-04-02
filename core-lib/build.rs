use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=static=kyber_ref");
    println!("cargo:rustc-link-search=native=core-lib/native/ref");

    let bindings = bindgen::Builder::default()
        .header("native/ref/include/api.h") 
        .clang_arg("-Inative/ref/include")  
        .allowlist_function("pqcrystals_kyber768_ref_.*")
        .generate()
        .expect("Unable to generate Kyber768 bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("kyber768_bindings.rs"))
        .expect("Couldn't write bindings!");
}