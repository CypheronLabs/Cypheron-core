use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let kyber_ref_dir = manifest_dir.join("..").join("vendor").join("kyber").join("ref");

    build_kyber("512", "2", &kyber_ref_dir);
    build_kyber("768", "3", &kyber_ref_dir);
    build_kyber("1024", "4", &kyber_ref_dir);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", kyber_ref_dir.display());
}

fn build_kyber(variant: &str, k_val: &str, ref_dir: &Path) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_name = format!("kyber_{}", variant);
    let out_bindings = out_dir.join(format!("kyber{}_bindings.rs", variant));

    cc::Build::new()
        .files([
            "indcpa.c", "kem.c", "ntt.c", "poly.c", "polyvec.c", "reduce.c",
            "verify.c", "symmetric-shake.c", "randombytes.c", "fips202.c", "cbd.c"
        ].iter().map(|f| ref_dir.join(f)))
        .include(ref_dir)
        .define("KYBER_K", Some(k_val))
        .flag_if_supported("-O3")
        .compile(&lib_name);

    println!("cargo:rustc-link-lib=static={}", lib_name);
    println!("cargo:rustc-link-search=native={}", out_dir.display());

    bindgen::Builder::default()
        .header(ref_dir.join("api.h").to_str().unwrap())
        .clang_arg(format!("-I{}", ref_dir.display()))
        .allowlist_function(&format!("pqcrystals_kyber{}_ref_keypair", variant))
        .allowlist_function(&format!("pqcrystals_kyber{}_ref_enc", variant))
        .allowlist_function(&format!("pqcrystals_kyber{}_ref_dec", variant))
        .generate()
        .expect(&format!("Unable to generate Kyber{} bindings", variant))
        .write_to_file(&out_bindings)
        .expect(&format!("Couldn't write Kyber{} bindings", variant));
}
