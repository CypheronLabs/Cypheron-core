use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    build_kyber_all(&manifest_dir);
    build_dilithium_all(&manifest_dir);
    build_falcon_all(&manifest_dir);
    build_sphincsplus_all(&manifest_dir);

    println!("cargo:rerun-if-changed=build.rs");
}

fn build_kyber_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("..").join("vendor/kyber/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    for (variant, k_val) in &[("512", "2"), ("768", "3"), ("1024", "4")] {
        PQBuilder::new(format!("kyber{}", variant), &ref_dir)
            .files(vec![
                "indcpa.c",
                "kem.c",
                "ntt.c",
                "poly.c",
                "polyvec.c",
                "reduce.c",
                "verify.c",
                "symmetric-shake.c",
                "randombytes.c",
                "fips202.c",
                "cbd.c",
            ])
            .defines(vec![("KYBER_K", k_val)])
            .header("api.h")
            .allowlist(vec![
                format!("pqcrystals_kyber{}_ref_keypair", variant),
                format!("pqcrystals_kyber{}_ref_enc", variant),
                format!("pqcrystals_kyber{}_ref_dec", variant),
            ])
            .build();
    }
}

fn build_dilithium_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("..").join("vendor/dilithium/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    for level in &["2", "3", "5"] {
        PQBuilder::new(format!("dilithium_{}", level), &ref_dir)
            .files(vec![
                "sign.c",
                "polyvec.c",
                "poly.c",
                "packing.c",
                "ntt.c",
                "reduce.c",
                "rounding.c",
                "symmetric-shake.c",
                "fips202.c",
                "randombytes.c",
            ])
            .defines(vec![("DILITHIUM_MODE", level)])
            .header("api.h")
            .allowlist(vec![
                format!("pqcrystals_dilithium{}_ref_keypair", level),
                format!("pqcrystals_dilithium{}_ref_signature", level),
                format!("pqcrystals_dilithium{}_ref_verify", level),
            ])
            .build();
    }
}

fn build_falcon_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("..").join("vendor/falcon");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    PQBuilder::new("falcon".into(), &ref_dir)
        .files(vec![
            "codec.c",
            "common.c",
            "deterministic.c",
            "falcon.c",
            "fft.c",
            "fpr.c",
            "keygen.c",
            "rng.c",
            "shake.c",
            "sign.c",
            "vrfy.c",
        ])
        .header("falcon.h")
        .allowlist(vec![
            "falcon_keygen_make".into(),
            "falcon_sign_dyn".into(),
            "falcon_sign_tree".into(),
            "falcon_sign_dyn_finish".into(),
            "falcon_sign_tree_finish".into(),
            "falcon_expand_privkey".into(),
            "falcon_verify".into(),
            "falcon_verify_start".into(),
            "falcon_verify_finish".into(),
            "shake256_init".into(),
            "shake256_inject".into(),
            "shake256_flip".into(),
            "shake256_extract".into(),
            "shake256_init_prng_from_seed".into(),
            "shake256_init_prng_from_system".into(),
            "FALCON_SIG_COMPRESSED".into(),
            "FALCON_SIG_PADDED".into(),
            "FALCON_SIG_CT".into(),
        ])
        .build();
}

fn build_sphincsplus_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("..").join("vendor/sphincsplus/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    let params_set = "sphincs-shake-128f";

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let generated_params_dir = out_dir.join("sphincsplus_params");

    let original_template = ref_dir.join("params").join(format!("params-{}.h", params_set));
    let patched_template = generated_params_dir.join(format!("params-{}.h", params_set));
    let patched_params_h = generated_params_dir.join("params.h");
    let shake_offsets_src = ref_dir.join("shake_offsets.h");
    let shake_offsets_dst = generated_params_dir.join("shake_offsets.h");

    std::fs::create_dir_all(&generated_params_dir)
        .expect("[build.rs] Failed to create sphincsplus_params directory");

    let include_line = format!("#include \"params-{}.h\"\n", params_set);
    std::fs::write(&patched_params_h, include_line)
        .expect("[build.rs] Failed to write patched params.h for SPHINCS+");

    if !patched_template.exists() {
        let contents = std::fs::read_to_string(&original_template)
            .expect("Failed to read original params header");
        let patched_contents =
            contents.replace(r#"#include "../shake_offsets.h""#, r#"#include "shake_offsets.h""#);
        std::fs::write(&patched_template, patched_contents)
            .expect("Failed to write patched params header");
    }

    std::fs::copy(&shake_offsets_src, &shake_offsets_dst)
        .expect("Failed to copy shake_offsets.h");

    PQBuilder::new(
        format!("sphincsplus_{}", params_set.replace('-', "_")),
        &ref_dir,
    )
    .files(vec![
        "address.c",
        "fors.c",
        "hash_shake.c",
        "merkle.c",
        "sign.c",
        "thash_shake_robust.c",
        "thash_shake_simple.c",
        "utils.c",
        "wots.c",
        "wotsx1.c",
        "randombytes.c",
        "fips202.c",
    ])
    .defines(vec![("PARAMS", "sphincs-shake-128f")])
    .header(patched_params_h.to_str().unwrap()) // redirect header
    .allowlist(vec![
        "crypto_sign_keypair".into(),
        "crypto_sign_seed_keypair".into(),
        "crypto_sign_signature".into(),
        "crypto_sign_verify".into(),
        "crypto_sign".into(),
        "crypto_sign_open".into(),
        "crypto_sign_secretkeybytes".into(),
        "crypto_sign_publickeybytes".into(),
        "crypto_sign_bytes".into(),
        "crypto_sign_seedbytes".into(),
        "CRYPTO_ALGNAME".into(),
        "CRYPTO_SECRETKEYBYTES".into(),
        "CRYPTO_PUBLICKEYBYTES".into(),
        "CRYPTO_BYTES".into(),
        "CRYPTO_SEEDBYTES".into(),
    ])
    .build();
}

// Generic Build Pattern for building the FFI bindings
struct PQBuilder<'a> {
    lib_name: String,
    src_dir: &'a Path,
    c_files: Vec<&'a str>,
    defines: Vec<(&'a str, &'a str)>,
    header: Option<String>,
    allowlist_functions: Vec<String>,
}

impl<'a> PQBuilder<'a> {
    fn new(lib_name: String, src_dir: &'a Path) -> Self {
        Self {
            lib_name,
            src_dir,
            c_files: vec![],
            defines: vec![],
            header: None,
            allowlist_functions: vec![],
        }
    }

    fn files(mut self, files: Vec<&'a str>) -> Self {
        self.c_files = files;
        self
    }

    fn defines(mut self, defs: Vec<(&'a str, &'a str)>) -> Self {
        self.defines = defs;
        self
    }

    fn header(mut self, header: &'a str) -> Self {
        self.header = Some(header.to_string());
        self
    }

    fn allowlist(mut self, funcs: Vec<String>) -> Self {
        self.allowlist_functions = funcs;
        self
    }

    fn build(self) {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let out_bindings = out_dir.join(format!("{}_bindings.rs", self.lib_name));

        // Compile C code
        let mut build = cc::Build::new();
        build.include(self.src_dir);
        build.files(self.c_files.iter().map(|f| self.src_dir.join(f)));
        build.flag_if_supported("-O3");
        for (k, v) in &self.defines {
            build.define(k, Some(*v));
        }
        build.compile(&self.lib_name);

        println!("cargo:rustc-link-lib=static={}", self.lib_name);
        println!("cargo:rustc-link-search=native={}", out_dir.display());

        let Some(header_file) = self.header else {
            eprintln!("[build.rs] No header file specified for {}", self.lib_name);
            std::process::exit(1);
        };

        let mut builder = bindgen::Builder::default()
            .header(self.src_dir.join(header_file).to_str().unwrap())
            .clang_arg(format!("-I{}", self.src_dir.display()));

        for func in &self.allowlist_functions {
            builder = builder.allowlist_function(func);
        }

        let bindings = builder.generate();
        match bindings {
            Ok(bindings) => {
                bindings
                    .write_to_file(&out_bindings)
                    .unwrap_or_else(|_| panic!("Couldn't write bindings for {}", self.lib_name));
            }
            Err(e) => {
                eprintln!(
                    "\n[build.rs] Failed to generate bindings for {}: {}",
                    self.lib_name, e
                );
                eprintln!("Make sure libclang is installed and visible.");
                eprintln!("Try: `sudo apt install libclang-dev`");
                eprintln!("Or set the environment variable: `LIBCLANG_PATH=/path/to/libclang.so`");
                std::process::exit(1);
            }
        }
    }
}
