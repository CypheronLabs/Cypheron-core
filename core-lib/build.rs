use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    build_kyber_all(&manifest_dir);
    build_dilithium_all(&manifest_dir);
    // build_falcon_all(&manifest_dir);
    // build_sphincs_all(&manifest_dir);

    println!("cargo:rerun-if-changed=build.rs");
}

fn build_kyber_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir
        .join("..")
        .join("vendor/kyber/ref");
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
    let ref_dir = manifest_dir
        .join("..")
        .join("vendor/dilithium/ref");
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
                format!("pqcrystals_dilithium{}_ref_sign", level),
                format!("pqcrystals_dilithium{}_ref_verify", level),
            ])
            .build();
    }
}

// TODO Falcon, Sphincs+

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
                eprintln!("\n[build.rs] Failed to generate bindings for {}: {}", self.lib_name, e);
                eprintln!("Make sure libclang is installed and visible.");
                eprintln!("Try: `sudo apt install libclang-dev`");
                eprintln!("Or set the environment variable: `LIBCLANG_PATH=/path/to/libclang.so`");
                std::process::exit(1);
            }
        }
    }
}
