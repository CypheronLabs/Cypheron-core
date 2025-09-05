// Copyright 2025 Cypheron Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "windows")]
const _OS_SUFFIX: &str = "windows";
#[cfg(target_os = "macos")]
const _OS_SUFFIX: &str = "macos";
#[cfg(target_os = "linux")]
const _OS_SUFFIX: &str = "linux";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sphincs_dir = manifest_dir.join("vendor/sphincsplus");

    println!("cargo:warning=Starting Cypheron-core cryptographic library build");
    println!("cargo:warning=Target architecture: {}", env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default());
    println!("cargo:warning=Target OS: {}", env::var("CARGO_CFG_TARGET_OS").unwrap_or_default());

    verify_vendor_integrity(&manifest_dir);

    println!("cargo:warning=Building ML-KEM (Kyber) variants...");
    build_kyber_all(&manifest_dir);
    
    println!("cargo:warning=Building ML-DSA (Dilithium) variants...");
    build_dilithium_all(&manifest_dir);
    
    println!("cargo:warning=Building Falcon variants...");
    build_falcon_all(&manifest_dir);
    
    println!("cargo:warning=Building SPHINCS+ reference variants...");
    build_sphincsplus_all(&sphincs_dir);
    
    if is_x86_architecture() {
        println!("cargo:warning=Target supports x86/x86_64 intrinsics - building SPHINCS+ Haraka-AESNI variants");
        let api_functions = vec![
            "crypto_sign_keypair".to_string(),
            "crypto_sign_seed_keypair".to_string(),
            "crypto_sign".to_string(),
            "crypto_sign_open".to_string(),
            "crypto_sign_signature".to_string(),
            "crypto_sign_verify".to_string(),
            "crypto_sign_bytes".to_string(),
            "crypto_sign_publickeybytes".to_string(),
            "crypto_sign_secretkeybytes".to_string(),
            "crypto_sign_seedbytes".to_string(),
        ];
        build_aesni_variants(&sphincs_dir, &api_functions);
    } else {
        println!("cargo:warning=Target architecture '{}' does not support x86/x86_64 intrinsics", 
                 env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default());
        println!("cargo:warning=Skipping SPHINCS+ Haraka-AESNI variants - using reference implementation only");
        println!("cargo:warning=This is normal and expected on ARM64, RISC-V, and other non-x86 architectures");
    }

    println!("cargo:warning=Cypheron-core build completed successfully");
    println!("cargo:rerun-if-changed=build.rs");
}

fn is_x86_architecture() -> bool {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    matches!(target_arch.as_str(), "x86" | "x86_64")
}

fn verify_vendor_integrity(manifest_dir: &Path) {
    if env::var("SKIP_VENDOR_INTEGRITY").is_ok() {
        println!("cargo:warning=Skipping vendor integrity verification");
        return;
    }

    let vendor_script = manifest_dir
        .parent()
        .unwrap()
        .join("scripts/vendor-integrity.sh");

    if !vendor_script.exists() {
        println!("cargo:warning=Vendor integrity script not found, skipping verification");
        return;
    }

    println!("cargo:warning=Verifying vendor code integrity...");

    let output = Command::new("bash")
        .arg(&vendor_script)
        .arg("verify")
        .current_dir(manifest_dir.parent().unwrap())
        .output();

    match output {
        Ok(result) => {
            if !result.status.success() {
                eprintln!("Vendor integrity verification failed!");
                eprintln!("STDOUT: {}", String::from_utf8_lossy(&result.stdout));
                eprintln!("STDERR: {}", String::from_utf8_lossy(&result.stderr));
                eprintln!("Set SKIP_VENDOR_INTEGRITY=1 to skip this check (not recommended)");
                std::process::exit(1);
            } else {
                println!("cargo:warning=Vendor integrity verification passed");
            }
        }
        Err(e) => {
            eprintln!("Failed to run vendor integrity verification: {}", e);
            eprintln!("Set SKIP_VENDOR_INTEGRITY=1 to skip this check (not recommended)");
            std::process::exit(1);
        }
    }
}

fn build_kyber_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("vendor/kyber/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    let required_files = [
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
    ];
    for file in &required_files {
        assert!(
            ref_dir.join(file).exists(),
            "[build.rs] Missing ML-KEM (Kyber) file: {}",
            file
        );
    }
    for (variant, k_val) in &[("512", "2"), ("768", "3"), ("1024", "4")] {
        PQBuilder::new(format!("ml_kem_{}", variant), &ref_dir)
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
    let ref_dir = manifest_dir.join("vendor/dilithium/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    let required_files = [
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
    ];
    for file in &required_files {
        assert!(
            ref_dir.join(file).exists(),
            "[build.rs] Missing ML-DSA (Dilithium) file: {}",
            file
        );
    }

    for level in &["2", "3", "5"] {
        PQBuilder::new(format!("ml_dsa_{}", level), &ref_dir)
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
    let ref_dir = manifest_dir.join("vendor/falcon");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

    let required_files = [
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
    ];
    for file in &required_files {
        assert!(
            ref_dir.join(file).exists(),
            "[build.rs] Missing Falcon file: {}",
            file
        );
    }

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
            "falcon_verify".into(),
            "FALCON_TMPSIZE_KEYGEN".into(),
            "FALCON_TMPSIZE_SIGNDYN".into(),
            "FALCON_TMPSIZE_VERIFY".into(),
            "shake256_init_prng_from_seed".into(),
            "shake256_init_prng_from_system".into(),
            "FALCON_SIG_COMPRESSED".into(),
            "FALCON_SIG_PADDED".into(),
            "FALCON_SIG_CT".into(),
        ])
        .build();
}

fn build_sphincsplus_all(sphincs_dir: &Path) {
    let ref_dir = sphincs_dir.join("ref");

    let hash_functions = ["sha2", "shake", "haraka"];
    let security_levels = ["128", "192", "256"];
    let optimizations = ["f", "s"];
    let thash_variants = ["simple", "robust"];

    let api_functions = vec![
        "crypto_sign_keypair".to_string(),
        "crypto_sign_seed_keypair".to_string(),
        "crypto_sign".to_string(),
        "crypto_sign_open".to_string(),
        "crypto_sign_signature".to_string(),
        "crypto_sign_verify".to_string(),
        "crypto_sign_bytes".to_string(),
        "crypto_sign_publickeybytes".to_string(),
        "crypto_sign_secretkeybytes".to_string(),
        "crypto_sign_seedbytes".to_string(),
    ];
    for &hash in &hash_functions {
        for &security in &security_levels {
            for &opt in &optimizations {
                for &thash in &thash_variants {
                    let lib_name =
                        format!("sphincsplus_sphincs_{}_{}{}_{}", hash, security, opt, thash);

                    let mut owned_files: Vec<String> = vec![];
                    let mut c_files: Vec<&str> = vec![
                        "address.c",
                        "fors.c",
                        "merkle.c",
                        "sign.c",
                        "utils.c",
                        "utilsx1.c",
                        "wots.c",
                        "wotsx1.c",
                        "randombytes.c",
                    ];

                    match hash {
                        "sha2" => {
                            owned_files.push(format!("thash_sha2_{}.c", thash));
                            c_files.push("sha2.c");
                            c_files.push("hash_sha2.c");
                            c_files.push(owned_files.last().unwrap());
                        }
                        "shake" => {
                            owned_files.push(format!("thash_shake_{}.c", thash));
                            c_files.push("fips202.c");
                            c_files.push("hash_shake.c");
                            c_files.push(owned_files.last().unwrap());
                        }
                        "haraka" => {
                            owned_files.push(format!("thash_haraka_{}.c", thash));
                            c_files.push("haraka.c");
                            c_files.push("hash_haraka.c");
                            c_files.push(owned_files.last().unwrap());
                        }
                        _ => panic!("Unsupported hash function"),
                    }

                    let thash_str = thash.to_string();

                    let param_file = format!("sphincs-{}-{}{}", hash, security, opt);

                    let param_file_path = ref_dir
                        .join("params")
                        .join(format!("params-{}.h", param_file));
                    if !param_file_path.exists() {
                        eprintln!(
                            "[build.rs] Missing SPHINCS+ parameter file: {}",
                            param_file_path.display()
                        );
                        std::process::exit(1);
                    }

                    let defines = vec![
                        ("PARAMS", param_file.as_str()),
                        ("THASH", thash_str.as_str()),
                    ];

                    PQBuilder::new(lib_name, &ref_dir)
                        .files(c_files)
                        .defines(defines)
                        .header("api.h")
                        .allowlist(api_functions.to_vec())
                        .build();
                }
            }
        }
    }
    println!("cargo:warning=SPHINCS+ optimized variants disabled for v0.1.0 - using reference implementation only");
    println!("cargo:warning=AVX2/AESNI variants will be available in future releases after proper testing");

    println!("cargo:rerun-if-changed={}", sphincs_dir.display());
}

/* Disabled for v0.1.0 - will be re-enabled in future releases with proper file handling
fn build_avx2_variants(sphincs_dir: &Path, api_functions: &[String]) {
    let hash_functions = ["sha2", "shake"];
    let security_levels = ["128", "192", "256"];
    let optimizations = ["f", "s"];
    let thash_variants = ["simple", "robust"];

    for &hash in &hash_functions {
        let avx2_dir = sphincs_dir.join(format!("{}-avx2", hash));

        for &security in &security_levels {
            for &opt in &optimizations {
                for &thash in &thash_variants {
                    let param_set = format!("sphincs-{}-{}{}", hash, security, opt);
                    let lib_name = format!(
                        "sphincsplus_{}_avx2_{}_{}{}_{}",
                        hash, hash, security, opt, thash
                    );

                    let param_file_path = avx2_dir.join("params").join(format!("params-{}.h", param_set));
                    if !param_file_path.exists() {
                        eprintln!("[build.rs] Missing SPHINCS+ AVX2 parameter file: {}", param_file_path.display());
                        std::process::exit(1);
                    }

                    let base_files = ["address.c", "fors.c", "sign.c", "utils.c", "wots.c", "randombytes.c"];
                    for file in &base_files {
                        if !avx2_dir.join(file).exists() {
                            eprintln!("[build.rs] Missing SPHINCS+ AVX2 C file: {}", avx2_dir.join(file).display());
                            std::process::exit(1);
                        }
                    }

                    let thash_file = format!("thash_{}_{}x{}.c", hash, thash,
                                             if hash == "sha2" { "8" } else { "4" });

                    let mut c_files = vec![
                        "address.c",
                        "fors.c",
                        "sign.c",
                        "utils.c",
                        "wots.c",
                        "randombytes.c",
                    ];

                    if hash == "sha2" {
                        c_files.extend(vec![
                            "sha2.c",
                            "sha256x8.c",
                            "hash_sha2.c",
                        ]);
                    } else if hash == "shake" {
                        c_files.extend(vec![
                            "fips202.c",
                            "fips202x4.c",
                            "hash_shake.c",
                        ]);
                    }

                    c_files.push(thash_file.as_str());

                    let defines = vec![
                        ("PARAMS", param_set.as_str()),
                        ("THASH", thash),
                    ];

                    PQBuilder::new(lib_name, &avx2_dir)
                        .files(c_files)
                        .defines(defines)
                        .header("api.h")
                        .allowlist(api_functions.to_vec())
                        .build();
                }
            }
        }
    }
}
*/

fn build_aesni_variants(sphincs_dir: &Path, api_functions: &[String]) {
    let aesni_dir = sphincs_dir.join("haraka-aesni");
    let security_levels = ["128", "192", "256"];
    let optimizations = ["f", "s"];
    let thash_variants = ["simple", "robust"];

    if !aesni_dir.exists() {
        println!("cargo:warning=AESNI directory not found: {}", aesni_dir.display());
        println!("cargo:warning=Skipping AESNI variants - directory missing");
        return;
    }

    println!("cargo:warning=Building SPHINCS+ Haraka-AESNI variants...");
    let mut successful_builds = 0;
    let mut failed_builds = 0;

    for &security in &security_levels {
        for &opt in &optimizations {
            for &thash in &thash_variants {
                let param_set = format!("sphincs-haraka-{}{}", security, opt);
                let lib_name = format!(
                    "sphincsplus_haraka_aesni_haraka_{}{}_{}",
                    security, opt, thash
                );

                println!("cargo:warning=Building AESNI variant: {} with {}", param_set, thash);

                // Check parameter file
                let param_file_path = aesni_dir
                    .join("params")
                    .join(format!("params-{}.h", param_set));
                if !param_file_path.exists() {
                    println!(
                        "cargo:warning=Missing SPHINCS+ AESNI parameter file: {} - skipping this variant",
                        param_file_path.display()
                    );
                    failed_builds += 1;
                    continue;
                }

                // Check required source files
                let base_files = [
                    "address.c",
                    "fors.c", 
                    "sign.c",
                    "utils.c",
                    "wots.c",
                    "randombytes.c",
                    "haraka.c",
                    "hash_haraka.c",
                ];
                let mut files_missing = false;
                for file in &base_files {
                    if !aesni_dir.join(file).exists() {
                        println!(
                            "cargo:warning=Missing SPHINCS+ AESNI C file: {} - skipping this variant",
                            aesni_dir.join(file).display()
                        );
                        files_missing = true;
                        break;
                    }
                }
                if files_missing {
                    failed_builds += 1;
                    continue;
                }

                let thash_filename = format!("thash_haraka_{}.c", thash);
                if !aesni_dir.join(&thash_filename).exists() {
                    println!(
                        "cargo:warning=Missing SPHINCS+ AESNI thash file: {} - skipping this variant",
                        aesni_dir.join(&thash_filename).display()
                    );
                    failed_builds += 1;
                    continue;
                }

                let c_files = vec![
                    "address.c",
                    "fors.c",
                    "sign.c", 
                    "utils.c",
                    "wots.c",
                    "randombytes.c",
                    "haraka.c",
                    "hash_haraka.c",
                    thash_filename.as_str(),
                ];

                let defines = vec![("PARAMS", param_set.as_str()), ("THASH", thash)];

                // Attempt to build with error handling
                match std::panic::catch_unwind(|| {
                    PQBuilder::new(lib_name.clone(), &aesni_dir)
                        .files(c_files)
                        .defines(defines)
                        .header("api.h")
                        .allowlist(api_functions.to_vec())
                        .build();
                }) {
                    Ok(_) => {
                        println!("cargo:warning=Successfully built SPHINCS+ AESNI variant: {}-{}", param_set, thash);
                        successful_builds += 1;
                    }
                    Err(_) => {
                        println!("cargo:warning=Failed to build SPHINCS+ AESNI variant: {}-{}", param_set, thash);
                        println!("cargo:warning=This may be due to architecture incompatibility - continuing with reference implementation");
                        failed_builds += 1;
                    }
                }
            }
        }
    }

    println!("cargo:warning=AESNI build summary: {} successful, {} failed", successful_builds, failed_builds);
    if successful_builds == 0 {
        println!("cargo:warning=No AESNI variants were built successfully - using reference implementation only");
        println!("cargo:warning=This is expected on non-x86 architectures");
    }
}

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

        let mut build = cc::Build::new();
        build.include(self.src_dir);

        self.configure_cross_platform(&mut build);

        let files_to_build = self.get_files();
        build.files(files_to_build);

        self.add_optimization_flags(&mut build);

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
        let params_dir = self.src_dir.join("params");
        if params_dir.exists() && std::env::var("VERBOSE").is_ok() {
            println!(
                "cargo:warning=[build.rs] Including params dir: {}",
                params_dir.display()
            );
            build.include(&params_dir);
            builder = builder.clang_arg(format!("-I{}", params_dir.display()));
        }

        for (key, val) in &self.defines {
            builder = builder.clang_arg(format!("-D{}={}", key, val));
        }

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

    fn configure_cross_platform(&self, build: &mut cc::Build) {
        #[cfg(target_os = "windows")]
        {
            build.flag_if_supported("/std:c11");
            build.define("_CRT_SECURE_NO_WARNINGS", None);
            build.define("WIN32_LEAN_AND_MEAN", None);

            if self.lib_name.contains("sphincs") || self.lib_name.contains("kyber") {
                build.define("USE_WINDOWS_CRYPTO", None);
            }
        }

        #[cfg(target_os = "macos")]
        {
            build.flag_if_supported("-std=c99");
            build.flag_if_supported("-Wno-unused-function");

            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");

            if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "aarch64" {
                build.flag_if_supported("-mcpu=apple-m1");
            }
        }

        #[cfg(target_os = "linux")]
        {
            build.flag_if_supported("-std=c99");
            build.flag_if_supported("-Wno-unused-function");
            build.flag_if_supported("-Wno-implicit-function-declaration");
            build.define("_GNU_SOURCE", None);

            println!("cargo:rustc-link-lib=pthread");
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            build.flag_if_supported("-fPIC");
            build.flag_if_supported("-fno-strict-aliasing");
        }
    }

    fn add_optimization_flags(&self, build: &mut cc::Build) {
        #[cfg(target_os = "windows")]
        {
            build.flag_if_supported("/O2");
            build.flag_if_supported("/Oi");
            build.flag_if_supported("/GL");
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            build.flag_if_supported("-O3");
            build.flag_if_supported("-fomit-frame-pointer");
            build.flag_if_supported("-march=native");

            if std::env::var("CARGO_CFG_TARGET_FEATURE")
                .unwrap_or_default()
                .contains("avx2")
            {
                build.flag_if_supported("-mavx2");
            }
        }
    }

    fn get_files(&self) -> Vec<PathBuf> {
        self.c_files
            .iter()
            .map(|file| self.src_dir.join(file))
            .collect()
    }
}
