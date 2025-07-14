use std::env;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
const _OS_SUFFIX: &str = "windows";
#[cfg(target_os = "macos")]
const _OS_SUFFIX: &str = "macos";
#[cfg(target_os = "linux")]
const _OS_SUFFIX: &str = "linux";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sphincs_dir = manifest_dir.join("..").join("vendor/sphincsplus");

    build_kyber_all(&manifest_dir);
    build_dilithium_all(&manifest_dir);
    build_falcon_all(&manifest_dir);
    build_sphincsplus_all(&sphincs_dir);

    println!("cargo:rerun-if-changed=build.rs");
}

fn build_kyber_all(manifest_dir: &Path) {
    let ref_dir = manifest_dir.join("..").join("vendor/kyber/ref");
    println!("cargo:rerun-if-changed={}", ref_dir.display());

assert!(
    ref_dir.join("indcpa.c").exists(),
    "[build.rs] Missing Kyber file: indcpa.c"
);
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
            "FALCON_TMPSIZE_KEYGEN".into(),
            "FALCON_TMPSIZE_SIGNDYN".into(),
            "FALCON_TMPSIZE_VERIFY".into(),
            // "shake256_init".into(),
            // "shake256_inject".into(),
            // "shake256_flip".into(),
            // "shake256_extract".into(),
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
    let optimizations = ["f", "s"]; // f = fast, s = small  
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
                    //let param_set = format!("sphincs-{}-{}{}", hash, security, opt);  
                    let lib_name = format!("sphincsplus_sphincs_{}_{}{}_{}", hash, security, opt, thash);  
                    
                    let mut owned_files: Vec<String> = vec![];
                    let mut c_files: Vec<&str> = vec![
                        "address.c",
                        "fors.c",
                        "merkle.c",      // <--- ADDED
                        "sign.c",
                        "utils.c",
                        "utilsx1.c",     // <--- ADDED
                        "wots.c",
                        "wotsx1.c",      // <--- ADDED
                        "randombytes.c"
                    ];

                    match hash {
                        "sha2" => {
                            owned_files.push(format!("thash_sha2_{}.c", thash));
                            c_files.push("sha2.c");
                            c_files.push("hash_sha2.c");
                            c_files.push(owned_files.last().unwrap());
                        },
                        "shake" => {
                            owned_files.push(format!("thash_shake_{}.c", thash));
                            c_files.push("fips202.c");
                            c_files.push("hash_shake.c");
                            c_files.push(owned_files.last().unwrap());
                        },
                        "haraka" => {
                            owned_files.push(format!("thash_haraka_{}.c", thash));
                            c_files.push("haraka.c");
                            c_files.push("hash_haraka.c");
                            c_files.push(owned_files.last().unwrap());
                        },
                        _ => panic!("Unsupported hash function"),
                    }
                      
                    //let param_h = format!("params-{}.h", param_set);
                    //let param_file = format!("params-sphincs-{}-{}{}", hash, security, opt);
                    let thash_str = thash.to_string();
                    
                    let param_file = format!("sphincs-{}-{}{}", hash, security, opt);
                    let defines = vec![
                        ("PARAMS", param_file.as_str()),
                        ("THASH", thash_str.as_str()),
];
                       
                    PQBuilder::new(lib_name, &ref_dir)  
                        .files(c_files)  
                        .defines(defines)  
                        .header("api.h")  
                        .allowlist(api_functions.clone())  
                        .build();  
                }  
            }  
        }  
    }  
    #[cfg(target_feature = "avx2")]  
    build_avx2_variants(sphincs_dir, &api_functions);  
      
    #[cfg(target_feature = "aes")]  
    build_aesni_variants(sphincs_dir, &api_functions);  
      
    println!("cargo:rerun-if-changed={}", sphincs_dir.display());  
}  
  
#[cfg(target_feature = "avx2")]  
fn build_avx2_variants(sphincs_dir: &Path, api_functions: &[String]) {  
    // Build AVX2-optimized variants for SHA2 and SHAKE  
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
                    let lib_name = format!("sphincsplus_{}_avx2_{}_{}{}_{}",   
                                          hash, hash, security, opt, thash);  
                      
                    // Core files  
                    let mut c_files = vec![  
                        "address.c",  
                        "fors.c",  
                        "sign.c",  
                        "utils.c",  
                        "wots.c",  
                        "randombytes.c",  
                    ];  
                      
                    // Add hash-specific files for AVX2  
                    if hash == "sha2" {  
                        c_files.extend(vec![  
                            "sha2.c",  
                            "sha2x8.c",  
                            "hash_sha2.c",  
                            &format!("thash_sha2_{}x8.c", thash),  
                        ]);  
                    } else if hash == "shake" {  
                        c_files.extend(vec![  
                            "fips202.c",  
                            "fips202x4.c",  
                            "hash_shake.c",  
                            &format!("thash_shake_{}x4.c", thash),  
                        ]);  
                    }  
                      
                    let defines = vec![  
                        ("PARAMS", &format!("params-{}.h", param_set)),  
                        ("THASH", thash),  
                    ];  
                      
                    PQBuilder::new(lib_name, &avx2_dir)  
                        .files(c_files)  
                        .defines(defines)  
                        .header("api.h")  
                        .allowlist(api_functions.clone())  
                        .build();  
                }  
            }  
        }  
    }  
}  
  
#[cfg(target_feature = "aes")]  
fn build_aesni_variants(sphincs_dir: &Path, api_functions: &[String]) {  
    let aesni_dir = sphincs_dir.join("haraka-aesni");  
    let security_levels = ["128", "192", "256"];  
    let optimizations = ["f", "s"];  
    let thash_variants = ["simple", "robust"];  
      
    for &security in &security_levels {  
        for &opt in &optimizations {  
            for &thash in &thash_variants {  
                let param_set = format!("sphincs-haraka-{}{}", security, opt);  
                let lib_name = format!("sphincsplus_haraka_aesni_haraka_{}{}_{}", security, opt, thash);  
                  
                let thash_filename = format!("thash_haraka_{}.c", thash);

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
                let param_h = format!("params-{}.h", param_set);
                let thash_str = thash.to_string();
                
                let defines = vec![
                    ("PARAMS", param_h.as_str()),
                    ("THASH", thash_str.as_str()),
                ];
                  
                PQBuilder::new(lib_name, &aesni_dir)  
                    .files(c_files)  
                    .defines(defines)  
                    .header("api.h")  
                    .allowlist(api_functions.to_vec())  
                    .build();  
                  
                println!("Built SPHINCS+ AESNI variant: {}-{}", param_set, thash);  
            }  
        }  
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
        
        // Cross-platform compiler configuration
        self.configure_cross_platform(&mut build);
        
        build.files(self.c_files.iter().map(|f| self.src_dir.join(f)));
        
        // Platform-specific optimization flags
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
            println!("cargo:warning=[build.rs] Including params dir: {}", params_dir.display());
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

    // Cross-platform compiler configuration
    fn configure_cross_platform(&self, build: &mut cc::Build) {
        // Windows-specific configuration
        #[cfg(target_os = "windows")]
        {
            // Use MSVC on Windows
            build.flag_if_supported("/std:c11");
            build.define("_CRT_SECURE_NO_WARNINGS", None);
            build.define("WIN32_LEAN_AND_MEAN", None);
            
            // Windows-specific crypto APIs
            if self.lib_name.contains("sphincs") || self.lib_name.contains("kyber") {
                build.define("USE_WINDOWS_CRYPTO", None);
            }
        }

        // macOS-specific configuration
        #[cfg(target_os = "macos")]
        {
            build.flag_if_supported("-std=c99");
            build.flag_if_supported("-Wno-unused-function");
            
            // macOS Security Framework for random number generation
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            
            // Apple Silicon optimization
            if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "aarch64" {
                build.flag_if_supported("-mcpu=apple-m1");
            }
        }

        // Linux-specific configuration (existing)
        #[cfg(target_os = "linux")]
        {
            build.flag_if_supported("-std=c99");
            build.flag_if_supported("-Wno-unused-function");
            
            // Link with pthread for random number generation
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
            build.flag_if_supported("/Oi"); // Enable intrinsic functions
            build.flag_if_supported("/GL"); // Whole program optimization
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            build.flag_if_supported("-O3");
            build.flag_if_supported("-fomit-frame-pointer");
            build.flag_if_supported("-march=native");
            
            if std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default().contains("avx2") {
                build.flag_if_supported("-mavx2");
            }
        }
    }
}
