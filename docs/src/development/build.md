# Build System Security

Cypheron Core's build system implements comprehensive security measures to safely compile potentially untrusted C vendor code while maintaining security guarantees.

For complete technical details, see [Architecture Documentation](../../ARCHITECTURE.md#build-process-security-architecture).

## Build Security Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    BUILD SECURITY PIPELINE                  │
├─────────────────────────────────────────────────────────────┤
│ 1. Pre-Build Security Checks                                │
│    ├─ Vendor code integrity verification                    │
│    ├─ Build dependency validation                           │
│    └─ Toolchain security verification                       │
├─────────────────────────────────────────────────────────────┤
│ 2. Secure Compilation Phase                                 │  
│    ├─ Security-hardened compiler flags                      │
│    ├─ Platform-specific optimizations                       │
│    └─ Stack protection enablement                           │
├─────────────────────────────────────────────────────────────┤
│ 3. FFI Binding Generation                                   │
│    ├─ API surface minimization                              │
│    ├─ Function allowlisting                                 │
│    └─ Type safety enforcement                               │
└─────────────────────────────────────────────────────────────┘
```

## Vendor Code Integrity

### Verification Process
```bash
# Automated integrity verification
find vendor/ -name "*.c" -o -name "*.h" | xargs sha256sum > SHA256SUMS
sha256sum -c SHA256SUMS
```

### Security Properties
- **Tamper Detection**: Any modification to vendor code detected immediately
- **Reproducible Builds**: Consistent verification across environments  
- **Build Failure on Mismatch**: Compilation halts if integrity check fails
- **Version Control Integration**: Checksum files tracked in git

### Vendor Sources
| Algorithm | Official Source | Verification |
|-----------|----------------|--------------|
| ML-KEM | NIST FIPS 203 Reference | SHA-256 checksums |
| ML-DSA | NIST FIPS 204 Reference | SHA-256 checksums |
| Falcon | NIST PQC Round 3 | SHA-256 checksums |
| SPHINCS+ | NIST PQC Round 3 | SHA-256 checksums |

## Secure Compilation

### Security-Hardened Compiler Flags

**Stack Protection:**
```rust  
cc.flag("-fstack-protector-strong");      // Stack canary protection
cc.flag("-D_FORTIFY_SOURCE=2");           // Buffer overflow detection
```

**Control Flow Integrity:**
```rust
#[cfg(target_os = "linux")]
cc.flag("-fcf-protection=full");          // Intel CET support

#[cfg(target_os = "windows")]
cc.flag("/guard:cf");                     // Windows CFG
```

**Memory Safety Hardening:**
```rust
cc.flag("-fPIE");                         // Position Independent Executable
cc.flag("-Wl,-z,relro");                  // Read-only relocations  
cc.flag("-Wl,-z,now");                    // Immediate symbol resolution
```

### Platform-Specific Security

**Linux Security Features:**
```rust
cc.flag("-fstack-clash-protection");     // Stack clash protection
cc.flag("-fcf-protection=full");         // Control Flow Integrity
cc.flag("-mshstk");                      // Shadow stack (Intel CET)
```

**Windows Security Features:**
```rust
cc.flag("/GS");                         // Stack buffer security check
cc.flag("/guard:cf");                   // Control Flow Guard
cc.flag("/DYNAMICBASE");                // ASLR support
```

## FFI Binding Security

### API Surface Minimization

**Function Allowlisting:**
```rust
let allowed_functions = vec![
    "crypto_kem_keypair",
    "crypto_kem_enc",
    "crypto_kem_dec",
    "crypto_sign_keypair", 
    "crypto_sign",
    "crypto_sign_open",
    // Only essential cryptographic functions exposed
];
```

**Type Restriction:**
```rust
bindgen_builder
    .allowlist_type("crypto_.*")
    .blocklist_type("internal_.*")           // Block internal details
    .opaque_type("rng_state")               // Opaque sensitive structures
```

### Security Through Isolation

**Symbol Visibility Control:**
```rust
cc.flag("-fvisibility=hidden");              // Hide symbols by default
cc.define("CRYPTO_API", "extern");           // Explicit API marking

// Platform-specific symbol control
#[cfg(target_os = "windows")]
cc.define("CRYPTO_EXPORT", "__declspec(dllexport)");

#[cfg(unix)]  
cc.define("CRYPTO_EXPORT", "__attribute__((visibility(\"default\")))");
```

**Static Linking Security:**
```rust
cc.static_flag(true);                        // Force static linking
cc.shared_flag(false);                       // Prevent DLL injection
cc.flag("-static-libgcc");                   // Static runtime linking
```

## Build Reproducibility

### Deterministic Compilation
```rust
cc.flag("-frandom-seed=0");                  // Reproducible randomization
cc.env("SOURCE_DATE_EPOCH", "1609459200");  // Reproducible timestamps
cc.flag("-fdebug-prefix-map=/build=.");     // Reproducible debug paths
```

### Build Audit Trail
```rust
println!("cargo:warning=Building with security flags: {:?}", security_flags);
println!("cargo:warning=Target architecture: {}", target_arch());
println!("cargo:warning=Compiler version: {}", compiler_version());
```

## Development Build Commands

### Standard Build
```bash
cargo build                    # Debug build with all security checks
cargo build --release          # Optimized build with security hardening
```

### Security Validation
```bash
cargo clippy                   # Static analysis and security lints
cargo test                     # Comprehensive test suite
cargo audit                    # Dependency security audit
```

### Platform-Specific Builds
```bash
# Linux with maximum security features
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Windows with enhanced security
cargo build --target x86_64-pc-windows-msvc --release

# macOS with Apple Silicon optimizations  
cargo build --target aarch64-apple-darwin --release
```

## Continuous Integration Security

### Security Validation Pipeline
1. **Vendor Integrity Check**: Verify all C code checksums
2. **Compiler Security Audit**: Validate security flags applied
3. **Binary Analysis**: Static analysis of generated binaries
4. **Symbol Analysis**: Verify minimal symbol exposure  
5. **Runtime Security Testing**: Validate security features

### Security Regression Prevention
- All security flags tracked in version control
- Build failures on missing security features
- Automated security flag regression detection
- Platform-specific security feature validation

For complete build system architecture including dependency management and security validation, see the full [Architecture Documentation](../../ARCHITECTURE.md).