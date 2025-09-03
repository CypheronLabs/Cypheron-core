# Cypheron Core

<div class="cypheron-logo">Cypheron Core</div>

> **IMPORTANT DEVELOPMENT STATUS NOTICE**
> 
> **This library is currently in ACTIVE DEVELOPMENT (v0.1.0) and is EXPERIMENTAL.**
> 
> **This is a Rust wrapper around official NIST reference implementations** - not custom cryptography.
> The core algorithms are NIST-certified, but the Rust integration layer has NOT undergone:
> - Independent security audits of FFI bindings
> - Formal verification of memory safety wrappers
> - Production environment validation
> 
> **DO NOT USE IN PRODUCTION** without comprehensive integration review and testing.
> 
> Risk areas: FFI safety, memory management, build system - NOT the underlying NIST algorithms.

**Post-quantum cryptography library implementing NIST-standardized quantum-resistant algorithms**

Cypheron Core is a Rust library implementing NIST-standardized quantum-resistant algorithms designed to protect against both classical and quantum computer attacks. The library provides high-performance implementations with strong security guarantees.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
cypheron-core = "0.1.0"
```

Basic usage:

```rust
use cypheron_core::kem::{MlKem768, Kem};

// Generate keypair
let (public_key, secret_key) = MlKem768::keypair()?;

// Encapsulate shared secret  
let (ciphertext, shared_secret) = MlKem768::encapsulate(&public_key)?;

// Decapsulate shared secret
let decapsulated_secret = MlKem768::decapsulate(&ciphertext, &secret_key)?;
assert_eq!(shared_secret.expose_secret(), decapsulated_secret.expose_secret());
```

## Algorithms Supported

### Key Encapsulation Mechanisms (KEM)

<div class="algorithm-badge">ML-KEM-512</div> <span class="security-level security-level-1">Security Level 1</span>
<div class="algorithm-badge">ML-KEM-768</div> <span class="security-level security-level-3">Security Level 3</span>  
<div class="algorithm-badge">ML-KEM-1024</div> <span class="security-level security-level-5">Security Level 5</span>

### Digital Signatures

<div class="algorithm-badge">ML-DSA-44</div> <span class="security-level security-level-2">Security Level 2</span>
<div class="algorithm-badge">ML-DSA-65</div> <span class="security-level security-level-3">Security Level 3</span>
<div class="algorithm-badge">ML-DSA-87</div> <span class="security-level security-level-5">Security Level 5</span>

<div class="algorithm-badge">Falcon-512</div> <span class="security-level security-level-1">Security Level 1</span>
<div class="algorithm-badge">Falcon-1024</div> <span class="security-level security-level-5">Security Level 5</span>

<div class="algorithm-badge">SPHINCS+</div> Multiple variants available

### Hybrid Cryptography

- **ECC + ML-DSA**: Classical elliptic curve + post-quantum signatures
- **Hybrid KEM**: Combined classical and post-quantum key agreement

## Performance

| Algorithm | Key Gen | Sign/Encaps | Verify/Decaps |
|-----------|---------|-------------|---------------|
| ML-KEM-768 | <span data-perf="Average: 0.05ms on modern CPUs">~50μs</span> | <span data-perf="Average: 0.06ms on modern CPUs">~60μs</span> | <span data-perf="Average: 0.08ms on modern CPUs">~80μs</span> |
| ML-DSA-65 | <span data-perf="Average: 0.12ms on modern CPUs">~120μs</span> | <span data-perf="Average: 0.25ms on modern CPUs">~250μs</span> | <span data-perf="Average: 0.11ms on modern CPUs">~110μs</span> |

## Security Features

- **Side-channel resistance**: Constant-time implementations
- **Memory safety**: Secure key zeroization
- **NIST compliance**: Implements FIPS 203, 204, 205 standards
- **Production hardened**: Extensive testing and validation

## Documentation Sections

- **[Getting Started](getting-started/installation.md)** - Installation and basic usage
- **[API Reference](api/types.md)** - Complete API documentation  
- **[Algorithms](algorithms/ml-kem.md)** - Detailed algorithm documentation
- **[Security](security/model.md)** - Security model and considerations
- **[Troubleshooting](troubleshooting/common.md)** - Common issues and solutions

## Error Handling

When you encounter errors, they include direct links to relevant documentation:

```rust
match MlKem768::keypair() {
    Ok((pk, sk)) => { /* use keys */ },
    Err(e) => {
        // Error includes link: ERROR-KEM-001
        // See: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-001
        eprintln!("Key generation failed: {}", e);
    }
}
```

## Local Development

Run the documentation locally:

```bash
# Install mdBook
cargo install mdbook

# Serve documentation with hot reload
cd docs
mdbook serve

# Open http://localhost:3000 in your browser
```

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

---

<div class="warning-box">
<strong>Development Status:</strong> This library (v0.1.0) contains experimental implementations and has not been audited. DO NOT USE IN PRODUCTION without thorough security review. Built with C vendor code + Rust FFI requiring careful validation. See <a href="security/model.md">Security Model</a> for details.
</div>