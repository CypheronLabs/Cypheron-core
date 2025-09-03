# Cypheron Core

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

Post-quantum cryptography library providing NIST-standardized quantum-resistant algorithms for secure applications.

## Overview

Cypheron Core implements post-quantum cryptographic algorithms that protect against both classical and quantum computer attacks. The library provides a secure, high-performance foundation for building quantum-resistant applications.

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)
- **ML-KEM (Kyber)** - 512, 768, 1024 bit security levels
- Quantum-resistant key exchange and encryption

### Digital Signatures  
- **ML-DSA (Dilithium)** - Levels 2, 3, 5
- **Falcon** - 512, 1024 bit variants
- **SPHINCS+** - Hash-based signatures with multiple configurations

### Hybrid Cryptography
- ECC + Post-Quantum combinations for migration scenarios
- Backward compatibility with existing systems

## Installation

### From Crates.io
```bash
cargo add cypheron-core
```

Or add manually to your `Cargo.toml`:
```toml
[dependencies]
cypheron-core = "0.1.0"
```

### From Source (for auditing)
```bash
git clone https://github.com/CypheronLabs/Cypheron-core.git
cd Cypheron-core/core-lib
cargo build --release
```

## Quick Start

Basic usage:
```rust
use cypheron_core::kem::ml_kem_768::MlKem768;

// Generate quantum-resistant key pair
let (public_key, secret_key) = MlKem768::generate_keypair();

// Encapsulate shared secret
let (ciphertext, shared_secret) = MlKem768::encapsulate(&public_key);

// Decapsulate on recipient side
let recovered_secret = MlKem768::decapsulate(&secret_key, &ciphertext);
assert_eq!(shared_secret, recovered_secret);
```

## Features

- **Memory Safety** - Built in Rust with automatic secure cleanup
- **Cross-platform** - Windows, macOS, Linux support
- **Performance Optimized** - Optimized implementations with platform-specific acceleration
- **Security Focused** - Constant-time implementations and side-channel protection
- **Well Tested** - Comprehensive test suite including known answer tests and fuzzing

## Security

- Constant-time implementations to prevent timing attacks
- Secure memory management with automatic zeroization
- Vendor code integrity verification during build
- Extensive testing including property-based and fuzz testing

## Documentation

### API Documentation
Run `cargo doc --open` to build and view complete API documentation locally.

### Resources
- **Website:** [cypheronlabs.com](https://cypheronlabs.com/)
- **Security Audit:** Full source code available for security review
- **Algorithm Specifications:** NIST standardized implementations
- **Performance Benchmarks:** Run `cargo bench` for platform-specific metrics

## Community Security Audit

**We invite security researchers and cryptography experts to audit this library.**

This experimental implementation includes:
- **Comprehensive test suite** - NIST KAT, timing analysis, side-channel detection
- **Security tooling** - Fuzzing infrastructure, memory safety validation
- **Open methodology** - Full source code, build reproducibility, test transparency

### Audit Resources
- **Test Suite**: Run `cargo test --test test_runner` for comprehensive security validation
- **Fuzzing**: Use `cargo fuzz` for robustness testing
- **Documentation**: Complete API and security model documentation available
- **Vendor Code**: C implementations from NIST reference sources with integrity verification

### Security Review Areas
- FFI boundary safety between Rust and C vendor code
- Constant-time implementation validation
- Memory safety and zeroization verification
- Side-channel resistance analysis
- NIST compliance validation

**Security findings welcome**: Report to security@cypheronlabs.com following our [Security Policy](SECURITY.md).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

Built by [Cypheron Labs](https://cypheronlabs.com/) - Advancing post-quantum cryptography.