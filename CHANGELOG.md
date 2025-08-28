# Changelog

All notable changes to Cypheron Core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-XX

### Added
- Initial release of Cypheron Core
- ML-KEM (Kyber) implementation with 512, 768, and 1024-bit security levels
- ML-DSA (Dilithium) digital signatures with levels 2, 3, and 5
- Falcon digital signatures with 512 and 1024-bit variants
- SPHINCS+ hash-based signatures with multiple configurations
- Hybrid cryptography support combining ECC with post-quantum algorithms
- Cross-platform support for Windows, macOS, and Linux
- Memory safety with automatic secure cleanup
- Constant-time implementations for side-channel protection
- Comprehensive test suite including:
  - Unit tests for all algorithms
  - Known Answer Tests (KAT) for NIST compliance
  - Property-based testing
  - Fuzz testing infrastructure
  - Security and timing tests
- Performance benchmarks for all algorithms
- Vendor code integrity verification
- Apache 2.0 license

### Security
- Constant-time cryptographic implementations
- Secure memory management with zeroization
- Side-channel attack prevention measures
- Memory safety guarantees through Rust

[0.1.0]: https://github.com/CypheronLabs/Cypheron-core/releases/tag/v0.1.0