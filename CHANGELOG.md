# Changelog

All notable changes to Cypheron Core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-01-08

### Fixed
- **Windows CI Build**: Fixed linking error for `randombytes` function on Windows builds
  - Resolved "unresolved external symbol randombytes" linker error
  - Added proper Windows-specific random number generation using Windows Crypto API
  - Excluded POSIX-only `randombytes.c` from Windows compilation
  - Maintained cross-platform compatibility with Linux and macOS

### Added  
- **Comprehensive Cargo Features**: Added granular feature flags for algorithm selection
  - Algorithm-specific features: `ml-kem`, `ml-dsa`, `falcon`, `sphincs`
  - Security level groupings: `level1`, `level3`, `level5` 
  - Recommended configurations: `balanced`, `high-security`, `low-latency`
  - Optimization features: `aesni`, `avx2`, `simd`
  - Platform features: `platform-entropy`, `platform-info`
  - Hybrid scheme features: `hybrid-kem`, `hybrid-sig`
  - Utility features: `serde`, `std`, `testing`
- **Platform Detection**: Enhanced runtime CPU feature detection
- **Module Organization**: Improved internal module structure for platform-specific code

### Changed
- **Dependency Management**: Made `serde` dependency optional for better feature control
- **Build Process**: Enhanced cross-platform build compatibility
- **API**: Maintained full backward compatibility with v0.1.0

### Technical
- Fixed module import structure for Windows-specific cryptographic functions
- Updated Windows API usage to support latest `windows` crate version
- Improved error handling in platform-specific random number generation
- Enhanced CI/CD pipeline reliability across all supported platforms

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

[0.1.1]: https://github.com/CypheronLabs/Cypheron-core/releases/tag/v0.1.1
[0.1.0]: https://github.com/CypheronLabs/Cypheron-core/releases/tag/v0.1.0