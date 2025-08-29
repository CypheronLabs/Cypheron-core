# Comprehensive Security Testing Infrastructure

This directory contains a comprehensive security testing infrastructure for the Cypheron-core post-quantum cryptographic library, implementing NIST FIPS 203, 204, and 205 compliant testing.

## Overview

The testing infrastructure validates:
- **NIST Compliance**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- **Security Properties**: Timing attacks, side channels, memory safety
- **Cryptographic Correctness**: Known Answer Tests, property-based testing
- **Performance**: Benchmarking and regression detection
- **Robustness**: Fuzzing and edge case handling

## Directory Structure

```
tests/
├── security/           # Security-specific tests
│   ├── timing_tests.rs         # Timing attack detection
│   ├── sidechannel_tests.rs    # Side-channel analysis
│   ├── memory_safety_tests.rs  # Memory safety validation
│   └── test_runner.rs          # Unified test runner
├── fuzz/              # Fuzzing infrastructure
│   ├── Cargo.toml             # Fuzzing dependencies
│   └── fuzz_targets/          # Individual fuzz targets
│       ├── fuzz_ml_kem_512.rs
│       ├── fuzz_ml_dsa_44.rs
│       └── fuzz_hybrid_ecc_dilithium.rs
├── kat/               # Known Answer Tests
│   ├── nist_vectors/          # NIST test vectors
│   └── kat_tests.rs           # KAT implementation
├── property/          # Property-based testing
│   └── crypto_properties.rs   # Cryptographic property validation
└── README.md          # This file
```

## Test Categories

### 1. Known Answer Tests (KAT)

Validates against NIST standard test vectors:

```bash
# Run NIST KAT tests
cargo test --test kat_tests
```

**Coverage:**
- ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
- ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
- Parameter validation and algorithm naming compliance

### 2. Property-Based Testing

Uses `proptest` to validate cryptographic properties:

```bash
# Run property-based tests
cargo test --test crypto_properties
```

**Properties Tested:**
- Encryption/decapsulation roundtrip correctness
- Signature generation and verification consistency
- Key generation determinism and uniqueness
- Hybrid scheme composition security

### 3. Security Analysis Tests

#### Timing Attack Detection
```bash
# Run timing analysis
cargo test --test timing_tests
```

Tests for constant-time behavior in:
- ML-KEM decapsulation operations
- ML-DSA signing and verification
- Hybrid scheme operations

#### Side-Channel Analysis
```bash
# Run side-channel tests
cargo test --test sidechannel_tests
```

Simulates and detects:
- Power analysis vulnerabilities
- Cache timing leaks
- Branch prediction dependencies
- Electromagnetic emission patterns

#### Memory Safety
```bash
# Run memory safety tests
cargo test --test memory_safety_tests
```

Validates:
- Buffer overflow protection
- Secure memory cleanup (zeroization)
- FFI boundary safety
- Use-after-free prevention

### 4. Fuzzing Infrastructure

#### Setup Fuzzing Environment
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run ML-KEM-512 fuzzing
cd tests/fuzz
cargo fuzz run fuzz_ml_kem_512

# Run ML-DSA-44 fuzzing
cargo fuzz run fuzz_ml_dsa_44

# Run hybrid scheme fuzzing
cargo fuzz run fuzz_hybrid_ecc_dilithium
```

**Fuzzing Targets:**
- ML-KEM operations with malformed ciphertexts
- ML-DSA operations with crafted inputs
- Hybrid scheme edge cases
- FFI boundary conditions

### 5. Performance Benchmarking

```bash
# Run comprehensive benchmarks
cargo bench --bench crypto_benchmarks

# Generate HTML reports
cargo bench --bench crypto_benchmarks -- --output-format html
```

**Benchmark Categories:**
- Algorithm performance comparison
- Security level trade-offs
- Message size throughput analysis
- Regression detection baselines

## Running All Tests

### Comprehensive Security Test Suite
```bash
# Run all security tests with unified runner
cargo test --test test_runner

# Individual test categories
cargo test --test kat_tests           # NIST compliance
cargo test --test crypto_properties   # Property validation
cargo test --test timing_tests        # Timing analysis
cargo test --test memory_safety_tests # Memory safety
cargo test --test sidechannel_tests   # Side-channel analysis
```

### CI/CD Integration

Add to your CI pipeline:

```yaml
name: Security Tests
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    - name: Run Security Tests
      run: |
        cd core-lib
        cargo test --test kat_tests
        cargo test --test crypto_properties
        cargo test --test timing_tests
        cargo test --test memory_safety_tests
        cargo test --test sidechannel_tests
    - name: Run Benchmarks
      run: cargo bench --bench crypto_benchmarks
```

## Test Configuration

### Environment Variables
```bash
# Enable verbose output
export RUST_LOG=debug

# Set test iterations for timing tests
export TIMING_SAMPLES=1000

# Configure fuzzing duration
export FUZZ_DURATION=300  # seconds
```

### Performance Thresholds

The tests include configurable performance thresholds:

```rust
// Timing variation tolerance
const MAX_TIMING_VARIATION_NS: u64 = 50_000; // 50 microseconds

// Side-channel correlation threshold
const MAX_CORRELATION: f64 = 0.3; // 30% correlation limit

// Performance regression threshold
const REGRESSION_THRESHOLD: f64 = 0.1; // 10% performance degradation
```

## Security Test Results Interpretation

### Pass Criteria

**PASS**: All security tests completed successfully
- NIST KAT tests validate against reference implementations
- Property tests confirm cryptographic correctness
- Timing tests show constant-time behavior
- Memory tests verify safe resource management
- Side-channel tests detect no significant leakage

### Failure Analysis

**FAIL**: Investigation required
1. **KAT Failures**: Algorithm implementation bug
2. **Property Failures**: Logic error or edge case
3. **Timing Failures**: Potential timing attack vulnerability
4. **Memory Failures**: Memory safety issue
5. **Side-channel Failures**: Information leakage detected

## Advanced Testing

### Custom Test Vectors

Add custom test vectors in `tests/kat/nist_vectors/`:

```rust
// Custom ML-KEM test vector
let custom_vector = MlKemKatVector {
    seed: hex::decode("...").unwrap(),
    public_key: vec![...],
    secret_key: vec![...],
    ciphertext: vec![...],
    shared_secret: vec![...],
};
```

### Extended Fuzzing

For extended fuzzing campaigns:

```bash
# Long-running fuzz campaign
cargo fuzz run fuzz_ml_kem_512 -- -max_total_time=3600  # 1 hour

# Parallel fuzzing
cargo fuzz run fuzz_ml_kem_512 -- -jobs=8

# Custom corpus
mkdir -p tests/fuzz/corpus/fuzz_ml_kem_512
# Add seed files to corpus directory
```

### Performance Profiling

```bash
# Profile with perf
cargo bench --bench crypto_benchmarks -- --profile-time=5

# Memory profiling with valgrind
cargo test --test memory_safety_tests --target x86_64-unknown-linux-gnu
valgrind --tool=memcheck target/debug/deps/memory_safety_tests-*
```

## Security Compliance

This testing infrastructure helps achieve:

- **NIST FIPS 203 Compliance**: ML-KEM validation
- **NIST FIPS 204 Compliance**: ML-DSA validation
- **NIST FIPS 205 Compliance**: SLH-DSA preparation
- **Common Criteria**: Security testing methodology
- **FIPS 140-2**: Cryptographic module validation

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Include both positive and negative test cases
3. Add appropriate documentation
4. Verify tests pass in CI environment
5. Update this README if adding new test categories

## Troubleshooting

### Common Issues

**Timing Tests Failing:**
- Ensure stable system load during testing
- Run on dedicated test hardware
- Adjust timing thresholds for virtual environments

**Memory Tests Failing:**
- Check for memory leaks with valgrind
- Verify proper cleanup in destructors
- Test with address sanitizer enabled

**KAT Tests Failing:**
- Verify NIST test vector accuracy
- Check algorithm parameter constants
- Validate endianness handling

### Performance Issues

**Slow Test Execution:**
- Reduce sample counts for development
- Use `--release` mode for accurate benchmarks
- Parallelize test execution where possible

**High Memory Usage:**
- Monitor test memory consumption
- Implement streaming for large test vectors
- Use memory-mapped files for large datasets

## References

- [NIST FIPS 203: ML-KEM Standard](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204: ML-DSA Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [NIST FIPS 205: SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- [cargo-fuzz Documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [Criterion Benchmarking](https://docs.rs/criterion/latest/criterion/)
- [Property-Based Testing with proptest](https://docs.rs/proptest/latest/proptest/)