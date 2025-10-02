# Security Policy

## Project Security Status

> **IMPORTANT: EXPERIMENTAL STATUS**  
> This library is currently in **ACTIVE DEVELOPMENT (v0.1.0)** and is **EXPERIMENTAL**.  
> **DO NOT USE IN PRODUCTION** without comprehensive integration review and testing.  
> The core algorithms are NIST-certified, but the Rust integration layer has **not undergone independent security audits**, formal verification of memory safety wrappers, or production environment validation.  
> **Primary risk areas**: FFI safety, memory management, build system integrity.

---

## Reporting Security Vulnerabilities

### Contact Information
- **Primary Contact**: [security@cypheronlabs.com](mailto:security@cypheronlabs.com)
- **Response Time**: We aim to acknowledge reports within **48 hours**
- **Resolution Time**: Critical vulnerabilities will be addressed within **7 days**

### Reporting Process
- **DO NOT** create public GitHub issues for security vulnerabilities.
- Email **security@cypheronlabs.com** with:
  - Detailed description of the vulnerability
  - Steps to reproduce
  - Potential impact assessment
  - Suggested fixes (if any)

### What to Report
Please report any of the following:
- Memory safety issues in FFI boundaries
- Constant-time implementation violations
- Side-channel vulnerabilities
- Build system integrity issues
- Vendor code integrity failures
- API misuse that could lead to security issues

---

## Security Model

### Trust Boundaries
- **NIST Reference Implementations**: Trusted (certified by NIST)
- **Rust FFI Layer**: Under security review — **primary risk area**
- **Build System**: Integrity-verified during build process

### Threat Model
- **In Scope**: Classical and quantum computer attacks on cryptographic operations
- **Protection Against**: Timing attacks, side-channel attacks, memory corruption
- **Risk Areas**: FFI safety, memory management, build system integrity

---

## Current Security Measures

### FFI Safety
The library implements comprehensive FFI safety measures:
- Buffer validation before FFI calls
- Message bounds checking
- Safe pointer casting mechanisms

### Memory Safety
- Automatic secure memory cleanup
- Buffer initialization verification
- Secure buffer sanitization (zeroization)

### Build System Integrity
- Vendor code integrity verification using SHA-256 checksums
- Build dependency validation
- Cross-platform secure compilation flags (e.g., `-fstack-protector-strong`, `-fcf-protection`)

### Cryptographic Security
- Constant-time implementations to prevent timing attacks
- NIST-certified algorithm implementations (FIPS 203, 204, 205)
- Platform-specific optimizations with security considerations

---

## Security Testing

### Known Answer Tests (KAT)
Comprehensive KAT files validate compliance with official NIST test vectors.

### Security Validation Includes:
- FFI boundary safety testing
- Memory safety validation
- Constant-time implementation verification
- Side-channel resistance analysis
- Vendor code integrity checks

### Testing Commands
```bash
# Run comprehensive security validation
cargo test --test test_runner

# Run vendor integrity verification
./scripts/vendor-integrity.sh verify

# Run fuzzing (when available)
cargo fuzz
