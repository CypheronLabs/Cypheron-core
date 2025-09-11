# Security Architecture

Cypheron Core implements a comprehensive security architecture designed for post-quantum cryptographic applications requiring high assurance.

For complete security analysis, see the full [Architecture Documentation](../../ARCHITECTURE.md#security-architecture).

## Security Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CYPHERON CORE SECURITY ARCHITECTURE                 │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                        APPLICATION LAYER                                │ │
│ │  • Memory Safety: Rust Compiler Guaranteed                             │ │
│ │  • Security Level: FULLY TRUSTED                                       │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                        CYPHERON CORE API                               │ │
│ │  • Input Validation & Sanitization                                     │ │
│ │  • Secure Memory Management                                            │ │
│ │  • Error Handling & Recovery                                           │ │
│ │  • Security Level: CONDITIONALLY TRUSTED                              │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│ ┌═════════════════════════════════════════════════════════════════════════┐ │
│ ║                        FFI SECURITY BOUNDARY                           ║ │
│ ║  • Buffer Bounds Validation                                            ║ │
│ ║  • Type Safety Enforcement                                             ║ │
│ ║  • Memory Ownership Control                                            ║ │
│ ║  • Security Level: CRITICAL TRUST BOUNDARY                            ║ │
│ └═════════════════════════════════════════════════════════════════════════┘ │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                        NIST C IMPLEMENTATIONS                          │ │
│ │  • Cryptographic Operations                                            │ │
│ │  • Manual Memory Management                                            │ │
│ │  • Platform-Specific Optimizations                                     │ │
│ │  • Security Level: UNTRUSTED (VERIFIED BY TESTING)                    │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Trust Boundaries

### Fully Trusted Zone
**Rust Application Code & Core API**
- Type safety guaranteed by Rust compiler
- Memory safety enforced automatically
- Bounds checking on all array accesses

### Conditionally Trusted Zone  
**Cypheron Core Unsafe Wrappers**
- Input validation and sanitization
- Buffer allocation and lifetime management
- Error handling and conversion
- Manual safety verification required

### Untrusted Zone
**NIST C Reference Implementations**
- Manual memory management
- Potential undefined behavior
- Platform-specific behavior
- Trust through verification and testing

## Security Properties

### Memory Safety
- **Rust Code**: Automatic memory safety through type system
- **FFI Boundary**: Manual validation with comprehensive testing
- **C Code**: Trust through NIST reference implementation quality

### Side-Channel Resistance
- Constant-time implementations where feasible in C vendor code
- Secure memory zeroization using Rust's zeroize crate
- Platform-specific secure random number generation

### Supply Chain Security
- SHA-256 verification of all vendor C code
- Reproducible build process
- Version-controlled checksum validation
- Build failure on integrity violations

## Attack Surface Analysis

### Primary Attack Vectors
1. **FFI Boundary Exploitation**: Buffer overflows, type confusion
2. **Memory Safety Violations**: Use-after-free, double-free in unsafe code
3. **Supply Chain Attacks**: Compromised vendor code, build system tampering
4. **Side-Channel Analysis**: Timing attacks, power analysis

### Mitigation Strategies
1. **Comprehensive Input Validation**: All FFI inputs validated before C calls
2. **Bounded Buffer Operations**: All C functions receive exact buffer sizes
3. **Integrity Verification**: Cryptographic verification of vendor code
4. **Security Testing**: Fuzzing, property-based testing, KAT validation

## Vendor Code Provenance

All C implementations sourced from official NIST references:
- **ML-KEM**: NIST FIPS 203 reference implementation
- **ML-DSA**: NIST FIPS 204 reference implementation  
- **Falcon**: NIST PQC Round 3 submission
- **SPHINCS+**: NIST PQC Round 3 submission

Each with SHA-256 integrity verification and controlled update process.

For complete technical details including FFI boundary analysis, memory safety model, and build process security, see the full [Architecture Documentation](../../ARCHITECTURE.md).