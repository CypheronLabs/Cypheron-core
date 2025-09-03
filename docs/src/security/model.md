# Security Model

> **DEVELOPMENT STATUS WARNING**
> 
> This security model describes the INTENDED security properties of Cypheron Core v0.1.0.
> 
> **CRITICAL**: This is a Rust wrapper around official NIST reference implementations - not custom cryptography.
> The core algorithms are NIST-certified, but the Rust integration layer is experimental and has NOT been:
> - Independently audited for FFI safety
> - Formally verified for memory management
> - Validated in production environments
> 
> Integration layer uses C vendor code with Rust FFI bindings requiring security evaluation.

Cypheron Core's security model describes intended cryptographic foundations and defensive programming practices.

## Threat Model

### Adversarial Capabilities

We protect against adversaries with the following capabilities:

1. **Classical Computers**: Unlimited classical computational power
2. **Quantum Computers**: Large-scale fault-tolerant quantum computers
3. **Side-Channel Attacks**: Timing, power, and electromagnetic analysis
4. **Memory Attacks**: Cold boot attacks, memory dumps, swap file analysis

### Security Goals

- **Confidentiality**: Encrypted data remains secret
- **Authenticity**: Signatures prove message origin
- **Integrity**: Tampering is detectable
- **Forward Secrecy**: Past communications remain secure if keys are compromised

## Cryptographic Security

### Post-Quantum Resistance

All algorithms are designed to resist quantum computer attacks:

- **ML-KEM**: Based on Module Learning With Errors (M-LWE)
- **ML-DSA**: Based on Module Short Integer Solution (M-SIS)
- **Falcon**: Based on NTRU lattices and Gaussian sampling
- **SPHINCS+**: Based on hash functions and one-time signatures

### Security Levels

| Level | Classical Security | Quantum Security | Real-World Equivalent |
|-------|-------------------|------------------|---------------------|
| 1     | 128-bit           | 64-bit           | AES-128             |
| 2     | 128-bit           | 64-bit           | SHA-256             |
| 3     | 192-bit           | 96-bit           | AES-192             |
| 4     | 192-bit           | 96-bit           | SHA-256             |
| 5     | 256-bit           | 128-bit          | AES-256             |

## Implementation Security

### Constant-Time Operations

All cryptographic operations execute in constant time:

```rust
// Example: Constant-time secret key usage
let (pk, sk) = MlKem768::keypair()?;
let (ct, ss) = MlKem768::encapsulate(&pk)?;

// Decapsulation time is independent of:
// - Secret key content
// - Ciphertext validity  
// - Previous operations
let result = MlKem768::decapsulate(&ct, &sk)?;
```

### Memory Protection

Sensitive data is automatically protected:

```rust
use secrecy::ExposeSecret;

{
    let (pk, sk) = MlKem768::keypair()?;
    
    // Secret key is in protected memory
    let secret_data = sk.0.expose_secret();
    
    // Use secret_data...
    
} // Secret key memory is zeroized automatically
```

### Randomness Requirements

Cryptographic operations require high-quality randomness:

- **Entropy Sources**: Hardware RNG, OS entropy pools
- **Seeding**: Proper CSPRNG initialization
- **Reseeding**: Regular entropy pool updates

```rust
// Entropy failure is handled gracefully
match MlKem768::keypair() {
    Ok((pk, sk)) => { /* success */ },
    Err(MlKemError::KeyGenerationEntropyFailure) => {
        // Handle insufficient entropy
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Retry...
    },
    Err(e) => return Err(e),
}
```

## Side-Channel Protection

### Timing Attacks

All operations use constant-time algorithms:

- **No secret-dependent branches**: Control flow is independent of secrets
- **No secret-dependent memory access**: Memory patterns are predictable
- **No secret-dependent loop bounds**: Iteration counts are fixed

### Power Analysis

Operations are designed to minimize power analysis vulnerabilities:

- **Uniform operations**: Similar power consumption patterns
- **Masked arithmetic**: Secret values are never used directly
- **Randomized execution**: Some operations include deliberate randomness

### Fault Injection

Critical operations include integrity checks:

```rust
// Example: Built-in integrity verification
let (pk, sk) = MlKem768::keypair()?;
let (ct, ss1) = MlKem768::encapsulate(&pk)?;

// Decapsulation includes implicit ciphertext validation
match MlKem768::decapsulate(&ct, &sk) {
    Ok(ss2) => {
        // ss1 and ss2 are identical if no faults occurred
        assert_eq!(ss1.expose_secret(), ss2.expose_secret());
    },
    Err(MlKemError::DecapsulationInvalidCiphertext) => {
        // Ciphertext was corrupted or maliciously modified
    },
}
```

## Key Management

### Key Lifecycle

1. **Generation**: High-entropy key creation
2. **Storage**: Encrypted at rest when possible
3. **Usage**: Minimal exposure time
4. **Destruction**: Cryptographic erasure

```rust
// Proper key lifecycle management
fn secure_key_usage() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generation
    let (pk, sk) = MlKem768::keypair()?;
    
    // 2. Usage (minimize exposure time)
    let (ct, ss) = MlKem768::encapsulate(&pk)?;
    
    // 3. Destruction is automatic when variables go out of scope
    Ok(())
} // Keys are zeroized here
```

### Key Rotation

Regular key rotation is recommended:

```rust
use std::time::{Duration, Instant};

struct KeyManager {
    current_keys: (MlKemPublicKey, MlKemSecretKey),
    created_at: Instant,
    rotation_interval: Duration,
}

impl KeyManager {
    fn should_rotate(&self) -> bool {
        self.created_at.elapsed() > self.rotation_interval
    }
    
    fn rotate(&mut self) -> Result<(), MlKemError> {
        if self.should_rotate() {
            self.current_keys = MlKem768::keypair()?;
            self.created_at = Instant::now();
        }
        Ok(())
    }
}
```

## Compliance and Standards

### NIST Standardization

All algorithms implement NIST-standardized specifications:

- **FIPS 203**: ML-KEM standard
- **FIPS 204**: ML-DSA standard  
- **FIPS 205**: SPHINCS+ standard

### Security Validations

- **Known Answer Tests (KAT)**: Validation against NIST test vectors
- **Monte Carlo Testing**: Statistical randomness validation
- **Side-Channel Testing**: Timing and power analysis resistance

## Limitations and Assumptions

### Trust Assumptions

- **Implementation Correctness**: No bugs in cryptographic implementations
- **Hardware Security**: CPU and memory provide basic security guarantees
- **Random Number Generation**: OS provides cryptographically secure randomness

### Known Limitations

- **No Perfect Forward Secrecy**: KEM schemes don't provide PFS by default
- **Post-Quantum Assumptions**: Security relies on unproven mathematical assumptions
- **Implementation Attacks**: Hardware vulnerabilities could compromise security

## Best Practices

### Application Security

```rust
// ✅ Good: Validate all inputs
if ciphertext.len() != EXPECTED_CIPHERTEXT_SIZE {
    return Err("Invalid ciphertext size");
}

// ✅ Good: Handle errors appropriately  
match MlKem768::decapsulate(&ct, &sk) {
    Ok(ss) => use_shared_secret(ss),
    Err(e) => log_security_event(e),
}

// ❌ Bad: Ignoring security-critical errors
let ss = MlKem768::decapsulate(&ct, &sk).unwrap(); // Don't do this!
```

### Operational Security

1. **Monitor Entropy**: Check system entropy levels
2. **Log Security Events**: Record cryptographic failures
3. **Update Regularly**: Keep libraries up to date
4. **Test Thoroughly**: Validate all error paths

## See Also

- [Side-Channel Protection](side-channels.md) - Detailed protection mechanisms
- [Memory Safety](memory.md) - Memory security guarantees
- [Compliance](compliance.md) - Standards compliance