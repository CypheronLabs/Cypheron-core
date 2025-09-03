# ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)

ML-KEM is the NIST-standardized quantum-resistant key encapsulation mechanism, formerly known as Kyber. It enables secure key exchange that is resistant to both classical and quantum computer attacks.

## Overview

ML-KEM is based on the Module Learning With Errors (M-LWE) problem, which is believed to be hard even for quantum computers. The algorithm provides:

- **Key Encapsulation**: Secure key exchange between parties
- **Quantum Resistance**: Security against Shor's algorithm
- **Performance**: Efficient operations suitable for real-world use
- **Standardization**: NIST FIPS 203 compliance

## Security Levels

Cypheron Core implements all three ML-KEM variants:

| Variant | Security Level | Classical Security | Quantum Security | Key Sizes |
|---------|---------------|-------------------|------------------|-----------|
| ML-KEM-512 | 1 | ~128-bit | ~64-bit | PK: 800B, SK: 1632B |
| ML-KEM-768 | 3 | ~192-bit | ~96-bit | PK: 1184B, SK: 2400B |
| ML-KEM-1024 | 5 | ~256-bit | ~128-bit | PK: 1568B, SK: 3168B |

## Basic Usage

```rust
use cypheron_core::kem::{MlKem768, Kem};

// Generate keypair
let (public_key, secret_key) = MlKem768::keypair()?;

// Alice encapsulates a shared secret
let (ciphertext, shared_secret_alice) = MlKem768::encapsulate(&public_key)?;

// Bob decapsulates the shared secret
let shared_secret_bob = MlKem768::decapsulate(&ciphertext, &secret_key)?;

// Both parties have the same 32-byte shared secret
assert_eq!(shared_secret_alice.expose_secret(), shared_secret_bob.expose_secret());
```

## Algorithm Details

### Key Generation

1. Generate matrix **A** from public randomness
2. Generate secret vectors **s** and **e** from centered binomial distribution
3. Compute **t = A·s + e**
4. Public key: **(ρ, t)**, Secret key: **s**

### Encapsulation

1. Generate ephemeral secret **r** and error vectors **e1**, **e2**
2. Compute **u = A^T·r + e1**
3. Compute **v = t^T·r + e2 + Encode(m)**
4. Return ciphertext **(u, v)** and shared secret **KDF(m)**

### Decapsulation

1. Compute **m' = Decode(v - s^T·u)**
2. Re-encapsulate with **m'** to get **(u', v')**
3. If **(u', v') = (u, v)**, return **KDF(m')**, else return **KDF(z)**

## Performance Characteristics

ML-KEM operations are highly efficient:

```rust
use std::time::Instant;
use cypheron_core::kem::{MlKem768, Kem};

fn benchmark_ml_kem() -> Result<(), Box<dyn std::error::Error>> {
    // Key generation
    let start = Instant::now();
    let (pk, sk) = MlKem768::keypair()?;
    println!("Keygen: {:?}", start.elapsed());
    
    // Encapsulation  
    let start = Instant::now();
    let (ct, ss1) = MlKem768::encapsulate(&pk)?;
    println!("Encaps: {:?}", start.elapsed());
    
    // Decapsulation
    let start = Instant::now();
    let ss2 = MlKem768::decapsulate(&ct, &sk)?;
    println!("Decaps: {:?}", start.elapsed());
    
    Ok(())
}
```

## Security Considerations

### Proper Usage

```rust
use cypheron_core::kem::{MlKem768, Kem};

// Correct: Use each key pair only once
let (pk, sk) = MlKem768::keypair()?;
let (ct, ss) = MlKem768::encapsulate(&pk)?;

// Correct: Validate ciphertext before decapsulation
if ct.len() == 1088 { // ML-KEM-768 ciphertext size
    let ss2 = MlKem768::decapsulate(&ct, &sk)?;
}

// Incorrect: Reusing the same keypair multiple times
// This could leak information about the secret key
```

### Side-Channel Protection

All operations use constant-time implementations:

- **Constant-time sampling**: Secret values don't affect execution time
- **Constant-time arithmetic**: Operations always take the same time
- **Memory access patterns**: No secret-dependent memory accesses

## Migration from Kyber

Cypheron Core provides compatibility aliases for smooth migration:

```rust
// Old Kyber code
use cypheron_core::kem::{Kyber768, KyberError}; // Deprecated

// New ML-KEM code  
use cypheron_core::kem::{MlKem768, MlKemError}; // Recommended

// Both interfaces are identical
let (pk, sk) = MlKem768::keypair()?;
```

## Test Vectors

Validation against NIST test vectors:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nist_vectors() {
        // Test against official NIST ML-KEM test vectors
        // See tests/kat/ directory for complete vectors
        let (pk, sk) = MlKem768::keypair().unwrap();
        let (ct, ss1) = MlKem768::encapsulate(&pk).unwrap();
        let ss2 = MlKem768::decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss1.expose_secret(), ss2.expose_secret());
    }
}
```

## Variants

- **[ML-KEM-512](ml-kem/ml-kem-512.md)** - Security Level 1
- **[ML-KEM-768](ml-kem/ml-kem-768.md)** - Security Level 3 (Recommended)  
- **[ML-KEM-1024](ml-kem/ml-kem-1024.md)** - Security Level 5

## See Also

- [KEM Operations API](../api/kem.md)
- [Performance Benchmarks](../performance/benchmarks.md)
- [Security Model](../security/model.md)