# Falcon (Digital Signatures)

Falcon is a post-quantum digital signature scheme based on the NTRU lattice structure, offering compact signatures and fast verification.

## Overview

Falcon provides:
- **Compact Signatures**: Smallest signature sizes among post-quantum schemes
- **Fast Verification**: Efficient signature verification operations
- **Quantum Resistance**: Security against quantum cryptanalysis
- **NIST Finalist**: Round 3 finalist in NIST post-quantum standardization

## Security Levels

Cypheron Core implements two Falcon variants:

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| Falcon-512 | Level 1 (~112-bit) | 897 bytes | 1,281 bytes | ~666 bytes |
| Falcon-1024 | Level 5 (~256-bit) | 1,793 bytes | 2,305 bytes | ~1,280 bytes |

*Note: Falcon signatures have variable length; sizes shown are typical values.*

## Basic Usage

### Key Generation
```rust
use cypheron_core::sig::{Falcon512, DigitalSignature};

// Generate a new keypair
let (public_key, secret_key) = Falcon512::keypair()?;
```

### Message Signing
```rust
let message = b"Falcon signature example";

// Sign the message
let signature = Falcon512::sign(&secret_key, message)?;
```

### Signature Verification
```rust
// Verify the signature
let is_valid = Falcon512::verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## Advanced Usage

### Deterministic Key Generation
```rust
use cypheron_core::sig::Falcon512;

// Generate keypair from seed (for testing)
let seed = [1u8; 48];  // Falcon uses 48-byte seeds
let (pk, sk) = Falcon512::keypair_deterministic(&seed)?;
```

### Variable-Length Signatures
```rust
// Falcon signatures have variable length
let signature = Falcon512::sign(&secret_key, message)?;
println!("Signature length: {} bytes", signature.len());

// Length varies based on randomness and message
// Typical range: 600-700 bytes for Falcon-512
```

## Security Considerations

### Recommended Usage
- **Use Falcon-512** for applications requiring compact signatures
- **Use Falcon-1024** for high-security applications needing 256-bit security
- Consider ML-DSA for applications where deterministic signature size is important

### Key Security
```rust
use secrecy::{ExposeSecret, Zeroize};

// Secret keys are automatically zeroized
impl Drop for FalconSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Safe secret key access
secret_key.expose_secret(|key_bytes| {
    Falcon512::sign_with_raw_key(key_bytes, message)
})
```

### Implementation Notes
- Uses floating-point arithmetic internally (NTRU structure)
- Signature generation involves random sampling
- Verification is deterministic and constant-time

## Performance Characteristics

### Typical Performance (x86_64, 3.0 GHz)
| Operation | Falcon-512 | Falcon-1024 |
|-----------|------------|-------------|
| Key Generation | ~2.5ms | ~8ms |
| Sign | ~1.2ms | ~3.5ms |
| Verify | ~85μs | ~180μs |

### Memory Usage
- Key generation requires temporary working memory
- Signing uses stack-allocated buffers
- Verification is memory-efficient

## Error Handling

### Common Errors
```rust
use cypheron_core::error::Error;

match Falcon512::verify(&public_key, message, &signature) {
    Ok(true) => println!("Valid signature"),
    Ok(false) => println!("Invalid signature"), 
    Err(Error::InvalidPublicKey) => println!("Malformed public key"),
    Err(Error::InvalidSignature) => println!("Malformed signature"),
    Err(Error::SigningFailed) => println!("Random sampling failed"),
    Err(e) => println!("Other error: {}", e),
}
```

### Input Validation
- Public keys validated for proper NTRU structure
- Signatures validated for encoding compliance
- Invalid inputs return errors without panicking

## Interoperability

### NIST Compatibility
- Implements NIST Round 3 Falcon specification
- Compatible with reference implementations
- Passes all official test vectors

### Serialization
```rust
// Serialize keys and signatures
let pk_bytes = public_key.as_bytes();
let sk_bytes = secret_key.expose_secret(|bytes| bytes.to_vec());
let sig_bytes = signature.as_bytes();

// Deserialize from bytes
let public_key = FalconPublicKey::from_bytes(&pk_bytes)?;
let signature = FalconSignature::from_bytes(&sig_bytes)?;
```

## Comparison with Other Schemes

### Falcon vs ML-DSA
| Aspect | Falcon | ML-DSA |
|--------|--------|--------|
| Signature Size | Smaller (~666 bytes) | Larger (~2,420+ bytes) |
| Key Generation | Slower | Faster |
| Verification | Fast | Fast |
| Implementation | More complex | Simpler |
| Standardization | NIST Round 3 finalist | NIST standardized |

### Use Case Recommendations
- **Choose Falcon** when signature size is critical
- **Choose ML-DSA** for standardized compliance
- **Consider SPHINCS+** for hash-based security model

## Hybrid Usage

Falcon can be combined with classical signatures:

```rust
use cypheron_core::hybrid::EccFalcon;

// Hybrid ECDSA + Falcon signature
let (hybrid_pk, hybrid_sk) = EccFalcon::keypair()?;
let hybrid_sig = EccFalcon::sign(&hybrid_sk, message)?;
let is_valid = EccFalcon::verify(&hybrid_pk, message, &hybrid_sig)?;
```

## Implementation Details

### NTRU Lattice Structure
- Based on polynomial rings over NTRU lattices
- Uses Gaussian sampling for signature generation
- Rejection sampling ensures security properties

### Floating-Point Considerations
- Implementation uses controlled floating-point arithmetic
- Results are deterministic across platforms
- Special handling for edge cases and rounding

## See Also

- [ML-DSA Digital Signatures](ml-dsa.md) - NIST-standardized alternative
- [SPHINCS+ Digital Signatures](sphincsplus.md) - Hash-based signatures
- [Hybrid Cryptography](../hybrid/overview.md) - Combining schemes
- [Security Model](../security/model.md) - Security considerations