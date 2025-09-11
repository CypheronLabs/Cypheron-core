# SPHINCS+ (Digital Signatures)

SPHINCS+ is a hash-based post-quantum digital signature scheme offering conservative security assumptions and no reliance on algebraic problems.

## Overview

SPHINCS+ provides:
- **Conservative Security**: Based only on hash function security
- **No Algebraic Assumptions**: Unlike lattice-based schemes
- **Stateless Operation**: No state management required
- **Multiple Variants**: Different security/performance tradeoffs

## Security Model

SPHINCS+ security relies solely on:
- **Hash Function Security**: SHA-256 or SHAKE-256 collision resistance
- **No Quantum Vulnerability**: Hash functions remain secure against quantum attacks
- **Proven Reduction**: Security reduces to underlying hash function

## Parameter Sets

Cypheron Core implements multiple SPHINCS+ variants:

### SPHINCS+-SHA256 Variants
| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| sphincs-sha256-128s | Level 1 (small sig) | 32 bytes | 64 bytes | 7,856 bytes |
| sphincs-sha256-128f | Level 1 (fast) | 32 bytes | 64 bytes | 17,088 bytes |
| sphincs-sha256-192s | Level 3 (small sig) | 48 bytes | 96 bytes | 16,224 bytes |
| sphincs-sha256-192f | Level 3 (fast) | 48 bytes | 96 bytes | 35,664 bytes |
| sphincs-sha256-256s | Level 5 (small sig) | 64 bytes | 128 bytes | 29,792 bytes |
| sphincs-sha256-256f | Level 5 (fast) | 64 bytes | 128 bytes | 49,856 bytes |

### SPHINCS+-SHAKE256 Variants
| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| sphincs-shake256-128s | Level 1 (small sig) | 32 bytes | 64 bytes | 7,856 bytes |
| sphincs-shake256-128f | Level 1 (fast) | 32 bytes | 64 bytes | 17,088 bytes |
| sphincs-shake256-192s | Level 3 (small sig) | 48 bytes | 96 bytes | 16,224 bytes |
| sphincs-shake256-192f | Level 3 (fast) | 48 bytes | 96 bytes | 35,664 bytes |
| sphincs-shake256-256s | Level 5 (small sig) | 64 bytes | 128 bytes | 29,792 bytes |
| sphincs-shake256-256f | Level 5 (fast) | 64 bytes | 128 bytes | 49,856 bytes |

## Basic Usage

### Key Generation
```rust
use cypheron_core::sig::{SphincsPlusSha256128s, DigitalSignature};

// Generate a new keypair
let (public_key, secret_key) = SphincsPlusSha256128s::keypair()?;
```

### Message Signing
```rust
let message = b"SPHINCS+ hash-based signature";

// Sign the message
let signature = SphincsPlusSha256128s::sign(&secret_key, message)?;
```

### Signature Verification
```rust
// Verify the signature
let is_valid = SphincsPlusSha256128s::verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## Variant Selection

### Small vs Fast Variants
```rust
use cypheron_core::sig::{SphincsPlusSha256128s, SphincsPlusSha256128f};

// Small signature variant (slower, smaller signatures)
let (pk_s, sk_s) = SphincsPlusSha256128s::keypair()?;
let sig_s = SphincsPlusSha256128s::sign(&sk_s, message)?;
println!("Small signature: {} bytes", sig_s.len());

// Fast variant (faster, larger signatures)  
let (pk_f, sk_f) = SphincsPlusSha256128f::keypair()?;
let sig_f = SphincsPlusSha256128f::sign(&sk_f, message)?;
println!("Fast signature: {} bytes", sig_f.len());
```

### SHA-256 vs SHAKE-256
```rust
use cypheron_core::sig::{SphincsPlusSha256128s, SphincsPlusShake256128s};

// SHA-256 based variant
let (pk_sha, sk_sha) = SphincsPlusSha256128s::keypair()?;

// SHAKE-256 based variant
let (pk_shake, sk_shake) = SphincsPlusShake256128s::keypair()?;

// Both provide equivalent security, choose based on:
// - SHA-256: Wider acceptance, NIST standard
// - SHAKE-256: More flexible, part of SHA-3 family
```

## Advanced Usage

### Deterministic Key Generation
```rust
use cypheron_core::sig::SphincsPlusSha256128s;

// Generate keypair from seed
let seed = [0u8; 48];  // SPHINCS+ uses variable seed lengths
let (pk, sk) = SphincsPlusSha256128s::keypair_deterministic(&seed)?;
```

### Context Separation
```rust
// Sign with context for domain separation
let context = b"document-signing-v2";
let signature = SphincsPlusSha256128s::sign_with_context(&secret_key, message, context)?;
let is_valid = SphincsPlusSha256128s::verify_with_context(&public_key, message, &signature, context)?;
```

## Security Considerations

### Conservative Security Model
- **No Algebraic Assumptions**: Security doesn't depend on lattice problems
- **Post-Quantum Safe**: Hash functions remain secure against quantum computers
- **Proven Security**: Well-understood cryptographic foundations

### Recommended Usage
- **Use 128s variants** for applications requiring smaller signatures
- **Use 128f variants** for applications requiring faster signing
- **Use 192s/256s** for higher security requirements
- **Choose SHA-256** for maximum compatibility

### Key Management
```rust
use secrecy::{ExposeSecret, Zeroize};

// Secret keys automatically zeroized on drop
impl Drop for SphincsSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Safe secret key access
secret_key.expose_secret(|key_bytes| {
    SphincsPlusSha256128s::sign_with_raw_key(key_bytes, message)
})
```

## Performance Characteristics

### Typical Performance (x86_64, 3.0 GHz)
| Variant | Key Generation | Sign | Verify |
|---------|----------------|------|--------|
| sha256-128s | ~15ms | ~180ms | ~4ms |
| sha256-128f | ~15ms | ~8ms | ~2ms |
| sha256-192s | ~25ms | ~650ms | ~8ms |
| sha256-192f | ~25ms | ~18ms | ~4ms |
| sha256-256s | ~35ms | ~1.2s | ~12ms |
| sha256-256f | ~35ms | ~35ms | ~6ms |

### Memory Usage
- Small key sizes (32-128 bytes)
- Large signature sizes (7KB-50KB)
- Stack-based operations, no heap allocation

## Error Handling

### Common Errors
```rust
use cypheron_core::error::Error;

match SphincsPlusSha256128s::verify(&public_key, message, &signature) {
    Ok(true) => println!("Valid signature"),
    Ok(false) => println!("Invalid signature"),
    Err(Error::InvalidPublicKey) => println!("Malformed public key"),
    Err(Error::InvalidSignature) => println!("Malformed signature"),
    Err(Error::HashingFailed) => println!("Internal hash computation failed"),
    Err(e) => println!("Other error: {}", e),
}
```

## Interoperability

### NIST Compliance
- Implements NIST Round 3 SPHINCS+ specification
- Compatible with reference implementations
- Passes all official test vectors

### Serialization
```rust
// Serialize keys and signatures
let pk_bytes = public_key.as_bytes();
let sk_bytes = secret_key.expose_secret(|bytes| bytes.to_vec());
let sig_bytes = signature.as_bytes();

// Deserialize from bytes
let public_key = SphincsPublicKey::from_bytes(&pk_bytes)?;
let signature = SphincsSignature::from_bytes(&sig_bytes)?;
```

## Comparison with Other Schemes

### SPHINCS+ vs Lattice-Based Schemes
| Aspect | SPHINCS+ | ML-DSA/Falcon |
|--------|----------|---------------|
| Security Model | Hash functions only | Lattice problems |
| Signature Size | Large (7KB-50KB) | Small (0.7KB-4KB) |
| Key Size | Small (32-128 bytes) | Medium (1-3KB) |
| Speed | Slower | Faster |
| Quantum Resistance | Very conservative | Well-studied |

### Use Case Recommendations
- **Choose SPHINCS+** for maximum conservative security
- **Choose ML-DSA** for practical performance and NIST standardization
- **Choose Falcon** for compact signatures
- **Consider hybrid** for transition periods

## Hybrid Usage

SPHINCS+ can be combined with other schemes:

```rust
use cypheron_core::hybrid::EccSphincs;

// Hybrid ECDSA + SPHINCS+ signature
let (hybrid_pk, hybrid_sk) = EccSphincs::keypair()?;
let hybrid_sig = EccSphincs::sign(&hybrid_sk, message)?;
let is_valid = EccSphincs::verify(&hybrid_pk, message, &hybrid_sig)?;
```

## Implementation Details

### Hash-Based Construction
- Built on one-way hash functions and Merkle trees
- Uses WOTS+ (Winternitz One-Time Signature Plus)
- XMSS-style tree authentication
- No state management required (stateless)

### Parameter Selection
- **"s" variants**: Optimize for smaller signatures
- **"f" variants**: Optimize for faster operations  
- **Security levels**: 128, 192, 256-bit equivalent security
- **Hash functions**: SHA-256 or SHAKE-256

## See Also

- [ML-DSA Digital Signatures](ml-dsa.md) - Lattice-based alternative
- [Falcon Digital Signatures](falcon.md) - Compact lattice-based signatures
- [Hybrid Cryptography](../hybrid/overview.md) - Combining schemes
- [Security Model](../security/model.md) - Security considerations