# ML-DSA (Digital Signatures)

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the NIST-standardized post-quantum digital signature scheme, based on the Dilithium algorithm.

## Overview

ML-DSA is designed to resist attacks from both classical and quantum computers, providing:
- **Quantum Resistance**: Security against Shor's algorithm
- **Efficiency**: Fast signature generation and verification
- **Small Signatures**: Compact signature sizes for practical deployment
- **NIST Standardized**: FIPS 204 compliant implementation

## Security Levels

Cypheron Core implements three ML-DSA variants:

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| ML-DSA-44 | Level 2 (~112-bit) | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | Level 3 (~128-bit) | 1,952 bytes | 4,032 bytes | 3,293 bytes |
| ML-DSA-87 | Level 5 (~256-bit) | 2,592 bytes | 4,896 bytes | 4,595 bytes |

## Basic Usage

### Key Generation
```rust
use cypheron_core::sig::{MlDsa65, DigitalSignature};

// Generate a new keypair
let (public_key, secret_key) = MlDsa65::keypair()?;
```

### Message Signing
```rust
let message = b"Hello, post-quantum world!";

// Sign the message
let signature = MlDsa65::sign(&secret_key, message)?;
```

### Signature Verification
```rust
// Verify the signature
let is_valid = MlDsa65::verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## Advanced Usage

### Deterministic Key Generation
```rust
use cypheron_core::sig::MlDsa65;

// Generate keypair from seed (for testing)
let seed = [42u8; 32];
let (pk, sk) = MlDsa65::keypair_deterministic(&seed)?;
```

### Context Separation
```rust
// Sign with context for domain separation
let context = b"email-signature-v1";
let signature = MlDsa65::sign_with_context(&secret_key, message, context)?;
let is_valid = MlDsa65::verify_with_context(&public_key, message, &signature, context)?;
```

## Security Considerations

### Recommended Usage
- **Use ML-DSA-65** for most applications (128-bit security level)
- **Use ML-DSA-87** for high-security applications requiring 256-bit security
- **Use ML-DSA-44** only for resource-constrained environments

### Key Management
```rust
use secrecy::{ExposeSecret, Zeroize};

// Secret keys are automatically zeroized on drop
impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Access secret key material safely
secret_key.expose_secret(|key_bytes| {
    // Use key_bytes for signing operation
    MlDsa65::sign_with_raw_key(key_bytes, message)
})
```

### Side-Channel Resistance
- Implementation uses constant-time operations where feasible
- Secret key operations avoid data-dependent branches
- Memory access patterns independent of secret values

## Performance Characteristics

### Typical Performance (x86_64, 3.0 GHz)
| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Key Generation | ~95μs | ~120μs | ~160μs |
| Sign | ~180μs | ~250μs | ~380μs |
| Verify | ~85μs | ~110μs | ~150μs |

### Memory Usage
- Stack allocation for all operations
- No dynamic memory allocation required
- Secure automatic cleanup on scope exit

## Error Handling

### Common Errors
```rust
use cypheron_core::error::Error;

match MlDsa65::verify(&public_key, message, &signature) {
    Ok(true) => println!("Valid signature"),
    Ok(false) => println!("Invalid signature"),
    Err(Error::InvalidPublicKey) => println!("Malformed public key"),
    Err(Error::InvalidSignature) => println!("Malformed signature"),
    Err(e) => println!("Other error: {}", e),
}
```

### Input Validation
- All inputs are validated before processing
- Malformed keys/signatures return appropriate errors
- No panics on invalid input data

## Interoperability

### NIST Compliance
- Implements FIPS 204 specification exactly
- Compatible with other FIPS 204 implementations
- Passes all NIST Known Answer Tests (KAT)

### Serialization
```rust
// Serialize keys and signatures
let pk_bytes = public_key.as_bytes();
let sk_bytes = secret_key.expose_secret(|bytes| bytes.to_vec());
let sig_bytes = signature.as_bytes();

// Deserialize from bytes
let public_key = MlDsaPublicKey::from_bytes(&pk_bytes)?;
let signature = MlDsaSignature::from_bytes(&sig_bytes)?;
```

## Hybrid Signatures

ML-DSA can be combined with classical signatures for transitional security:

```rust
use cypheron_core::hybrid::EccDilithium;

// Hybrid ECDSA + ML-DSA signature
let (hybrid_pk, hybrid_sk) = EccDilithium::keypair()?;
let hybrid_sig = EccDilithium::sign(&hybrid_sk, message)?;
let is_valid = EccDilithium::verify(&hybrid_pk, message, &hybrid_sig)?;
```

## See Also

- [Falcon Digital Signatures](falcon.md) - Alternative post-quantum signature scheme
- [SPHINCS+ Digital Signatures](sphincsplus.md) - Hash-based signature scheme  
- [Hybrid Cryptography](../hybrid/overview.md) - Combining classical and post-quantum
- [Security Model](../security/model.md) - Overall security considerations