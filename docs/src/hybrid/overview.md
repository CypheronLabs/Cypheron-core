# Hybrid Cryptography Overview

Hybrid cryptography combines classical and post-quantum algorithms to provide defense against both current and future cryptographic attacks.

## Why Hybrid?

Hybrid schemes provide multiple layers of security:

1. **Classical Security**: Protection against traditional computing threats
2. **Quantum Resistance**: Protection against quantum computer attacks  
3. **Migration Safety**: Smooth transition from classical to post-quantum
4. **Defense in Depth**: Multiple independent security assumptions

## Hybrid Strategies

### Composite Signatures

Combine classical and post-quantum signature schemes:

```rust
use cypheron_core::hybrid::{EccDilithium, HybridEngine};

// Generate hybrid keypair (ECC + ML-DSA)
let (public_key, secret_key) = EccDilithium::keypair()?;

// Create composite signature  
let message = b"Hybrid signed message";
let signature = EccDilithium::sign(message, &secret_key)?;

// Verification can use different policies
let is_valid = EccDilithium::verify(message, &signature, &public_key);
```

### Verification Policies

Different policies for signature verification:

```rust
use cypheron_core::hybrid::VerificationPolicy;

// Strict: Both signatures must be valid
let strict_valid = EccDilithium::verify_with_policy(
    message,
    &signature, 
    &public_key,
    VerificationPolicy::BothRequired
);

// Relaxed: Either signature can be valid
let relaxed_valid = EccDilithium::verify_with_policy(
    message,
    &signature,
    &public_key, 
    VerificationPolicy::EitherValid
);

// Migration: Prefer post-quantum but accept classical
let migration_valid = EccDilithium::verify_with_policy(
    message,
    &signature,
    &public_key,
    VerificationPolicy::PostQuantumPreferred
);
```

## Security Analysis

### Combined Security Level

The security of hybrid schemes depends on verification policy:

| Policy | Security Level | Description |
|--------|---------------|-------------|
| BothRequired | min(classical, pq) | Weakest component determines security |
| EitherValid | max(classical, pq) | Strongest component determines security |
| PostQuantumPreferred | post-quantum | Prioritizes quantum resistance |

### Attack Scenarios

**Quantum Computer Attack:**
- Classical component: Broken
- Post-quantum component: Secure
- Result with EitherValid: Secure

**Classical Cryptanalysis:**
- Classical component: Potentially broken  
- Post-quantum component: Secure
- Result with EitherValid: Secure

**Post-Quantum Cryptanalysis:**
- Classical component: Secure
- Post-quantum component: Potentially broken
- Result with EitherValid: Secure

## Performance Considerations

### Signature Size

Hybrid signatures combine both signature types:

```rust
// Individual signature sizes (approximate)
// ECDSA P-256: ~64 bytes
// ML-DSA-65: ~3300 bytes  
// Combined: ~3364 bytes

let (pk, sk) = EccDilithium::keypair()?;
let signature = EccDilithium::sign(b"message", &sk)?;

println!("Hybrid signature size: {} bytes", signature.len());
// Output: Hybrid signature size: 3364 bytes
```

### Verification Time

Verification involves both algorithms:

```rust
use std::time::Instant;

let start = Instant::now();
let valid = EccDilithium::verify(message, &signature, &public_key);
let duration = start.elapsed();

println!("Hybrid verification: {:?}", duration);
// Typical: ~0.5ms (classical) + ~0.1ms (post-quantum) = ~0.6ms
```

## Migration Strategies

### Phase 1: Introduction

Start with relaxed verification policy:

```rust
// Accept either classical or post-quantum signatures
let valid = EccDilithium::verify_with_policy(
    message,
    &signature,
    &public_key,
    VerificationPolicy::EitherValid
);
```

### Phase 2: Transition

Require both signatures but log failures:

```rust
let strict_valid = EccDilithium::verify_with_policy(
    message,
    &signature,
    &public_key,
    VerificationPolicy::BothRequired
);

if !strict_valid {
    // Log for monitoring but continue processing
    log::warn!("Hybrid signature verification failed");
    
    // Fallback to relaxed policy during transition
    let relaxed_valid = EccDilithium::verify_with_policy(
        message,
        &signature,
        &public_key,
        VerificationPolicy::EitherValid
    );
    
    return relaxed_valid;
}
```

### Phase 3: Post-Quantum Only

Eventually migrate to pure post-quantum:

```rust
use cypheron_core::sig::{MlDsa65, SignatureEngine};

// Pure post-quantum signatures
let (pk, sk) = MlDsa65::keypair()?;
let signature = MlDsa65::sign(message, &sk)?;
let valid = MlDsa65::verify(message, &signature, &pk);
```

## Configuration Management

### Policy Configuration

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct HybridConfig {
    pub verification_policy: VerificationPolicy,
    pub signature_format: SignatureFormat,
    pub key_rotation_interval: u64, // days
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            verification_policy: VerificationPolicy::EitherValid,
            signature_format: SignatureFormat::Concatenated,
            key_rotation_interval: 90,
        }
    }
}
```

### Environment-Based Configuration

```rust
use std::env;

fn get_verification_policy() -> VerificationPolicy {
    match env::var("CYPHERON_VERIFICATION_POLICY").as_deref() {
        Ok("strict") => VerificationPolicy::BothRequired,
        Ok("relaxed") => VerificationPolicy::EitherValid,
        Ok("pq-preferred") => VerificationPolicy::PostQuantumPreferred,
        _ => VerificationPolicy::EitherValid, // Default
    }
}
```

## Interoperability

### Wire Format

Hybrid signatures can use different encoding formats:

```rust
// Concatenated format: [classical_sig][pq_sig]
// Tagged format: [tag][len][classical_sig][tag][len][pq_sig]
// ASN.1 format: Structured encoding with OIDs
```

### Protocol Integration

Example integration with TLS:

```rust
// Custom signature scheme identifier
const HYBRID_ECC_MLDSA: u16 = 0xFE00;

impl SignatureScheme for EccDilithium {
    fn scheme_id(&self) -> u16 {
        HYBRID_ECC_MLDSA
    }
    
    fn sign(&self, message: &[u8], key: &PrivateKey) -> Vec<u8> {
        // Convert from TLS types to Cypheron types
        let sk = HybridSecretKey::from_tls(key);
        EccDilithium::sign(message, &sk).unwrap()
    }
}
```

## See Also

- [ECC + ML-DSA](ecc-mldsa.md) - Specific hybrid implementation
- [Hybrid KEM](hybrid-kem.md) - Key encapsulation mechanisms  
- [Security Considerations](security.md) - Security analysis