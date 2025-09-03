# Quick Start Guide

Get up and running with Cypheron Core in minutes.

## Installation

Add cypheron-core to your `Cargo.toml`:

```toml
[dependencies]
cypheron-core = "0.1.0"
```

## Basic KEM Example

Key Encapsulation Mechanisms (KEMs) are used for secure key exchange:

```rust
use cypheron_core::kem::{MlKem768, Kem};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a keypair
    let (public_key, secret_key) = MlKem768::keypair()?;
    
    // Alice encapsulates a shared secret using Bob's public key
    let (ciphertext, shared_secret_alice) = MlKem768::encapsulate(&public_key)?;
    
    // Bob decapsulates the shared secret using his secret key
    let shared_secret_bob = MlKem768::decapsulate(&ciphertext, &secret_key)?;
    
    // Both parties now have the same shared secret
    assert_eq!(shared_secret_alice.expose_secret(), shared_secret_bob.expose_secret());
    
    println!("Key exchange successful!");
    Ok(())
}
```

## Basic Signature Example

Digital signatures provide authentication and non-repudiation:

```rust
use cypheron_core::sig::{MlDsa65, SignatureEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Hello, post-quantum world!";
    
    // Generate signing keypair
    let (public_key, secret_key) = MlDsa65::keypair()?;
    
    // Sign the message
    let signature = MlDsa65::sign(message, &secret_key)?;
    
    // Verify the signature
    let is_valid = MlDsa65::verify(message, &signature, &public_key);
    
    assert!(is_valid);
    println!("Signature verification successful!");
    Ok(())
}
```

## Hybrid Example

Combine classical and post-quantum security:

```rust
use cypheron_core::hybrid::{EccDilithium, HybridEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Hybrid security message";
    
    // Generate hybrid keypair (ECC + ML-DSA)
    let (public_key, secret_key) = EccDilithium::keypair()?;
    
    // Create hybrid signature
    let signature = EccDilithium::sign(message, &secret_key)?;
    
    // Verify with different policies
    use cypheron_core::hybrid::VerificationPolicy;
    
    // Require both classical and post-quantum signatures to be valid
    let strict_valid = EccDilithium::verify_with_policy(
        message, 
        &signature, 
        &public_key, 
        VerificationPolicy::BothRequired
    );
    
    // Accept if either classical OR post-quantum signature is valid
    let relaxed_valid = EccDilithium::verify_with_policy(
        message, 
        &signature, 
        &public_key, 
        VerificationPolicy::EitherValid
    );
    
    println!("Strict policy: {}", strict_valid);
    println!("Relaxed policy: {}", relaxed_valid);
    
    Ok(())
}
```

## Error Handling

Cypheron Core uses structured error types with helpful messages:

```rust
use cypheron_core::kem::{MlKem768, Kem};

match MlKem768::keypair() {
    Ok((pk, sk)) => {
        println!("Keypair generated successfully");
        // Use the keys...
    },
    Err(e) => {
        eprintln!("Key generation failed: {}", e);
        // Error codes like ERROR-KEM-001 link to documentation
        // See troubleshooting/errors.md for complete error reference
    }
}
```

## Memory Safety

All sensitive data is automatically zeroized when dropped:

```rust
use cypheron_core::kem::{MlKem768, Kem};

{
    let (public_key, secret_key) = MlKem768::keypair().unwrap();
    // Use keys...
} // secret_key is automatically zeroized when it goes out of scope
```

## Next Steps

- **[Algorithm Details](../algorithms/ml-kem.md)** - Learn about specific algorithms
- **[API Reference](../api/types.md)** - Complete API documentation
- **[Security Model](../security/model.md)** - Understanding security guarantees
- **[Performance Guide](../performance/optimization.md)** - Optimizing your application

## Production Checklist

Before using in production:

1. Read the [Security Model](../security/model.md)
2. Review [Compliance Requirements](../security/compliance.md)  
3. Set up [Monitoring](../deployment/monitoring.md)
4. Test your [Error Handling](../troubleshooting/common.md)
5. Performance test with [Benchmarking Guide](../performance/benchmarks.md)