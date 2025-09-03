# Error Codes Reference

Complete reference for all error codes in Cypheron Core.

## KEM Errors

### ERROR-KEM-001
**Key Generation Entropy Failure**

**Cause:** Insufficient entropy available for key generation.

**Solution:**
```rust
// Ensure your system has adequate entropy
// On Linux: check /proc/sys/kernel/random/entropy_avail
// Consider using hardware RNG if available

use cypheron_core::kem::{MlKem768, Kem};

// Retry with backoff
for attempt in 1..=3 {
    match MlKem768::keypair() {
        Ok(keys) => return Ok(keys),
        Err(e) if attempt < 3 => {
            std::thread::sleep(std::time::Duration::from_millis(100 * attempt));
            continue;
        },
        Err(e) => return Err(e),
    }
}
```

### ERROR-KEM-002  
**Decapsulation Invalid Ciphertext**

**Cause:** Ciphertext was corrupted or not generated with the corresponding public key.

**Solution:**
```rust
use cypheron_core::kem::{MlKem768, Kem};

let (pk, sk) = MlKem768::keypair().unwrap();
let (ct, ss1) = MlKem768::encapsulate(&pk).unwrap();

// Verify ciphertext length before decapsulation
if ct.len() != 1088 { // ML-KEM-768 ciphertext size
    return Err("Invalid ciphertext size");
}

match MlKem768::decapsulate(&ct, &sk) {
    Ok(shared_secret) => { /* success */ },
    Err(e) => {
        // Check if ciphertext is corrupted
        // Verify it was generated with correct public key
        eprintln!("Decapsulation failed: {}", e);
    }
}
```

### ERROR-KEM-003
**Encapsulation Invalid Public Key**

**Cause:** Public key format is invalid or corrupted.

**Solution:**
```rust
// Validate public key before use
use cypheron_core::kem::{MlKem768, Kem};

fn validate_public_key(pk_bytes: &[u8]) -> Result<(), &'static str> {
    if pk_bytes.len() != 1184 { // ML-KEM-768 public key size
        return Err("Invalid public key size");
    }
    // Additional validation logic...
    Ok(())
}

// Use validated public key
if let Err(e) = validate_public_key(&pk_bytes) {
    return Err(format!("Public key validation failed: {}", e));
}
```

## Signature Errors

### ERROR-SIG-001
**Signature Generation Failed**

**Cause:** Internal error during signature generation, possibly due to entropy issues.

**Solution:**
```rust
use cypheron_core::sig::{MlDsa65, SignatureEngine};

let message = b"message to sign";
let (pk, sk) = MlDsa65::keypair().unwrap();

match MlDsa65::sign(message, &sk) {
    Ok(signature) => { /* success */ },
    Err(e) => {
        // Check message size (ML-DSA has no message size limit)
        // Verify secret key integrity
        // Ensure adequate system entropy
        eprintln!("Signature generation failed: {}", e);
    }
}
```

### ERROR-SIG-002
**Signature Verification Failed**

**Cause:** Signature is invalid, message was modified, or wrong public key used.

**Solution:**
```rust
use cypheron_core::sig::{MlDsa65, SignatureEngine};

// Ensure exact message match
let original_message = b"Hello, world!";
let modified_message = b"Hello, world?"; // Note the different punctuation

let (pk, sk) = MlDsa65::keypair().unwrap();
let signature = MlDsa65::sign(original_message, &sk).unwrap();

// This will fail
let valid = MlDsa65::verify(modified_message, &signature, &pk);
assert!(!valid); // Verification fails due to message modification

// This will succeed  
let valid = MlDsa65::verify(original_message, &signature, &pk);
assert!(valid);
```

## Hybrid Errors

### ERROR-HYBRID-001
**Composite Key Generation Failed**

**Cause:** Failure in either classical or post-quantum key generation.

**Solution:**
```rust
use cypheron_core::hybrid::{EccDilithium, HybridEngine};

// Retry hybrid key generation with error isolation
match EccDilithium::keypair() {
    Ok(keys) => { /* success */ },
    Err(e) => {
        // Error could be from ECC or ML-DSA component
        // Check system entropy and crypto library status
        eprintln!("Hybrid key generation failed: {}", e);
        
        // Consider fallback to individual algorithms for debugging
        use cypheron_core::sig::{MlDsa44, SignatureEngine};
        let pq_test = MlDsa44::keypair();
        match pq_test {
            Ok(_) => println!("Post-quantum component working"),
            Err(e) => println!("Post-quantum issue: {}", e),
        }
    }
}
```

## Platform-Specific Errors

### ERROR-PLATFORM-001
**Windows Entropy Source Unavailable**

**Cause:** Windows CryptoAPI is not accessible.

**Solution:**
```rust
// Ensure Windows CryptoAPI is available
// This is rare but can happen in restricted environments

#[cfg(target_os = "windows")]
fn check_windows_crypto() -> Result<(), Box<dyn std::error::Error>> {
    // The library will automatically fallback to other entropy sources
    // but you can manually check availability
    
    use cypheron_core::platform::secure_random_bytes;
    let mut buffer = vec![0u8; 32];
    secure_random_bytes(&mut buffer)?;
    Ok(())
}
```

## Memory Errors

### ERROR-MEM-001
**Secure Memory Allocation Failed**

**Cause:** System cannot allocate secure memory for sensitive operations.

**Solution:**
```rust
// Reduce memory pressure or increase available memory
// Check system memory limits and available RAM

use cypheron_core::kem::{MlKem512, Kem}; // Use smaller variant if needed

// Consider using smaller security parameters temporarily
let (pk, sk) = MlKem512::keypair()?; // Instead of MlKem1024
```

## FFI Errors

### ERROR-FFI-001
**C Library Binding Failed**

**Cause:** Underlying C library call failed.

**Solution:**
```rust
// This indicates an issue with the vendor C implementations
// Usually due to memory corruption or invalid parameters

// Enable debug logging to get more details
std::env::set_var("RUST_LOG", "debug");
env_logger::init();

// The error will include more detailed information in debug mode
```

## Debugging Tips

### Enable Detailed Logging

```rust
// Add to your Cargo.toml
[dependencies]
env_logger = "0.10"

// In your code
fn main() {
    env_logger::init();
    // Your code here - errors will include more details
}
```

### Validate Input Data

```rust
use cypheron_core::kem::{MlKem768, Kem};

fn safe_decapsulate(ct: &[u8], sk: &SecretKey) -> Result<SharedSecret, String> {
    // Validate ciphertext size
    if ct.len() != 1088 {
        return Err(format!("Invalid ciphertext size: expected 1088, got {}", ct.len()));
    }
    
    // Additional validation...
    
    MlKem768::decapsulate(ct, sk)
        .map_err(|e| format!("Decapsulation failed: {}", e))
}
```

### Test with Known Good Data

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_with_known_vectors() {
        // Use NIST test vectors for validation
        // See tests/kat/ directory for examples
        let (pk, sk) = MlKem768::keypair().unwrap();
        let (ct, ss1) = MlKem768::encapsulate(&pk).unwrap();
        let ss2 = MlKem768::decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss1.expose_secret(), ss2.expose_secret());
    }
}
```

## Getting Help

If you encounter an error not covered here:

1. **Check the [FAQ](faq.md)** for common solutions
2. **Enable debug logging** to get more details
3. **Search [GitHub Issues](https://github.com/CypheronLabs/Cypheron-core/issues)**
4. **Create a minimal reproduction case**
5. **File a new issue** with full error details

## See Also

- [Common Issues](common.md) - Frequent problems and solutions
- [Debug Guide](debug.md) - Advanced debugging techniques
- [API Reference](../api/errors.md) - Error type documentation