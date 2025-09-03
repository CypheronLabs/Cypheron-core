# Basic Examples

Complete working examples to get you started with Cypheron Core.

## Key Encapsulation (KEM) Example

```rust
use cypheron_core::kem::{MlKem768, Kem};
use cypheron_core::SecretBox;

fn kem_example() -> Result<(), Box<dyn std::error::Error>> {
    // Alice generates a keypair
    let (alice_pk, alice_sk) = MlKem768::keypair()?;
    
    // Bob wants to send a secret to Alice
    // He encapsulates using Alice's public key
    let (ciphertext, shared_secret_bob) = MlKem768::encapsulate(&alice_pk)?;
    
    // Alice decapsulates using her secret key
    let shared_secret_alice = MlKem768::decapsulate(&ciphertext, &alice_sk)?;
    
    // Both parties now have the same shared secret
    assert_eq!(
        shared_secret_alice.expose_secret(),
        shared_secret_bob.expose_secret()
    );
    
    println!("Shared secret exchange successful!");
    Ok(())
}
```

## Digital Signature Example

```rust
use cypheron_core::sig::{MlDsa65, SignatureEngine};

fn signature_example() -> Result<(), Box<dyn std::error::Error>> {
    let document = b"Important contract terms...";
    
    // Alice generates signing keys
    let (verify_key, signing_key) = MlDsa65::keypair()?;
    
    // Alice signs the document
    let signature = MlDsa65::sign(document, &signing_key)?;
    
    // Bob verifies Alice's signature
    let is_valid = MlDsa65::verify(document, &signature, &verify_key);
    
    if is_valid {
        println!("Signature is valid - document authenticated!");
    } else {
        println!("Invalid signature - document may be tampered!");
    }
    
    Ok(())
}
```

## Hybrid Signature Example

```rust
use cypheron_core::hybrid::{EccDilithium, HybridEngine, VerificationPolicy};

fn hybrid_example() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Quantum-safe hybrid message";
    
    // Generate hybrid keypair (ECC + ML-DSA)
    let (public_key, secret_key) = EccDilithium::keypair()?;
    
    // Create hybrid signature
    let signature = EccDilithium::sign(message, &secret_key)?;
    
    // Verify with strict policy (both signatures must be valid)
    let strict_valid = EccDilithium::verify_with_policy(
        message,
        &signature,
        &public_key,
        VerificationPolicy::BothRequired
    );
    
    // Verify with relaxed policy (either signature valid)
    let relaxed_valid = EccDilithium::verify_with_policy(
        message,
        &signature,
        &public_key,
        VerificationPolicy::EitherValid
    );
    
    println!("Strict policy result: {}", strict_valid);
    println!("Relaxed policy result: {}", relaxed_valid);
    
    Ok(())
}
```

## Error Handling Example

```rust
use cypheron_core::kem::{MlKem768, Kem, MlKemError};

fn error_handling_example() {
    match MlKem768::keypair() {
        Ok((pk, sk)) => {
            println!("Keys generated successfully");
            
            // Try to encapsulate
            match MlKem768::encapsulate(&pk) {
                Ok((ct, ss)) => {
                    println!("Encapsulation successful");
                    
                    // Try to decapsulate
                    match MlKem768::decapsulate(&ct, &sk) {
                        Ok(decrypted_ss) => {
                            println!("Decapsulation successful");
                        },
                        Err(e) => {
                            eprintln!("Decapsulation failed: {}", e);
                            // Error includes helpful documentation links
                        }
                    }
                },
                Err(e) => eprintln!("Encapsulation failed: {}", e),
            }
        },
        Err(e) => {
            eprintln!("Key generation failed: {}", e);
            // Errors include ERROR-KEM-XXX codes linking to docs
        }
    }
}
```

## Memory Safety Example

```rust
use cypheron_core::kem::{MlKem768, Kem};
use cypheron_core::SecretBox;

fn memory_safety_example() -> Result<(), Box<dyn std::error::Error>> {
    let shared_secret = {
        let (pk, sk) = MlKem768::keypair()?;
        let (ct, ss) = MlKem768::encapsulate(&pk)?;
        
        // Secret key `sk` is automatically zeroized when it goes out of scope
        ss
    }; // Keys are now securely zeroized
    
    // Shared secret is still valid and secure
    println!("Shared secret length: {}", shared_secret.expose_secret().len());
    
    // When shared_secret goes out of scope, it will be zeroized
    Ok(())
}
```

## Complete Application Example

```rust
use cypheron_core::kem::{MlKem768, Kem};
use cypheron_core::sig::{MlDsa65, SignatureEngine};

struct SecureMessage {
    encrypted_data: Vec<u8>,
    signature: Vec<u8>,
}

fn secure_messaging_example() -> Result<(), Box<dyn std::error::Error>> {
    // Alice's keys for encryption
    let (alice_kem_pk, alice_kem_sk) = MlKem768::keypair()?;
    
    // Bob's keys for signing  
    let (bob_sig_pk, bob_sig_sk) = MlDsa65::keypair()?;
    
    let plaintext = b"Confidential message from Bob to Alice";
    
    // Bob encrypts message for Alice
    let (ciphertext, shared_secret) = MlKem768::encapsulate(&alice_kem_pk)?;
    
    // Use shared secret to encrypt data (simplified - in practice use AES-GCM)
    let mut encrypted_data = plaintext.to_vec();
    for (i, byte) in encrypted_data.iter_mut().enumerate() {
        *byte ^= shared_secret.expose_secret()[i % 32];
    }
    
    // Bob signs the encrypted message
    let signature = MlDsa65::sign(&encrypted_data, &bob_sig_sk)?;
    
    let secure_msg = SecureMessage {
        encrypted_data,
        signature,
    };
    
    // Alice receives and verifies the message
    // First verify Bob's signature
    let signature_valid = MlDsa65::verify(
        &secure_msg.encrypted_data,
        &secure_msg.signature,
        &bob_sig_pk
    );
    
    if !signature_valid {
        return Err("Invalid signature!".into());
    }
    
    // Then decrypt using her private key
    let decrypted_secret = MlKem768::decapsulate(&ciphertext, &alice_kem_sk)?;
    
    // Decrypt the message
    let mut decrypted_data = secure_msg.encrypted_data.clone();
    for (i, byte) in decrypted_data.iter_mut().enumerate() {
        *byte ^= decrypted_secret.expose_secret()[i % 32];
    }
    
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted_data));
    
    Ok(())
}

fn main() {
    if let Err(e) = secure_messaging_example() {
        eprintln!("Secure messaging failed: {}", e);
    }
}
```

## Next Steps

- [Algorithm Details](../algorithms/ml-kem.md) - Learn about specific algorithms
- [Security Model](../security/model.md) - Understand security guarantees  
- [Performance Guide](../performance/optimization.md) - Optimize your applications