# Core Types

This section documents the core types and data structures used throughout Cypheron Core.

## Key Types

### Public Keys

All public key types are `Clone` and can be safely shared:

```rust
use cypheron_core::kem::MlKemPublicKey;
use cypheron_core::sig::MlDsaPublicKey;

// ML-KEM public keys
let pk: MlKemPublicKey = // ... from keypair generation
let pk_clone = pk.clone(); // Safe to clone

// ML-DSA public keys  
let verify_key: MlDsaPublicKey = // ... from keypair generation
```

### Secret Keys

Secret keys are wrapped in `SecretBox` for memory safety:

```rust
use cypheron_core::kem::MlKemSecretKey;
use cypheron_core::sig::MlDsaSecretKey;
use secrecy::ExposeSecret;

// Secret keys are automatically zeroized when dropped
let sk: MlKemSecretKey = // ... from keypair generation

// Access secret data only when needed
let secret_bytes = sk.0.expose_secret();
// sk is automatically zeroized when it goes out of scope
```

## Shared Secrets

Shared secrets from KEM operations are securely managed:

```rust
use cypheron_core::kem::{MlKem768, Kem};
use secrecy::ExposeSecret;

let (pk, sk) = MlKem768::keypair()?;
let (ct, shared_secret) = MlKem768::encapsulate(&pk)?;

// Access shared secret data
let secret_data = shared_secret.expose_secret(); // &[u8; 32]

// shared_secret is zeroized when dropped
```

## Error Types

### KEM Errors

```rust
use cypheron_core::kem::MlKemError;

pub enum MlKemError {
    KeyGenerationEntropyFailure,
    KeyGenerationInternalError,
    EncapsulationInvalidKey,
    EncapsulationInternalError,
    DecapsulationInvalidCiphertext,
    DecapsulationInternalError,
    InvalidCiphertextLength { expected: usize, actual: usize },
    InvalidPublicKeyLength { expected: usize, actual: usize },
    InvalidSecretKeyLength { expected: usize, actual: usize },
    CLibraryError { code: i32 },
}
```

### Signature Errors

```rust
use cypheron_core::sig::MlDsaError;

pub enum MlDsaError {
    KeyGenerationFailed,
    SignatureFailed,
    VerificationFailed,
    InvalidSignatureLength { expected: usize, actual: usize },
    InvalidPublicKeyLength { expected: usize, actual: usize },
    InvalidSecretKeyLength { expected: usize, actual: usize },
    CLibraryError { code: i32 },
}
```

## Trait Definitions

### KEM Trait

```rust
pub trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;
    type Error;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;
    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Result<Self::SharedSecret, Self::Error>;
}
```

### SignatureEngine Trait

```rust
pub trait SignatureEngine {
    type PublicKey;
    type SecretKey;
    type Signature;
    type Error;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn sign(message: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error>;
    fn verify(message: &[u8], signature: &Self::Signature, pk: &Self::PublicKey) -> bool;
}
```

## Size Constants

All algorithm parameters are available as constants:

```rust
use cypheron_core::kem::sizes;
use cypheron_core::sig::sizes as sig_sizes;

// ML-KEM sizes
const ML_KEM_768_PUBLIC: usize = sizes::ML_KEM_768_PUBLIC;     // 1184
const ML_KEM_768_SECRET: usize = sizes::ML_KEM_768_SECRET;     // 2400  
const ML_KEM_768_CIPHERTEXT: usize = sizes::ML_KEM_768_CIPHERTEXT; // 1088
const ML_KEM_768_SHARED: usize = sizes::ML_KEM_768_SHARED;     // 32

// ML-DSA sizes
const ML_DSA_65_PUBLIC: usize = sig_sizes::ML_DSA_65_PUBLIC;   // 1952
const ML_DSA_65_SECRET: usize = sig_sizes::ML_DSA_65_SECRET;   // 4032
```

## Memory Safety Guarantees

### Automatic Zeroization

```rust
use zeroize::Zeroize;

// All secret types implement Zeroize
fn example() {
    let (pk, sk) = MlKem768::keypair().unwrap();
    
    // Use secret key...
    
} // sk is automatically zeroized here when dropped
```

### SecretBox Protection

```rust
use secrecy::{SecretBox, ExposeSecret};

// Secret data is protected until explicitly exposed
let secret = SecretBox::new([1, 2, 3, 4]);

// Only expose when absolutely necessary
let data = secret.expose_secret(); // &[u8]

// secret is zeroized when dropped
```

## Serialization Support

With the `serialize` feature enabled:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct KeyPair {
    public_key: MlKemPublicKey,
    // Note: Secret keys should NOT be serialized in most cases
}

// Serialize public key safely
let json = serde_json::to_string(&public_key)?;

// Deserialize public key  
let pk: MlKemPublicKey = serde_json::from_str(&json)?;
```

## Thread Safety

All public key types are `Send` and `Sync`:

```rust
use std::sync::Arc;
use std::thread;

let (pk, _sk) = MlKem768::keypair().unwrap();
let shared_pk = Arc::new(pk);

// Public keys can be shared across threads
let handles: Vec<_> = (0..4).map(|_| {
    let pk = shared_pk.clone();
    thread::spawn(move || {
        // Use pk in thread...
        MlKem768::encapsulate(&pk)
    })
}).collect();
```

## See Also

- [KEM Operations](kem.md) - Key Encapsulation APIs
- [Signature Operations](signatures.md) - Digital Signature APIs
- [Error Handling](errors.md) - Error types and handling