use crate::kem::sizes;
use crate::kem::{Kem, KemVariant};

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(not(rust_analyzer))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/kyber512_bindings.rs"));
}
use bindings::*;

pub struct MlKemSecretKey(pub [u8; sizes::ML_KEM_512_SECRET]);

// Deprecated alias for backward compatibility
#[deprecated(since = "0.2.0", note = "Use MlKemSecretKey instead for NIST FIPS 203 compliance")]
pub type KyberSecretKey = MlKemSecretKey;

#[derive(Clone)]
pub struct MlKemPublicKey(pub [u8; sizes::ML_KEM_512_PUBLIC]);

// Deprecated alias for backward compatibility
#[deprecated(since = "0.2.0", note = "Use MlKemPublicKey instead for NIST FIPS 203 compliance")]
pub type KyberPublicKey = MlKemPublicKey;

#[derive(Error, Debug)]
pub enum MlKemError {
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },
}

// Deprecated alias for backward compatibility
#[deprecated(since = "0.2.0", note = "Use MlKemError instead for NIST FIPS 203 compliance")]
pub type KyberError = MlKemError;


pub struct MlKem512;

// Deprecated alias for backward compatibility
#[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
pub type Kyber512 = MlKem512;

impl MlKem512 {
    /// Returns the NIST FIPS 203 compliant variant (ML-KEM-512)
    pub fn variant() -> KemVariant {
        KemVariant::MlKem512
    }
    
    /// Returns the deprecated variant for backward compatibility
    #[deprecated(since = "0.2.0", note = "Use variant() instead for NIST FIPS 203 compliance")]
    pub fn legacy_variant() -> KemVariant {
        #[allow(deprecated)]
        KemVariant::Kyber512
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::ML_KEM_512_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for MlKem512 {
    type PublicKey = MlKemPublicKey;
    type SecretKey = MlKemSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::ML_KEM_512_SHARED]>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; sizes::ML_KEM_512_PUBLIC];
        let mut sk = [0u8; sizes::ML_KEM_512_SECRET];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        
        if result != 0 {
            pk.zeroize();
            sk.zeroize();
            panic!("ML-KEM-512 key generation failed with code: {}", result);
        }
        
        (MlKemPublicKey(pk), MlKemSecretKey(sk))
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        if pk.0.len() != sizes::ML_KEM_512_PUBLIC {
            panic!("Invalid public key length: expected {}, got {}", 
                   sizes::ML_KEM_512_PUBLIC, pk.0.len());
        }
        
        let mut ct = vec![0u8; sizes::ML_KEM_512_CIPHERTEXT];
        let mut ss = [0u8; sizes::ML_KEM_512_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
        };
        
        if result != 0 {
            ss.zeroize();
            panic!("ML-KEM-512 encapsulation failed with code: {}", result);
        }
        
        (ct, SecretBox::new(ss.into()))
    }

    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
        if ct.len() != sizes::ML_KEM_512_CIPHERTEXT {
            panic!("Invalid ciphertext length: expected {}, got {}", 
                   sizes::ML_KEM_512_CIPHERTEXT, ct.len());
        }
        if sk.0.len() != sizes::ML_KEM_512_SECRET {
            panic!("Invalid secret key length: expected {}, got {}", 
                   sizes::ML_KEM_512_SECRET, sk.0.len());
        }
        
        let mut ss = [0u8; sizes::ML_KEM_512_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr())
        };
        
        if result != 0 {
            ss.zeroize();
            panic!("ML-KEM-512 decapsulation failed with code: {}", result);
        }
        
        SecretBox::new(ss.into())
    }
}

// Note: Kyber512 is a type alias for MlKem512, so it automatically inherits the Kem implementation
