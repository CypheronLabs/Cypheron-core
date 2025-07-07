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
    include!(concat!(env!("OUT_DIR"), "/kyber1024_bindings.rs"));
}
use bindings::*;

pub struct KyberSecretKey(pub [u8; sizes::KYBER1024_SECRET]);

#[derive(Clone)]
pub struct KyberPublicKey(pub [u8; sizes::KYBER1024_PUBLIC]);

#[derive(Error, Debug)]
pub enum KyberError {
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },
}

pub struct Kyber1024;

impl Kyber1024 {
    pub fn variant() -> KemVariant {
        KemVariant::Kyber1024
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::KYBER1024_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for Kyber1024 {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::KYBER1024_SHARED]>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; sizes::KYBER1024_PUBLIC];
        let mut sk = [0u8; sizes::KYBER1024_SECRET];
        
        let result = unsafe {
            pqcrystals_kyber1024_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        
        // Kyber C implementation returns 0 on success
        if result != 0 {
            // Zero out buffers on failure for security
            pk.zeroize();
            sk.zeroize();
            panic!("Kyber1024 key generation failed with code: {}", result);
        }
        
        (KyberPublicKey(pk), KyberSecretKey(sk))
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        // Validate input: ensure public key has correct size
        if pk.0.len() != sizes::KYBER1024_PUBLIC {
            panic!("Invalid public key length: expected {}, got {}", 
                   sizes::KYBER1024_PUBLIC, pk.0.len());
        }
        
        let mut ct = vec![0u8; sizes::KYBER1024_CIPHERTEXT];
        let mut ss = [0u8; sizes::KYBER1024_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber1024_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
        };
        
        if result != 0 {
            // Zero out sensitive data on failure
            ss.zeroize();
            panic!("Kyber1024 encapsulation failed with code: {}", result);
        }
        
        (ct, SecretBox::new(ss.into()))
    }

    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
        // Validate inputs
        if ct.len() != sizes::KYBER1024_CIPHERTEXT {
            panic!("Invalid ciphertext length: expected {}, got {}", 
                   sizes::KYBER1024_CIPHERTEXT, ct.len());
        }
        if sk.0.len() != sizes::KYBER1024_SECRET {
            panic!("Invalid secret key length: expected {}, got {}", 
                   sizes::KYBER1024_SECRET, sk.0.len());
        }
        
        let mut ss = [0u8; sizes::KYBER1024_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber1024_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr())
        };
        
        if result != 0 {
            // Zero out potentially corrupted shared secret
            ss.zeroize();
            panic!("Kyber1024 decapsulation failed with code: {}", result);
        }
        
        SecretBox::new(ss.into())
    }
}
