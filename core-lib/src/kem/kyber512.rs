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

pub struct KyberSecretKey(pub [u8; sizes::KYBER512_SECRET]);

#[derive(Clone)]
pub struct KyberPublicKey(pub [u8; sizes::KYBER512_PUBLIC]);

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

pub struct Kyber512;

impl Kyber512 {
    pub fn variant() -> KemVariant {
        KemVariant::Kyber512
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::KYBER512_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for Kyber512 {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::KYBER512_SHARED]>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; sizes::KYBER512_PUBLIC];
        let mut sk = [0u8; sizes::KYBER512_SECRET];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        
        if result != 0 {
            pk.zeroize();
            sk.zeroize();
            panic!("Kyber512 key generation failed with code: {}", result);
        }
        
        (KyberPublicKey(pk), KyberSecretKey(sk))
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        if pk.0.len() != sizes::KYBER512_PUBLIC {
            panic!("Invalid public key length: expected {}, got {}", 
                   sizes::KYBER512_PUBLIC, pk.0.len());
        }
        
        let mut ct = vec![0u8; sizes::KYBER512_CIPHERTEXT];
        let mut ss = [0u8; sizes::KYBER512_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
        };
        
        if result != 0 {
            ss.zeroize();
            panic!("Kyber512 encapsulation failed with code: {}", result);
        }
        
        (ct, SecretBox::new(ss.into()))
    }

    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
        if ct.len() != sizes::KYBER512_CIPHERTEXT {
            panic!("Invalid ciphertext length: expected {}, got {}", 
                   sizes::KYBER512_CIPHERTEXT, ct.len());
        }
        if sk.0.len() != sizes::KYBER512_SECRET {
            panic!("Invalid secret key length: expected {}, got {}", 
                   sizes::KYBER512_SECRET, sk.0.len());
        }
        
        let mut ss = [0u8; sizes::KYBER512_SHARED];
        
        let result = unsafe {
            pqcrystals_kyber512_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr())
        };
        
        if result != 0 {
            ss.zeroize();
            panic!("Kyber512 decapsulation failed with code: {}", result);
        }
        
        SecretBox::new(ss.into())
    }
}
