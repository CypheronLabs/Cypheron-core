use crate::kem::sizes;
use crate::kem::{Kem, KemVariant};

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

#[cfg(not(rust_analyzer))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/kyber768_bindings.rs"));
}
use bindings::*;

pub struct KyberSecretKey(pub [u8; sizes::KYBER768_SECRET]);

#[derive(Clone)]
pub struct KyberPublicKey(pub [u8; sizes::KYBER768_PUBLIC]);

pub struct Kyber768;

impl Kyber768 {
    pub fn variant() -> KemVariant {
        KemVariant::Kyber768
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::KYBER768_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for Kyber768 {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::KYBER768_SHARED]>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; sizes::KYBER768_PUBLIC];
        let mut sk = [0u8; sizes::KYBER768_SECRET];
        unsafe {
            pqcrystals_kyber768_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        (KyberPublicKey(pk), KyberSecretKey(sk))
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let mut ct = vec![0u8; sizes::KYBER768_CIPHERTEXT];
        let mut ss = [0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr());
        }
        (ct, SecretBox::new(ss.into()))
    }

    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
        let mut ss = [0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr());
        }
        SecretBox::new(ss.into())
    }
}
