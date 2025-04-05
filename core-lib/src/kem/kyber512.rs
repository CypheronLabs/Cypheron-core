use crate::kem::sizes;
use crate::kem::{Kem, KemVariant};

use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

#[cfg(not(rust_analyzer))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/kyber512_bindings.rs"));
}
use bindings::*;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KyberSecretKey(pub [u8; sizes::KYBER512_SECRET]);

#[derive(Clone)]
pub struct KyberPublicKey(pub [u8; sizes::KYBER512_PUBLIC]);

pub struct Kyber512;

impl Kyber512 {
    pub fn variant() -> KemVariant {
        KemVariant::Kyber512
    }

    pub fn expose_shared(secret: &Secret<[u8; sizes::KYBER512_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for Kyber512 {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = Secret<[u8; sizes::KYBER512_SHARED]>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; sizes::KYBER512_PUBLIC];
        let mut sk = [0u8; sizes::KYBER512_SECRET];
        unsafe {
            pqcrystals_kyber512_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        (KyberPublicKey(pk), KyberSecretKey(sk))
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let mut ct = vec![0u8; sizes::KYBER512_CIPHERTEXT];
        let mut ss = [0u8; sizes::KYBER512_SHARED];
        unsafe {
            pqcrystals_kyber512_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr());
        }
        (ct, Secret::new(ss))
    }

    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
        let mut ss = [0u8; sizes::KYBER512_SHARED];
        unsafe {
            pqcrystals_kyber512_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr());
        }
        Secret::new(ss)
    }
}
