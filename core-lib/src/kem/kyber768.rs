use crate::kem::sizes;
use zeroize::Zeroize;
use secrecy::{Secret, ExposeSecret};
use rand_core::{CryptoRng, RngCore};

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/kyber768_bindings.rs"));
}
use bindings::*;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KyberSecretKey(pub [u8; sizes::KYBER768_SECRET]);

#[derive(Clone)]
pub struct KyberPublicKey(pub [u8; sizes::KYBER768_PUBLIC]);

pub struct Kyber768;

impl Kyber768 {
    pub fn keypair() -> (KyberPublicKey, KyberSecretKey) {
        let mut pk = [0u8; sizes::KYBER768_PUBLIC];
        let mut sk = [0u8; sizes::KYBER768_SECRET];
        unsafe {
            pqcrystals_kyber768_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        (KyberPublicKey(pk), KyberSecretKey(sk))
    }

    pub fn encapsulate(pk: &KyberPublicKey) -> (Vec<u8>, Secret<[u8; sizes::KYBER768_SHARED]>) {
        let mut ct = vec![0u8; sizes::KYBER768_CIPHERTEXT];
        let mut ss = [0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr());
        }
        (ct, Secret::new(ss))
    }

    pub fn decapsulate(ct: &[u8], sk: &KyberSecretKey) -> Secret<[u8; sizes::KYBER768_SHARED]> {
        let mut ss = [0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.as_ptr());
        }
        Secret::new(ss)
    }
}
