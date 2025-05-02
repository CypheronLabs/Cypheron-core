use crate::sig::dilithium::dilithium5::bindings::*;
use crate::sig::dilithium::dilithium5::types::*;
use crate::sig::dilithium::common::*;
use crate::sig::traits::SignatureEngine;
use secrecy::{ExposeSecret, Secret};
use std::mem::MaybeUninit;

pub struct Dilithium5Engine;

impl SignatureEngine for Dilithium5Engine {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = MaybeUninit::<[u8; DILITHIUM5_PUBLIC]>::uninit();
        let mut sk = MaybeUninit::<[u8; DILITHIUM5_SECRET]>::uninit();
        unsafe {
            pqcrystals_dilithium5_ref_keypair(
                pk.as_mut_ptr() as *mut u8,
                sk.as_mut_ptr() as *mut u8,
            );
            (
                PublicKey(pk.assume_init()),
                SecretKey(Secret::new(sk.assume_init())),
            )
        }
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        let mut sig = MaybeUninit::<[u8; DILITHIUM5_SIGNATURE]>::uninit();
        let mut siglen = 0usize;
        unsafe {
            pqcrystals_dilithium5_ref_signature(
                sig.as_mut_ptr() as *mut u8,
                &mut siglen,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(), // ctx
                0,                // ctxlen
                sk.0.expose_secret().as_ptr(),
            );
            Signature(sig.assume_init())
        }
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        unsafe {
            pqcrystals_dilithium5_ref_verify(
                sig.0.as_ptr(),
                sig.0.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(), // ctx
                0,                // ctxlen
                pk.0.as_ptr(),
            ) == 0
        }
    }
}
