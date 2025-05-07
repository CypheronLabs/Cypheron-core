use super::bindings::*;
use super::types::*;
use crate::sig::sphincs::common::*;
use crate::sig::sphincs::errors::SphincsError;
use crate::sig::traits::SignatureEngine;

use secrecy::{ExposeSecret, SecretBox};
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, Default)]
pub struct SphincsShake128fEngine;

impl SignatureEngine for SphincsShake128fEngine {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = SphincsError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = MaybeUninit::<[u8; SPHINCS_SHAKE_128F_PUBLIC]>::uninit();
        let mut sk = MaybeUninit::<[u8; SPHINCS_SHAKE_128F_SECRET]>::uninit();

        let result = unsafe {
            pqcrystals_sphincs_haraka_128f_simple_keypair(
                pk.as_mut_ptr() as *mut u8,
                sk.as_mut_ptr() as *mut u8,
            )
        };
        match result {
            0 => {
                let pk = unsafe { pk.assume_init() };
                let sk = unsafe { sk.assume_init() };
                Ok(
                    (
                        PublicKey(pk),
                        SecretKey(SecretBox::new(sk.into())),
                    ),
                )
            },
            i32::MIN..=-1_i32 | 1_i32..=i32::MAX => {
                Err(SphincsError::KeyGenerationInternalError)
            }
        }
    }
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let mut sig = MaybeUninit::<[u8; SPHINCS_SHAKE_128F_SIGNATURE]>::uninit();
        let mut siglen = 0usize;
        let sk_bytes = sk.0.expose_secret();

        let result = unsafe {
            pqcrystals_sphincs_haraka_128f_simple_signature(
                sig.as_mut_ptr() as *mut u8,
                &mut siglen,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_bytes.as_ptr(),
            )
        };
        match result {
            0 => {
                let sig = unsafe { sig.assume_init() };
                Ok(Signature(sig))
            },
            i32::MIN..=-1_i32 | 1_i32..=i32::MAX => {
                Err(SphincsError::SigningInternalError)
            }
        }
    }
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let pk_bytes = pk.0;
        let sig_bytes = sig.0;

        let result = unsafe {
            pqcrystals_sphincs_haraka_128f_simple_verify(
                sig_bytes.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                pk_bytes.as_ptr(),
            )
        };
        result == 0
    }
}