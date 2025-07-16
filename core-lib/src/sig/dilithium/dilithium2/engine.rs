use super::bindings::*;
use super::types::*;
use crate::sig::dilithium::common::*;
use crate::sig::dilithium::errors::DilithiumError;
use crate::sig::traits::SignatureEngine;

use secrecy::{ExposeSecret, SecretBox};
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, Default)]
pub struct Dilithium2Engine;

impl SignatureEngine for Dilithium2Engine {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = DilithiumError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; ML_DSA_44_PUBLIC];
        let mut sk = [0u8; ML_DSA_44_SECRET];

        let result = unsafe {
            pqcrystals_dilithium2_ref_keypair(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
            )
        };
        match result {
            0 => {
                // C function succeeded, buffers are now properly initialized
                Ok(
                    (
                        PublicKey(pk),
                        SecretKey(SecretBox::new(sk.into())),
                    ),
                )
            },
            code => {
                Err(DilithiumError::from_c_code(code, "keypair"))
            }
        }
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let mut sig = MaybeUninit::<[u8; ML_DSA_44_SIGNATURE]>::uninit();
        let mut siglen = 0usize;
        let sk_bytes = sk.0.expose_secret();

        let result = unsafe {
            pqcrystals_dilithium2_ref_signature(
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
            }
            code => {
                Err(DilithiumError::from_c_code(code, "sign"))
            }
        }
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let sig_len = sig.0.len();
        let result = unsafe {
            pqcrystals_dilithium2_ref_verify(
                sig.0.as_ptr(),
                sig_len,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                pk.0.as_ptr(),
            )
        };
        result == 0
    }
}
