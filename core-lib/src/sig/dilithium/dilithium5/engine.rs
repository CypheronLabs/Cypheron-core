use super::bindings::*;
use super::types::*;
use crate::security::{verify_buffer_initialized, FfiSafe};
use crate::sig::dilithium::common::*;
use crate::sig::dilithium::errors::DilithiumError;
use crate::sig::traits::SignatureEngine;

use secrecy::{ExposeSecret, SecretBox};
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, Default)]
pub struct Dilithium5Engine;

impl SignatureEngine for Dilithium5Engine {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = DilithiumError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; ML_DSA_87_PUBLIC];
        let mut sk = [0u8; ML_DSA_87_SECRET];

        let result = unsafe { pqcrystals_dilithium5_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        match result {
            0 => {
                Ok((PublicKey(pk), SecretKey(SecretBox::new(sk.into()))))
            }
            code => Err(DilithiumError::from_c_code(code, "keypair")),
        }
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        if msg.len() > usize::MAX / 2 {
            return Err(DilithiumError::InvalidInput);
        }
        if !msg.is_valid_for_ffi() && !msg.is_empty() {
            return Err(DilithiumError::InvalidInput);
        }
        
        let mut sig_buffer = [0u8; ML_DSA_87_SIGNATURE];
        let mut siglen = 0usize;
        let sk_bytes = sk.0.expose_secret();

        if sk_bytes.len() != ML_DSA_87_SECRET {
            return Err(DilithiumError::InvalidInput);
        }

        let result = unsafe {
            pqcrystals_dilithium5_ref_signature(
                sig_buffer.as_mut_ptr(),
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
                if siglen == 0 || siglen > ML_DSA_87_SIGNATURE {
                    return Err(DilithiumError::SigningInternalError);
                }
                
                if !verify_buffer_initialized(&sig_buffer[..siglen], siglen) {
                    return Err(DilithiumError::SigningInternalError);
                }

                Ok(Signature(sig_buffer))
            }
            code => Err(DilithiumError::from_c_code(code, "sign")),
        }
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        if msg.len() > usize::MAX / 2 {
            return false;
        }
        if !msg.is_valid_for_ffi() && !msg.is_empty() {
            return false;
        }
        
        if sig.0.len() != ML_DSA_87_SIGNATURE {
            return false;
        }
        if pk.0.len() != ML_DSA_87_PUBLIC {
            return false;
        }
        
        let sig_len = sig.0.len();
        let result = unsafe {
            pqcrystals_dilithium5_ref_verify(
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
