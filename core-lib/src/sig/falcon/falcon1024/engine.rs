use secrecy::{ExposeSecret, SecretBox};
use std::ffi::c_void;
use std::mem::MaybeUninit;

use crate::sig::falcon::bindings::*;
use crate::sig::falcon::falcon1024::constants::*;
use crate::sig::falcon::falcon1024::types::{
    Falcon1024PublicKey, Falcon1024SecretKey, Falcon1024Signature, PublicKey, SecretKey, Signature,
};
// Use errors from parent module
use crate::sig::falcon::errors::FalconErrors;
// Use the trait
use crate::sig::traits::SignatureEngine;
use libc::c_int;

#[derive(Debug, Clone, Copy, Default)]
pub struct Falcon1024Engine;

impl SignatureEngine for Falcon1024Engine {
    type PublicKey = Falcon1024PublicKey;
    type SecretKey = Falcon1024SecretKey;
    type Signature = Falcon1024Signature;
    type Error = FalconErrors;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; FALCON_PUBLIC];
        let mut sk = [0u8; FALCON_SECRET];
        let mut tmp = vec![0u8; FALCON_TMPSIZE_KEYGEN];
        let mut rng = MaybeUninit::uninit();
        let rng_result: c_int = unsafe { shake256_init_prng_from_system(rng.as_mut_ptr()) };

        if rng_result != 0 {
            return Err(FalconErrors::RngInitializationFailed);
        }
        let keygen_result: c_int = unsafe {
            falcon_keygen_make(
                rng.as_mut_ptr(),
                FALCON_LOGN as u32,
                sk.as_mut_ptr() as *mut c_void,
                sk.len(),
                pk.as_mut_ptr() as *mut c_void,
                pk.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            )
        };

        if keygen_result != 0 {
            return Err(FalconErrors::KeyGenerationFailed);
        }
        Ok((PublicKey(pk), SecretKey(SecretBox::new(Box::from(sk)))))
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let sk_bytes = sk.0.expose_secret();

        let mut sig = [0u8; FALCON_SIGNATURE];
        let mut siglen: usize = FALCON_SIGNATURE;
        let mut tmp = vec![0u8; FALCON_TMPSIZE_SIGNDYN];
        let mut rng = MaybeUninit::uninit();

        let rng_result: c_int = unsafe { shake256_init_prng_from_system(rng.as_mut_ptr()) };
        if rng_result != 0 {
            return Err(FalconErrors::RngInitializationFailed);
        }

        let sign_result: c_int = unsafe {
            falcon_sign_dyn(
                rng.as_mut_ptr(),
                sig.as_mut_ptr() as *mut _,
                &mut siglen,
                FALCON_SIG_COMPRESSED,
                sk_bytes.as_ptr() as *const c_void,
                sk_bytes.len(),
                msg.as_ptr() as *const c_void,
                msg.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            )
        };

        if sign_result != 0 {
            return Err(FalconErrors::SigningFailed);
        }

        // Truncate signature to actual length
        let mut actual_sig = [0u8; FALCON_SIGNATURE];
        actual_sig[..siglen].copy_from_slice(&sig[..siglen]);
        if siglen < FALCON_SIGNATURE {
            // Zero out unused bytes
            actual_sig[siglen..].fill(0);
        }
        Ok(Signature(actual_sig))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let sig_bytes = &sig.0;
        let pk_bytes = &pk.0;

        // Find actual signature length by looking for the first non-zero trailing byte
        let mut actual_sig_len = sig_bytes.len();
        while actual_sig_len > 0 && sig_bytes[actual_sig_len - 1] == 0 {
            actual_sig_len -= 1;
        }

        // Falcon signatures should have a minimum length
        if actual_sig_len < 40 {
            actual_sig_len = sig_bytes.len(); // fallback to full length
        }

        let mut tmp = vec![0u8; FALCON_TMPSIZE_VERIFY];

        // Check return code directly
        let verify_result: c_int = unsafe {
            falcon_verify(
                sig_bytes.as_ptr() as *const c_void,
                actual_sig_len,
                FALCON_SIG_COMPRESSED,
                pk_bytes.as_ptr() as *const c_void,
                pk_bytes.len(),
                msg.as_ptr() as *const c_void,
                msg.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            )
        };
        verify_result == 0
    }
}
