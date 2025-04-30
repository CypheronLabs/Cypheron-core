use secrecy::Secret;
use std::mem::MaybeUninit;

use crate::sig::falcon::falcon1024::constants::*;
use crate::sig::falcon::bindings::*;
use crate::sig::traits::SignatureEngine;

pub struct Falcon1024;

impl SignatureEngine for Falcon1024 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; FALCON_PUBLIC];
        let mut sk = [0u8; FALCON_SECRET];
        let mut tmp = vec![0u8; FALCON_TMPSIZE_KEYGEN];
        let mut rng = MaybeUninit::uninit();

        unsafe {
            shake256_init_prng_from_system(rng.as_mut_ptr());
            falcon_keygen_make(
                rng.as_mut_ptr(),
                FALCON_LOGN as u32,
                sk.as_mut_ptr() as *mut _,
                sk.len(),
                pk.as_mut_ptr() as *mut _,
                pk.len(),
                tmp.as_mut_ptr() as *mut _,
                tmp.len(),
            );
        }

        (PublicKey(pk), SecretKey(Secret::new(sk)))
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        let mut sig = [0u8; FALCON_SIGNATURE];
        let mut siglen = 0usize;
        let mut tmp = vec![0u8; FALCON_TMPSIZE_SIGNDYN];
        let mut rng = MaybeUninit::uninit();

        unsafe {
            shake256_init_prng_from_system(rng.as_mut_ptr());
            falcon_sign_dyn(
                rng.as_mut_ptr(),
                sig.as_mut_ptr() as *mut _,
                &mut siglen,
                FALCON_SIG_COMPRESSED,
                sk.0.expose_secret().as_ptr() as *const _,
                sk.0.expose_secret().len(),
                msg.as_ptr() as *const _,
                msg.len(),
                tmp.as_mut_ptr() as *mut _,
                tmp.len(),
            );
        }

        Signature(sig)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let mut tmp = vec![0u8; FALCON_TMPSIZE_VERIFY];

        unsafe {
            falcon_verify(
                sig.0.as_ptr() as *const _,
                sig.0.len(),
                FALCON_SIG_COMPRESSED,
                pk.0.as_ptr() as *const _,
                pk.0.len(),
                msg.as_ptr() as *const _,
                msg.len(),
                tmp.as_mut_ptr() as *mut _,
                tmp.len(),
            ) == 0
        }
    }
}
