use secrecy::Secret;
use std::mem::MaybeUninit;

use crate::sig::falcon512::types::*;
use crate::sig::falcon::bindings::*;
use crate::sig::traits::SignatureEngine;
use crate::sig::falcon::common::{SIG_COMPRESSED, logn_from_bit_level};

pub struct Falcon512;

impl SignatureEngine for Falcon512 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let logn = 9;
        let mut pk = [0u8; FALCON512_PUBLIC];
        let mut sk = [0u8; FALCON512_SECRET];
        let mut tmp = vec![0u8; unsafe { FALCON_TMPSIZE_KEYGEN(logn) as usize }];
        let mut rng = MaybeUninit::uninit();

        unsafe {
            shake256_init_prng_from_system(rng.as_mut_ptr());

            falcon_keygen_make(
                rng.as_mut_ptr(),
                logn,
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
        let logn = 9;
        let mut sig = [0u8; FALCON512_SIGNATURE];
        let mut siglen = 0usize;
        let mut tmp = vec![0u8; unsafe { FALCON_TMPSIZE_SIGNDYN(logn) as usize }];
        let mut rng = MaybeUninit::uninit();

        unsafe {
            shake256_init_prng_from_system(rng.as_mut_ptr());

            falcon_sign_dyn(
                rng.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut siglen,
                FALCON_SIG_COMPRESSED,
                sk.0.expose_secret().as_ptr(),
                sk.0.expose_secret().len(),
                msg.as_ptr(),
                msg.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            );
        }

        Signature(sig)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let logn = 9;
        let mut tmp = vec![0u8; unsafe { FALCON_TMPSIZE_VERIFY(logn) as usize }];

        unsafe {
            falcon_verify(
                sig.0.as_ptr(),
                sig.0.len(),
                FALCON_SIG_COMPRESSED,
                pk.0.as_ptr(),
                pk.0.len(),
                msg.as_ptr(),
                msg.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            ) == 0
        }
    }
}
