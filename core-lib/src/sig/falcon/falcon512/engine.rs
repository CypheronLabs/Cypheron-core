use secrecy::Secret;
use secrecy::ExposeSecret;
use std::ffi::c_void;
use std::mem::MaybeUninit;

use crate::sig::falcon::bindings::*;
use crate::sig::falcon::falcon512::constants::*;
use crate::sig::falcon::falcon512::types::{
    Falcon512PublicKey,
    Falcon512SecretKey,
    Falcon512Signature,
    PublicKey,
    SecretKey,
    Signature,
};
use crate::sig::traits::SignatureEngine;

pub struct Falcon512;

impl SignatureEngine for Falcon512 {
    type PublicKey = Falcon512PublicKey;
    type SecretKey = Falcon512SecretKey;
    type Signature = Falcon512Signature;

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
                pk.as_mut_ptr() as *mut c_void,
                pk.len(),
                sk.as_mut_ptr() as *mut c_void,
                sk.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            );
        }

        (
            PublicKey(pk),
            SecretKey(Secret::new(sk)),
        )
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        let SecretKey(secret) = sk;

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
                secret.expose_secret().as_ptr() as *mut c_void,
                secret.expose_secret().len(),
                msg.as_ptr() as *mut c_void,
                msg.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            );
        }

        Signature(sig)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let Signature(sig_bytes) = sig;
        let PublicKey(pk_bytes) = pk;

        let mut tmp = vec![0u8; FALCON_TMPSIZE_VERIFY];

        unsafe {
            falcon_verify(
                sig_bytes.as_ptr() as *mut c_void,
                sig_bytes.len(),
                FALCON_SIG_COMPRESSED,
                pk_bytes.as_ptr() as *mut c_void,
                pk_bytes.len(),
                msg.as_ptr() as *mut c_void,
                msg.len(),
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            ) == 0
        }
    }
}
