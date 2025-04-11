use crate::sig::dilithium2::types::{PublicKey, SecretKey, Signature};
use crate::sig::dilithium_common::sizes::*;
use secrecy::ExposeSecret; 

pub fn keypair(
    ffi_keypair: unsafe fn(*mut u8, *mut u8),
) -> (PublicKey, SecretKey) {
    let mut pk = [0u8; DILITHIUM2_PUBLIC];
    let mut sk = [0u8; DILITHIUM2_SECRET];
    unsafe {
        ffi_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }

    let secret = secrecy::Secret::new(sk);
    (PublicKey(pk), SecretKey(secret))
}

pub fn sign(
    ffi_sign: unsafe fn(*mut u8, *mut usize, *const u8, usize, *const u8),
    msg: &[u8],
    sk: &SecretKey,
) -> Signature {
    let mut sig = [0u8; DILITHIUM2_SIGNATURE];
    let mut siglen = 0usize;

    unsafe {
        ffi_sign(
            sig.as_mut_ptr(),
            &mut siglen,
            msg.as_ptr(),
            msg.len(),
            sk.0.expose_secret().as_ptr(), 
        );
    }

    Signature(sig)
}

pub fn verify(
    ffi_verify: unsafe fn(*const u8, usize, *const u8, usize, *const u8) -> i32,
    msg: &[u8],
    sig: &Signature,
    pk: &PublicKey,
) -> bool {
    unsafe {
        ffi_verify(
            msg.as_ptr(),
            msg.len(),
            sig.0.as_ptr(),
            sig.0.len(),
            pk.0.as_ptr(),
        ) == 0
    }
}
