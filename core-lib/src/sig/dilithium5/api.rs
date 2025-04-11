use crate::sig::dilithium_common::engine::{self, DilithiumEngine};
use crate::sig::dilithium_common::types::{PublicKey, SecretKey, Signature};
use crate::sig::traits::SignatureScheme;
use super::bindings::*;

pub struct Dilithium5;

impl DilithiumEngine for Dilithium5 {
    const PUBLIC_KEY_BYTES: usize = pqcrystals_dilithium5_ref_PUBLICKEYBYTES;
    const SECRET_KEY_BYTES: usize = pqcrystals_dilithium5_ref_SECRETKEYBYTES;
    const SIGNATURE_BYTES: usize = pqcrystals_dilithium5_ref_BYTES;

    unsafe fn ffi_keypair(pk: *mut u8, sk: *mut u8) {
        pqcrystals_dilithium5_ref_keypair(pk, sk);
    }

    unsafe fn ffi_sign(
        sig: *mut u8,
        siglen: *mut usize,
        msg: *const u8,
        msglen: usize,
        sk: *const u8,
    ){
        pqcrystals_dilithium5_ref_sign(sig, siglen, msg, msglen, sk)
    }

    unsafe fn ffi_verify(
        msg: *const u8,
        msglen: usize,
        sig: *const u8,
        siglen: usize,
        pk: *const u8,
    ) -> i32 {
        pqcrystals_dilithium5_ref_verify(sig, siglen, msg, msglen, pk)
    }
}

impl SignatureScheme for Dilithium5 {
    type PublicKey = PublicKey<Self>;
    type SecretKey = SecretKey<Self>;
    type Signature = Signature<Self>;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        engine::keypair::<Self>()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        engine::sign::<Self>(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        engine::verify::<Self>(msg, sig, pk)
    }
}