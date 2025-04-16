use super::types::*;
use crate::sig::falcon::bindings::*;
use crate::sig::traits::SignatureEngine;
use secrecy::Secret;
use std::mem::MaybeUninit;

impl SignatureScheme for Falcon512 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        <Self as crate::sig::traits::SignatureEngine>::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        <Self as crate::sig::traits::SignatureEngine>::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        <Self as crate::sig::traits::SignatureEngine>::verify(msg, sig, pk)
    }
}
