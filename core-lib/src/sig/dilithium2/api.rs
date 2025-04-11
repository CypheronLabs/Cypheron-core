use crate::sig::dilithium2::engine;
use crate::sig::dilithium2::types::{PublicKey, SecretKey, Signature};
use crate::sig::traits::SignatureScheme;
use super::bindings::*;

pub struct Dilithium2;

impl SignatureScheme for Dilithium2 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        engine::keypair(pqcrystals_dilithium2_ref_keypair)
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        engine::sign(pqcrystals_dilithium2_ref_sign, msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        engine::verify(pqcrystals_dilithium2_ref_verify, msg, sig, pk)
    }
}
