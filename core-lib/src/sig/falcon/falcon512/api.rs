use super::types::*;
use crate::sig::traits::SignatureEngine;
use crate::sig::falcon::Falcon512;

impl SignatureEngine for Falcon512 {
    type PublicKey = super::types::Falcon512PublicKey;
    type SecretKey = super::types::Falcon512SecretKey;
    type Signature = super::types::Falcon512Signature;

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
