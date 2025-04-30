use crate::sig::dilithium::dilithium2::engine::Dilithium2Engine;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

pub struct Dilithium2;

impl SignatureEngine for Dilithium2 {
    type PublicKey = <Dilithium2Engine as SignatureEngine>::PublicKey;
    type SecretKey = <Dilithium2Engine as SignatureEngine>::SecretKey;
    type Signature = <Dilithium2Engine as SignatureEngine>::Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        Dilithium2Engine::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        Dilithium2Engine::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Dilithium2Engine::verify(msg, sig, pk)
    }
}

impl SignatureScheme for Dilithium2 {}