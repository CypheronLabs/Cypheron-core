use crate::sig::dilithium5::engine::Dilithium5Engine;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

pub struct Dilithium5;

impl SignatureEngine for Dilithium5 {
    type PublicKey = <Dilithium5Engine as SignatureEngine>::PublicKey;
    type SecretKey = <Dilithium5Engine as SignatureEngine>::SecretKey;
    type Signature = <Dilithium5Engine as SignatureEngine>::Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        Dilithium5Engine::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        Dilithium5Engine::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Dilithium5Engine::verify(msg, sig, pk)
    }
}

impl SignatureScheme for Dilithium5 {}