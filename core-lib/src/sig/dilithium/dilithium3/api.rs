use crate::sig::dilithium::dilithium3::engine::Dilithium3Engine;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

pub struct Dilithium3;

impl SignatureEngine for Dilithium3 {
    type PublicKey = <Dilithium3Engine as SignatureEngine>::PublicKey;
    type SecretKey = <Dilithium3Engine as SignatureEngine>::SecretKey;
    type Signature = <Dilithium3Engine as SignatureEngine>::Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        Dilithium3Engine::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature {
        Dilithium3Engine::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Dilithium3Engine::verify(msg, sig, pk)
    }
}

impl SignatureScheme for Dilithium3 {}
