use super::engine::Dilithium5Engine;
use super::types::{PublicKey, SecretKey, Signature};
use crate::sig::dilithium::errors::DilithiumError;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

#[derive(Clone, Debug, Copy, Default)]
pub struct Dilithium5;

impl SignatureEngine for Dilithium5 {
    type PublicKey = PublicKey; 
    type SecretKey = SecretKey; 
    type Signature = Signature; 
    type Error = DilithiumError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        Ok(Dilithium5Engine::keypair()?)
    }
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        Dilithium5Engine::sign(msg, sk)
    }
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Dilithium5Engine::verify(msg, sig, pk)
    }
}

impl SignatureScheme for Dilithium5 {}