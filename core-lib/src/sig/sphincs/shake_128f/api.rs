use super::engine::SphincsPlusShake128fSimpleEngine;
use super::types::{PublicKey, SecretKey, Signature};
use crate::sig::sphincs::errors::SphincsPlusError;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

#[derive(Clone, Debug, Copy, Default)]
pub struct SphincsPlusShake128fSimple;

impl SignatureEngine for SphincsPlusShake128fSimple {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = SphincsPlusError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        Ok(SphincsPlusShake128fSimpleEngine::keypair()?)
    }
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        SphincsPlusShake128fSimpleEngine::sign(msg, sk)
    }
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        SphincsPlusShake128fSimpleEngine::verify(msg, sig, pk)
    }
}
impl SignatureScheme for SphincsPlusShake128fSimple {}