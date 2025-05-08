use super::engine;
use super::types::{PublicKey, SecretKey, Signature, Seed};
use crate::sig::sphincs::errors::SphincsError;

pub const ALGORITHM_NAME: &str = "SPHINCS+-SHA2-256s-robust";

pub fn public_key_bytes() -> usize { 
    engine::public_key_bytes() 
}
pub fn secret_key_bytes() -> usize { 
    engine::secret_key_bytes() 
}
pub fn signature_bytes() -> usize { 
    engine::signature_bytes() 
}
pub fn seed_bytes() -> usize { 
    engine::seed_bytes() 
}

pub fn keypair_from_seed(seed_bytes: &[u8]) -> Result<(PublicKey, SecretKey), SphincsError> {
    let seed = Seed::from_bytes(seed_bytes)?;
    engine::keypair_from_seed_generate(&seed)
}

pub fn keypair() -> Result<(PublicKey, SecretKey), SphincsError> {
    engine::keypair_generate()
}

pub fn sign_detached(message: &[u8], sk: &SecretKey) -> Result<Signature, SphincsError> {
    engine::sign_detached_create(message, sk)
}

pub fn verify_detached(
    signature: &Signature,
    message: &[u8],
    pk: &PublicKey,
) -> Result<(), SphincsError> {
    engine::verify_detached_check(signature, message, pk)
}

pub fn sign_combined(message: &[u8], sk: &SecretKey) -> Result<Vec<u8>, SphincsError> {
    engine::sign_combined_create(message, sk)
}

pub fn open_combined(signed_message: &[u8], pk: &PublicKey) -> Result<Vec<u8>, SphincsError> {
    engine::open_combined_verify(signed_message, pk)
}
