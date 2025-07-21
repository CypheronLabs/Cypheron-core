use super::bindings::robust_ffi as ffi;
use super::engine;
use super::types::{PublicKey, SecretKey, Seed, Signature};
use crate::sig::sphincs::errors::SphincsError;

pub const ALGORITHM_NAME: &str = "SPHINCS+-Haraka-192f-robust";

pub fn public_key_bytes() -> usize {
    unsafe { ffi::crypto_sign_publickeybytes() as usize }
}
pub fn secret_key_bytes() -> usize {
    unsafe { ffi::crypto_sign_secretkeybytes() as usize }
}
pub fn signature_bytes() -> usize {
    unsafe { ffi::crypto_sign_bytes() as usize }
}
pub fn seed_bytes() -> usize {
    unsafe { ffi::crypto_sign_seedbytes() as usize }
}

pub fn keypair_from_seed(seed_bytes_data: &[u8]) -> Result<(PublicKey, SecretKey), SphincsError> {
    let seed = Seed::from_bytes(seed_bytes_data)?;
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
