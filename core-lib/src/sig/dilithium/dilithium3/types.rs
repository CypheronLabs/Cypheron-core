use crate::sig::dilithium::common::*;
use secrecy::Secret;

#[derive(Clone)]
pub struct PublicKey(pub [u8; DILITHIUM3_PUBLIC]);

pub struct SecretKey(pub Secret<[u8; DILITHIUM3_SECRET]>); // already zeroizes on drop!

#[derive(Clone)]
pub struct Signature(pub [u8; DILITHIUM3_SIGNATURE]);
