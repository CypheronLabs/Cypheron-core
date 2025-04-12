use crate::sig::dilithium_common::sizes::*;
use secrecy::Secret;

#[derive(Clone)]
pub struct PublicKey(pub [u8; DILITHIUM5_PUBLIC]);

pub struct SecretKey(pub Secret<[u8; DILITHIUM5_SECRET]>); // already zeroizes on drop!

#[derive(Clone)]
pub struct Signature(pub [u8; DILITHIUM5_SIGNATURE]);
