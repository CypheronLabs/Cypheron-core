use crate::sig::dilithium_common::sizes::*;
use secrecy::Secret;

#[derive(Clone)]
pub struct PublicKey(pub [u8; DILITHIUM2_PUBLIC]);

pub struct SecretKey(pub Secret<[u8; DILITHIUM2_SECRET]>); // already zeroizes on drop!

#[derive(Clone)]
pub struct Signature(pub [u8; DILITHIUM2_SIGNATURE]);
