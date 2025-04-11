use secrecy::{Secret, Zeroize};
use crate::sig::dilithium_common::sizes::*;

#[derive(Clone)]
pub struct PublicKey(pub [u8; DILITHIUM2_PUBLIC]);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub Secret<[u8; DILITHIUM2_SECRET]>);

#[derive(Clone)]
pub struct Signature(pub [u8; DILITHIUM2_SIGNATURE]);