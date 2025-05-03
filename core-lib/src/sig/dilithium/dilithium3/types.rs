use crate::sig::dilithium::common::*;
use secrecy::SecretBox;
use zeroize::Zeroize;
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; DILITHIUM3_PUBLIC]);
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey([... {} bytes ...])", DILITHIUM3_PUBLIC)
    }
}
pub struct SecretKey(pub SecretBox<[u8; DILITHIUM3_SECRET]>);
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED {} bytes])", DILITHIUM3_SECRET)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; DILITHIUM3_SIGNATURE]);
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        let display_len = std::cmp::min(len, 16);
        write!(f, "Signature({:02X?}... {} bytes total ...)", &self.0[..display_len], len)
    }
}
