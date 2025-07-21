use secrecy::SecretBox;
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey([... {} bytes ...])", N)
    }
}

pub struct SecretKey<const N: usize>(pub SecretBox<[u8; N]>);
impl<const N: usize> Zeroize for SecretKey<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED {} bytes])", N)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature<const N: usize>(pub [u8; N]);
impl<const N: usize> fmt::Debug for Signature<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        let display_len = std::cmp::min(len, 16);
        write!(f, "Signature({:02X?}... {} bytes total ...)", &self.0[..display_len], len)
    }
}
use crate::sig::falcon::falcon1024::constants::{FALCON_PUBLIC, FALCON_SECRET, FALCON_SIGNATURE};

pub type Falcon1024PublicKey = PublicKey<FALCON_PUBLIC>;
pub type Falcon1024SecretKey = SecretKey<FALCON_SECRET>;
pub type Falcon1024Signature = Signature<FALCON_SIGNATURE>;
