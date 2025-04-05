pub mod kyber1024;
pub mod kyber512;
pub mod kyber768;
pub mod sizes;

pub use kyber1024::Kyber1024;
pub use kyber512::Kyber512;
pub use kyber768::Kyber768;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KemVariant {
    Kyber768,
    Kyber512,
    Kyber1024,
}
pub trait Kem {
    type PublicKey: Clone;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);
    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret;
}
