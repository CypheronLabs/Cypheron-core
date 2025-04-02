pub mod kyber768;
pub mod sizes;

pub use kyber768::{Kyber768, KyberPublicKey, KyberSecretKey};

// Enum for abstract KEM variant usage (optional, future use)
#[derive(Debug, Clone, Copy)]
pub enum KemVariant {
    Kyber768,
    // Kyber512,
    // Kyber1024,
}
// pub trait Kem {
//     fn keypair(&self) -> (...);
//     fn encapsulate(&self, ...);
//     fn decapsulate(&self, ...);
// }