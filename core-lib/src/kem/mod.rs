pub mod ml_kem_1024;
pub mod ml_kem_512;
pub mod ml_kem_768;
pub mod sizes;

// NIST FIPS 203 Compliant exports - ML-KEM (Module Lattice Key Encapsulation Mechanism)
pub use ml_kem_1024::MlKem1024;
pub use ml_kem_512::MlKem512;
pub use ml_kem_768::MlKem768;

// Deprecated aliases for backward compatibility - will be removed in future versions
#[deprecated(since = "0.2.0", note = "Use MlKem1024 instead for NIST FIPS 203 compliance")]
pub use ml_kem_1024::MlKem1024 as Kyber1024;
#[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
pub use ml_kem_512::MlKem512 as Kyber512;
#[deprecated(since = "0.2.0", note = "Use MlKem768 instead for NIST FIPS 203 compliance")]
pub use ml_kem_768::MlKem768 as Kyber768;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,

    // Deprecated variants for backward compatibility
    #[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
    Kyber512,
    #[deprecated(since = "0.2.0", note = "Use MlKem768 instead for NIST FIPS 203 compliance")]
    Kyber768,
    #[deprecated(since = "0.2.0", note = "Use MlKem1024 instead for NIST FIPS 203 compliance")]
    Kyber1024,
}

pub trait Kem {
    type PublicKey: Clone;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;
    type Error;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn encapsulate(
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;
    fn decapsulate(
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error>;
}
