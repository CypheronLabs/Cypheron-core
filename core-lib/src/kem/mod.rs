// NIST FIPS 203 Compliant ML-KEM modules
pub mod ml_kem_512;
pub mod ml_kem_768;
pub mod ml_kem_1024;
pub mod sizes;

// NIST FIPS 203 Compliant exports - ML-KEM (Module Lattice Key Encapsulation Mechanism)
pub use ml_kem_512::MlKem512;
pub use ml_kem_768::MlKem768;
pub use ml_kem_1024::MlKem1024;

// Deprecated aliases for backward compatibility - will be removed in future versions
#[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
pub use ml_kem_512::MlKem512 as Kyber512;
#[deprecated(since = "0.2.0", note = "Use MlKem768 instead for NIST FIPS 203 compliance")]
pub use ml_kem_768::MlKem768 as Kyber768;
#[deprecated(since = "0.2.0", note = "Use MlKem1024 instead for NIST FIPS 203 compliance")]
pub use ml_kem_1024::MlKem1024 as Kyber1024;

/// NIST FIPS 203 Compliant KEM Algorithm Variants
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KemVariant {
    /// ML-KEM-512: NIST FIPS 203 approved algorithm (formerly Kyber-512)
    MlKem512,
    /// ML-KEM-768: NIST FIPS 203 approved algorithm (formerly Kyber-768)  
    MlKem768,
    /// ML-KEM-1024: NIST FIPS 203 approved algorithm (formerly Kyber-1024)
    MlKem1024,
    
    // Deprecated variants for backward compatibility
    #[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
    Kyber512,
    #[deprecated(since = "0.2.0", note = "Use MlKem768 instead for NIST FIPS 203 compliance")]
    Kyber768,
    #[deprecated(since = "0.2.0", note = "Use MlKem1024 instead for NIST FIPS 203 compliance")]
    Kyber1024,
}

/// NIST FIPS 203 Compliant KEM Trait
pub trait Kem {
    type PublicKey: Clone;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);
    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret;
}
