pub mod traits;
pub mod composite;
pub mod schemes;
pub mod ecdsa;

pub use traits::{HybridEngine, HybridScheme};
pub use composite::{CompositeSignature, CompositeKeypair};
pub use schemes::{EccDilithium, EccFalcon, EccSphincs};

/// NIST FIPS Compliant Hybrid Algorithm Variants
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HybridVariant {
    /// ECDSA P-256 + ML-DSA-44 (formerly EccDilithium2) - NIST FIPS 204 compliant
    EccMlDsa44,
    /// ECDSA P-256 + ML-DSA-65 (formerly EccDilithium3) - NIST FIPS 204 compliant
    EccMlDsa65,
    /// ECDSA P-256 + ML-DSA-87 (formerly EccDilithium5) - NIST FIPS 204 compliant
    EccMlDsa87,
    /// ECDSA P-256 + Falcon-512 hybrid scheme
    EccFalcon512,
    /// ECDSA P-256 + Falcon-1024 hybrid scheme
    EccFalcon1024,
    /// ECDSA P-256 + SLH-DSA (formerly EccSphincs) - NIST FIPS 205 compliant
    EccSlhDsa,
    
    // Deprecated variants for backward compatibility - will be removed in future versions
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa44 instead for NIST FIPS 204 compliance")]
    EccDilithium2,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa65 instead for NIST FIPS 204 compliance")]
    EccDilithium3,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa87 instead for NIST FIPS 204 compliance")]
    EccDilithium5,
    #[deprecated(since = "0.2.0", note = "Use EccSlhDsa instead for NIST FIPS 205 compliance")]
    EccSphincs,
}