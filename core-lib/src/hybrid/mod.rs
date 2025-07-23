pub mod composite;
pub mod ecdsa;
pub mod schemes;
pub mod traits;

pub use composite::{CompositeKeypair, CompositeSignature};
pub use schemes::{EccDilithium, EccFalcon, EccSphincs};
pub use traits::{HybridEngine, HybridScheme};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HybridVariant {
    EccMlDsa44,
    EccMlDsa65,
    EccMlDsa87,
    EccFalcon512,
    EccFalcon1024,
    EccSlhDsa,

    #[deprecated(since = "0.2.0", note = "Use EccMlDsa44 instead for NIST FIPS 204 compliance")]
    EccDilithium2,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa65 instead for NIST FIPS 204 compliance")]
    EccDilithium3,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa87 instead for NIST FIPS 204 compliance")]
    EccDilithium5,
    #[deprecated(since = "0.2.0", note = "Use EccSlhDsa instead for NIST FIPS 205 compliance")]
    EccSphincs,
}
