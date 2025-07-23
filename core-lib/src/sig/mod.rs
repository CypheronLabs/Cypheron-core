pub mod dilithium;
pub mod falcon;
pub mod sphincs;
pub mod traits;

pub use dilithium::dilithium2::Dilithium2 as MlDsa44;
pub use dilithium::dilithium3::Dilithium3 as MlDsa65;
pub use dilithium::dilithium5::Dilithium5 as MlDsa87;

#[deprecated(since = "0.2.0", note = "Use MlDsa44 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium2::Dilithium2;
#[deprecated(since = "0.2.0", note = "Use MlDsa65 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium3::Dilithium3;
#[deprecated(since = "0.2.0", note = "Use MlDsa87 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium5::Dilithium5;

pub use falcon::falcon1024::Falcon1024;
pub use falcon::falcon512::Falcon512;

pub use traits::SignatureScheme;
