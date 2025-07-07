pub mod falcon;          
pub mod sphincs;         
pub mod traits;          
pub mod dilithium;       

// NIST FIPS 204 Compliant ML-DSA (Module Lattice Digital Signature Algorithm) exports
pub use dilithium::dilithium2::Dilithium2 as MlDsa44;
pub use dilithium::dilithium3::Dilithium3 as MlDsa65; 
pub use dilithium::dilithium5::Dilithium5 as MlDsa87;

// Deprecated aliases for backward compatibility - will be removed in future versions
#[deprecated(since = "0.2.0", note = "Use MlDsa44 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium2::Dilithium2; 
#[deprecated(since = "0.2.0", note = "Use MlDsa65 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium3::Dilithium3; 
#[deprecated(since = "0.2.0", note = "Use MlDsa87 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium5::Dilithium5;

// FIPS 205 compliant SPHINCS+ → SLH-DSA naming (future implementation)
// pub use sphincs::haraka_192f::SphincsHaraka192f as SlhDsaHaraka192f;
// pub use sphincs::sha2_256s::SphincsSha2256s as SlhDsaSha2256s;

pub use falcon::falcon512::Falcon512;
pub use falcon::falcon1024::Falcon1024;

pub use traits::SignatureScheme;
