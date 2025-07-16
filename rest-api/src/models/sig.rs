use serde::{Deserialize, Serialize};
use crate::error::AppError;

#[derive(Deserialize)]
pub struct SignRequest {
    pub message: String,
    pub sk: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub message: String,
    pub signature: String,
    pub pk: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Serialize)]
pub struct KeypairResponse {
    pub pk: String,
    pub sk: String,
}

#[derive(Deserialize)]
pub struct KeypairRequest {
    #[allow(dead_code)]
    pub variant: String,
}

#[derive(Serialize)]
pub struct KeypairResult {
    pub pk: String,
    pub sk: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVariant {
    // NIST FIPS 204 compliant names (ML-DSA)
    MlDsa44,      // Formerly Dilithium2
    MlDsa65,      // Formerly Dilithium3
    MlDsa87,      // Formerly Dilithium5
    
    // Falcon signatures (pending NIST standardization)
    Falcon512,
    Falcon1024,
    
    // NIST FIPS 205 compliant names (SLH-DSA, formerly SPHINCS+)
    SlhDsaHaraka192f,    // Formerly Haraka192f
    SlhDsaSha2256s,      // Formerly Sha2_256s
    SlhDsaShake128f,     // Formerly Shake128f
    
    // Deprecated variants for backward compatibility
    #[deprecated(since = "0.2.0", note = "Use MlDsa44 instead for NIST FIPS 204 compliance")]
    Dilithium2,
    #[deprecated(since = "0.2.0", note = "Use MlDsa65 instead for NIST FIPS 204 compliance")]
    Dilithium3,
    #[deprecated(since = "0.2.0", note = "Use MlDsa87 instead for NIST FIPS 204 compliance")]
    Dilithium5,
    #[deprecated(since = "0.2.0", note = "Use SlhDsaHaraka192f instead for NIST FIPS 205 compliance")]
    Haraka192f,
    #[deprecated(since = "0.2.0", note = "Use SlhDsaSha2256s instead for NIST FIPS 205 compliance")]
    Sha2_256s,
    #[deprecated(since = "0.2.0", note = "Use SlhDsaShake128f instead for NIST FIPS 205 compliance")]
    Shake128f,
}

pub fn parse_sig_variant(s: &str) -> Result<SigVariant, AppError> {
    match s {
        // NIST FIPS 204 compliant names (ML-DSA)
        "ml-dsa-44" | "ml_dsa_44" => Ok(SigVariant::MlDsa44),
        "ml-dsa-65" | "ml_dsa_65" => Ok(SigVariant::MlDsa65),
        "ml-dsa-87" | "ml_dsa_87" => Ok(SigVariant::MlDsa87),
        
        // Falcon signatures
        "falcon-512" | "falcon512" => Ok(SigVariant::Falcon512),
        "falcon-1024" | "falcon1024" => Ok(SigVariant::Falcon1024),
        
        // NIST FIPS 205 compliant names (SLH-DSA)
        "slh-dsa-haraka-192f" | "slh_dsa_haraka_192f" => Ok(SigVariant::SlhDsaHaraka192f),
        "slh-dsa-sha2-256s" | "slh_dsa_sha2_256s" => Ok(SigVariant::SlhDsaSha2256s),
        "slh-dsa-shake-128f" | "slh_dsa_shake_128f" => Ok(SigVariant::SlhDsaShake128f),
        
        // Backward compatibility (deprecated)
        "dilithium2" => {
            tracing::warn!("Using deprecated 'dilithium2', please use 'ml-dsa-44' for NIST FIPS 204 compliance");
            Ok(SigVariant::MlDsa44)
        },
        "dilithium3" => {
            tracing::warn!("Using deprecated 'dilithium3', please use 'ml-dsa-65' for NIST FIPS 204 compliance");
            Ok(SigVariant::MlDsa65)
        },
        "dilithium5" => {
            tracing::warn!("Using deprecated 'dilithium5', please use 'ml-dsa-87' for NIST FIPS 204 compliance");
            Ok(SigVariant::MlDsa87)
        },
        "haraka_192f" => {
            tracing::warn!("Using deprecated 'haraka_192f', please use 'slh-dsa-haraka-192f' for NIST FIPS 205 compliance");
            Ok(SigVariant::SlhDsaHaraka192f)
        },
        "sha2_256s" => {
            tracing::warn!("Using deprecated 'sha2_256s', please use 'slh-dsa-sha2-256s' for NIST FIPS 205 compliance");
            Ok(SigVariant::SlhDsaSha2256s)
        },
        "shake_128f" => {
            tracing::warn!("Using deprecated 'shake_128f', please use 'slh-dsa-shake-128f' for NIST FIPS 205 compliance");
            Ok(SigVariant::SlhDsaShake128f)
        },
        
        _ => Err(AppError::InvalidVariant),
    }
}