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
    Dilithium2,
    Dilithium3,
    Dilithium5,
    FALCON512,
    FALCON1024,
    Haraka192f,
    Sha2_256s,
    Shake128f,
}

pub fn parse_sig_variant(s: &str) -> Result<SigVariant, AppError> {
    match s {
        "dilithium2" => Ok(SigVariant::Dilithium2),
        "dilithium3" => Ok(SigVariant::Dilithium3),
        "dilithium5" => Ok(SigVariant::Dilithium5),
        "falcon512" => Ok(SigVariant::FALCON512),
        "falcon1024" => Ok(SigVariant::FALCON1024),
        "haraka_192f" => Ok(SigVariant::Haraka192f),
        "sha2_256s" => Ok(SigVariant::Sha2_256s),
        "shake_128f" => Ok(SigVariant::Shake128f),
        _ => Err(AppError::InvalidVariant),
    }
}