use axum::{extract::{Path, Json}};
use crate::{models::sig::*};
use crate::utils::encoding::encode_base64;
use crate::services::sig_service::SigService;
use crate::error::AppError;
use crate::models::sig::parse_sig_variant;
use crate::services::sig_service::AnySignature;

fn encode_signature(sig: AnySignature) -> String {
    match sig {
        AnySignature::Dilithium2(s) => encode_base64(&s.0),
        AnySignature::Dilithium3(s) => encode_base64(&s.0),
        AnySignature::Dilithium5(s) => encode_base64(&s.0),
        AnySignature::Falcon512(s) => encode_base64(&s.0),
        AnySignature::Falcon1024(s) => encode_base64(&s.0),
        AnySignature::Haraka192f(s) => encode_base64(s.as_bytes()),
        AnySignature::Sha2_256s(s) => encode_base64(s.as_bytes()),
        AnySignature::Shake128f(s) => encode_base64(s.as_bytes()),
    }
}

pub async fn keygen(Path(variant): Path<String>) -> Result<Json<KeypairResponse>, AppError> {
    let variant = parse_sig_variant(&variant)?;
    let keypair = SigService::generate_keypair(variant)?;
    Ok(Json(keypair))
}
pub async fn sign(
    Path(variant): Path<String>,
    Json(payload): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    let variant = parse_sig_variant(&variant)?;
    let signature = SigService::sign(variant, &payload.message, &payload.sk)?;
    let signature = encode_signature(signature);
    Ok(Json(SignResponse { signature }))
}
pub async fn verify(
    Path(variant): Path<String>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let variant = parse_sig_variant(&variant)?;
    let valid = SigService::verify(variant, &payload.message, &payload.signature, &payload.pk)?;
    Ok(Json(VerifyResponse { valid }))
}