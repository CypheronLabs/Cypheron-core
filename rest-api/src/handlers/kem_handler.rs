use axum::extract::{Path, Json};
use crate::models::kem::*;
use crate::services::kem_service::KemService;
use crate::error::AppError;
use core_lib::kem::KemVariant;

pub async fn keygen(Path(variant): Path<String>) -> Result<Json<KeypairResponse>, AppError> {
    let variant = parse_variant(&variant)?;
    let (pk, sk) = KemService::generate_keypair(variant)?;
    Ok(Json(KeypairResponse { pk, sk }))
}

pub async fn encapsulate(
    Path(variant): Path<String>,
    Json(payload): Json<EncapsulateRequest>,
) -> Result<Json<EncapsulateResponse>, AppError> {
    let variant = parse_variant(&variant)?;
    let (ct, ss) = KemService::encapsulate(variant, &payload.pk)?;
    Ok(Json(EncapsulateResponse { ct, ss }))
}

pub async fn decapsulate(
    Path(variant): Path<String>,
    Json(payload): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, AppError> {
    let variant = parse_variant(&variant)?;
    let ss = KemService::decapsulate(variant, &payload.ct, &payload.sk)?;
    Ok(Json(DecapsulateResponse { ss }))
}

fn parse_variant(s: &str) -> Result<KemVariant, AppError> {
    match s {
        "kyber512" => Ok(KemVariant::Kyber512),
        "kyber768" => Ok(KemVariant::Kyber768),
        "kyber1024" => Ok(KemVariant::Kyber1024),
        _ => Err(AppError::InvalidVariant),
    }
}