use axum::extract::{Path, Json};
use crate::{models::kem::*, validation};
use crate::services::kem_service::KemService;
use crate::error::AppError;
use core_lib::kem::KemVariant;
use crate::utils::encoding::encode_struct_base64;
use serde_json::json;

pub async fn keygen(Path(variant): Path<String>) -> Result<Json<KeypairResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    let variant = parse_variant(&variant)?;
    let (pk, sk) = KemService::generate_keypair(variant)?;
    Ok(Json(KeypairResponse { 
        pk: pk.clone(), 
        sk: sk.clone(),
        format: "base64".to_string(),
        pk_hex: None, 
        sk_hex: None,
    }))
}

pub async fn encapsulate(
    Path(variant): Path<String>,
    Json(payload): Json<EncapsulateRequest>,
) -> Result<Json<EncapsulateResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_base64_key(&payload.pk)?;
    
    let variant = parse_variant(&variant)?;
    let (ct, ss) = KemService::encapsulate(variant, &payload.pk)?;
    Ok(Json(EncapsulateResponse { 
        ct, 
        ss,
        format: payload.format,
    }))
}

pub async fn decapsulate(
    Path(variant): Path<String>,
    Json(payload): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_base64_key(&payload.sk)?;
    validation::validate_base64_key(&payload.ct)?; 
    
    let variant = parse_variant(&variant)?;
    let ss = KemService::decapsulate(variant, &payload.ct, &payload.sk)?;
    Ok(Json(DecapsulateResponse { ss, format: payload.format }))
}

pub async fn variant_info(Path(variant): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
    validation::validate_path_parameter(&variant)?;
    let variant_enum = parse_variant(&variant)?;
    
    let info = json!({
        "variant": variant,
        "algorithm": match variant_enum {
            KemVariant::Kyber512 => "Kyber-512",
            KemVariant::Kyber768 => "Kyber-768", 
            KemVariant::Kyber1024 => "Kyber-1024",
        },
        "security_level": match variant_enum {
            KemVariant::Kyber512 => 1,
            KemVariant::Kyber768 => 3,
            KemVariant::Kyber1024 => 5,
        },
        "key_sizes": match variant_enum {
            KemVariant::Kyber512 => json!({"public_key": 800, "secret_key": 1632, "ciphertext": 768, "shared_secret": 32}),
            KemVariant::Kyber768 => json!({"public_key": 1184, "secret_key": 2400, "ciphertext": 1088, "shared_secret": 32}),
            KemVariant::Kyber1024 => json!({"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32}),
        },
        "supported_formats": ["base64", "hex", "base64url"],
        "endpoints": [
            format!("/kem/{}/keygen", variant),
            format!("/kem/{}/encapsulate", variant),
            format!("/kem/{}/decapsulate", variant),
        ]
    });
    
    let encoded_info = encode_struct_base64(&info)?;
    let response = json!({
        "info": info,
        "encoded_info": encoded_info,
        "note": "The 'encoded_info' field demonstrates struct encoding - it contains the same data as 'info' but base64-encoded as JSON"
    });
    
    Ok(Json(response))
}

fn parse_variant(s: &str) -> Result<KemVariant, AppError> {
    match s {
        "kyber512" => Ok(KemVariant::Kyber512),
        "kyber768" => Ok(KemVariant::Kyber768),
        "kyber1024" => Ok(KemVariant::Kyber1024),
        _ => Err(AppError::InvalidVariant),
    }
}