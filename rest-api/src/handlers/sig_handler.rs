use axum::{extract::{Path, Json, State}};
use crate::{models::sig::*, validation};
use crate::utils::encoding::encode_base64;
use crate::services::sig_service::SigService;
use crate::error::AppError;
use crate::models::sig::parse_sig_variant;
use crate::services::sig_service::AnySignature;
use crate::security::{AuditLogger, AuditEvent, AuditEventType};
use serde_json::json;
use std::sync::Arc;

fn encode_signature(sig: AnySignature) -> String {
    match sig {
        // The AnySignature enum uses the underlying implementation types,
        // so we still match on the same patterns regardless of NIST naming
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

pub async fn keygen(
    Path(variant): Path<String>,
    State(audit_logger): State<Arc<AuditLogger>>,
) -> Result<Json<KeypairResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    let variant = parse_sig_variant(&variant)?;
    
    let start_time = std::time::Instant::now();
    tracing::info!("Signature keygen operation: variant={:?}", variant);
    
    let keypair = SigService::generate_keypair(variant)?;
    
    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoOperation,
        "POST".to_string(),
        format!("/sig/{}/keygen", sig_variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(),
    ).with_resource(format!("SIG-{:?}-KeyGen", variant))
     .with_additional_data(json!({
         "operation": "keygen",
         "variant": format!("{:?}", variant),
         "key_sizes": {
             "public_key": keypair.pk.len(),
             "secret_key": keypair.sk.len()
         }
     }));
    
    audit_logger.log_event(audit_event).await;
    
    Ok(Json(keypair))
}

pub async fn sign(
    Path(variant): Path<String>,
    State(audit_logger): State<Arc<AuditLogger>>,
    Json(payload): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_message(&payload.message)?;
    validation::validate_base64_key(&payload.sk)?;
    
    let variant = parse_sig_variant(&variant)?;
    
    let start_time = std::time::Instant::now();
    tracing::info!("Signature sign operation: variant={:?}", variant);
    
    let signature = SigService::sign(variant, &payload.message, &payload.sk)?;
    let signature_encoded = encode_signature(signature);
    
    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoOperation,
        "POST".to_string(),
        format!("/sig/{}/sign", sig_variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(),
    ).with_resource(format!("SIG-{:?}-Sign", variant))
     .with_additional_data(json!({
         "operation": "sign",
         "variant": format!("{:?}", variant),
         "message_length": payload.message.len(),
         "signature_length": signature_encoded.len()
     }));
    
    audit_logger.log_event(audit_event).await;
    
    Ok(Json(SignResponse { signature: signature_encoded }))
}

pub async fn verify(
    Path(variant): Path<String>,
    State(audit_logger): State<Arc<AuditLogger>>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_message(&payload.message)?;
    validation::validate_base64_key(&payload.pk)?;
    validation::validate_base64_signature(&payload.signature)?;
    
    let variant = parse_sig_variant(&variant)?;
    
    let start_time = std::time::Instant::now();
    tracing::info!("Signature verify operation: variant={:?}", variant);
    
    let valid = SigService::verify(variant, &payload.pk, &payload.message, &payload.signature)?;
    
    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoVerification,
        "POST".to_string(),
        format!("/sig/{}/verify", sig_variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(),
    ).with_resource(format!("SIG-{:?}-Verify", variant))
     .with_additional_data(json!({
         "operation": "verify",
         "variant": format!("{:?}", variant),
         "message_length": payload.message.len(),
         "signature_length": payload.signature.len(),
         "verification_result": valid
     }));
    
    audit_logger.log_event(audit_event).await;
    
    Ok(Json(VerifyResponse { valid }))
}

fn sig_variant_to_string(variant: &SigVariant) -> &'static str {
    match variant {
        SigVariant::MlDsa44 => "ml-dsa-44",
        SigVariant::MlDsa65 => "ml-dsa-65", 
        SigVariant::MlDsa87 => "ml-dsa-87",
        SigVariant::Falcon512 => "falcon-512",
        SigVariant::Falcon1024 => "falcon-1024",
        SigVariant::SlhDsaHaraka192f => "slh-dsa-haraka-192f",
        SigVariant::SlhDsaSha2256s => "slh-dsa-sha2-256s",
        SigVariant::SlhDsaShake128f => "slh-dsa-shake-128f",
        #[allow(deprecated)]
        SigVariant::Dilithium2 => "dilithium2",
        #[allow(deprecated)]
        SigVariant::Dilithium3 => "dilithium3",
        #[allow(deprecated)]
        SigVariant::Dilithium5 => "dilithium5",
        #[allow(deprecated)]
        SigVariant::Haraka192f => "haraka192f",
        #[allow(deprecated)]
        SigVariant::Sha2_256s => "sha2_256s",
        #[allow(deprecated)]
        SigVariant::Shake128f => "shake128f",
    }
}