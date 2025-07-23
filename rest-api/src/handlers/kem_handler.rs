use crate::error::AppError;
use crate::security::{AuditEvent, AuditEventType, ComplianceEventType, RiskLevel};
use crate::services::kem_service::KemService;
use crate::state::AppState;
use crate::utils::encoding::encode_struct_base64;
use crate::{models::kem::*, validation};
use axum::extract::{Json, Path, State};
use core_lib::kem::KemVariant;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

pub async fn keygen(
    Path(variant): Path<String>,
    State(app_state): State<AppState>,
) -> Result<Json<KeypairResponse>, AppError> {
    let handler_start = std::time::Instant::now();
    eprintln!("DEBUG: Handler entry at {:?}", handler_start.elapsed());

    validation::validate_path_parameter(&variant)?;
    eprintln!("DEBUG: Path validation completed at {:?}", handler_start.elapsed());

    let variant = parse_variant(&variant)?;
    eprintln!("DEBUG: Variant parsed at {:?}", handler_start.elapsed());

    let start_time = std::time::Instant::now();
    tracing::info!("KEM keygen operation: variant={:?}", variant);
    eprintln!("DEBUG: About to call KemService::generate_keypair at {:?}", handler_start.elapsed());

    let (pk, sk) = KemService::generate_keypair(variant)?;
    eprintln!("DEBUG: KemService::generate_keypair completed at {:?}", handler_start.elapsed());

    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoOperation,
        "POST".to_string(),
        format!("/kem/{}/keygen", variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(), // Will be updated with actual IP in middleware
    )
    .with_resource(format!("KEM-{:?}-KeyGen", variant))
    .with_additional_data(json!({
        "operation": "keygen",
        "variant": format!("{:?}", variant),
        "key_sizes": {
            "public_key": pk.len(),
            "secret_key": sk.len()
        }
    }));

    eprintln!("DEBUG: About to log audit event at {:?}", handler_start.elapsed());
    app_state.audit_logger.log_event(audit_event).await;
    eprintln!("DEBUG: Audit event logged at {:?}", handler_start.elapsed());

    // Log compliance event for data processing with privacy controls
    let mut details = HashMap::new();
    details.insert("operation".to_string(), "keygen".to_string());
    details.insert("variant".to_string(), variant_to_string(&variant).to_string());
    details.insert("response_time_ms".to_string(), response_time.to_string());
    details.insert("success".to_string(), "true".to_string());
    details.insert("key_sizes".to_string(), format!("pk:{}, sk:{}", pk.len(), sk.len()));

    // Use AppState convenience methods for privacy controls
    let sanitized_variant = app_state.sanitize_sensitive_data(&variant_to_string(&variant));
    details.insert("sanitized_variant".to_string(), sanitized_variant);

    // If there was a session ID or user context, we would pseudonymize it
    // Example: let pseudo_session = app_state.pseudonymize_user_id("session_12345");

    // Use enhanced logging with user context (no user context for keygen, but shows the pattern)
    app_state
        .log_compliance_with_user(
            ComplianceEventType::DataCreated,
            details,
            RiskLevel::Low,
            None, // No user context for key generation
            None, // Could extract IP from request headers if needed
        )
        .await;
    eprintln!("DEBUG: Compliance logging completed at {:?}", handler_start.elapsed());

    eprintln!("DEBUG: Creating response at {:?}", handler_start.elapsed());
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
    State(app_state): State<AppState>,
    Json(payload): Json<EncapsulateRequest>,
) -> Result<Json<EncapsulateResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_base64_key(&payload.pk)?;

    let variant = parse_variant(&variant)?;

    let start_time = std::time::Instant::now();
    tracing::info!("KEM encapsulate operation: variant={:?}", variant);

    let (ct, ss) = KemService::encapsulate(variant, &payload.pk)?;

    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoOperation,
        "POST".to_string(),
        format!("/kem/{}/encapsulate", variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(),
    )
    .with_resource(format!("KEM-{:?}-Encapsulate", variant))
    .with_additional_data(json!({
        "operation": "encapsulate",
        "variant": format!("{:?}", variant),
        "output_sizes": {
            "ciphertext": ct.len(),
            "shared_secret": ss.len()
        }
    }));

    app_state.audit_logger.log_event(audit_event).await;

    // Log compliance event for data processing with privacy controls
    let mut details = HashMap::new();
    details.insert("operation".to_string(), "encapsulate".to_string());
    details.insert("variant".to_string(), variant_to_string(&variant).to_string());
    details.insert("response_time_ms".to_string(), response_time.to_string());
    details.insert("success".to_string(), "true".to_string());
    details.insert("output_sizes".to_string(), format!("ct:{}, ss:{}", ct.len(), ss.len()));

    // Use AppState convenience methods for privacy controls
    // Simulate processing a request ID that might contain sensitive information
    let request_id = format!("encap_req_{}", Uuid::new_v4());
    let pseudonymized_request = app_state.pseudonymize_user_id(&request_id);
    details.insert("request_id".to_string(), pseudonymized_request);

    // Use enhanced logging with privacy controls
    app_state
        .log_compliance_with_user(
            ComplianceEventType::DataEncrypted,
            details,
            RiskLevel::Low,
            None, // Could extract user from API key context if available
            None, // Could extract IP from request headers
        )
        .await;

    Ok(Json(EncapsulateResponse { ct, ss, format: payload.format }))
}

pub async fn decapsulate(
    Path(variant): Path<String>,
    State(app_state): State<AppState>,
    Json(payload): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, AppError> {
    validation::validate_path_parameter(&variant)?;
    validation::validate_base64_key(&payload.sk)?;
    validation::validate_base64_key(&payload.ct)?;

    let variant = parse_variant(&variant)?;

    let start_time = std::time::Instant::now();
    tracing::info!("KEM decapsulate operation: variant={:?}", variant);

    let ss = KemService::decapsulate(variant, &payload.ct, &payload.sk)?;

    // Log audit event
    let response_time = start_time.elapsed().as_millis() as u64;
    let audit_event = AuditEvent::new(
        AuditEventType::CryptoOperation,
        "POST".to_string(),
        format!("/kem/{}/decapsulate", variant_to_string(&variant)),
        200,
        response_time,
        "127.0.0.1".to_string(),
    )
    .with_resource(format!("KEM-{:?}-Decapsulate", variant))
    .with_additional_data(json!({
        "operation": "decapsulate",
        "variant": format!("{:?}", variant),
        "output_sizes": {
            "shared_secret": ss.len()
        }
    }));

    app_state.audit_logger.log_event(audit_event).await;

    // Log compliance event for data processing with privacy controls
    let mut details = HashMap::new();
    details.insert("operation".to_string(), "decapsulate".to_string());
    details.insert("variant".to_string(), variant_to_string(&variant).to_string());
    details.insert("response_time_ms".to_string(), response_time.to_string());
    details.insert("success".to_string(), "true".to_string());
    details.insert("output_size".to_string(), format!("ss:{}", ss.len()));

    // Use enhanced logging with privacy controls
    app_state
        .log_compliance_with_user(
            ComplianceEventType::DataDecrypted,
            details,
            RiskLevel::Low,
            None, // Could extract user from API key context if available
            None, // Could extract IP from request headers
        )
        .await;

    Ok(Json(DecapsulateResponse { ss, format: payload.format }))
}

pub async fn variant_info(
    Path(variant): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    validation::validate_path_parameter(&variant)?;
    let variant_enum = parse_variant(&variant)?;

    let info = json!({
        "variant": variant,
        "algorithm": match variant_enum {
            KemVariant::MlKem512 => "ML-KEM-512 (NIST FIPS 203)",
            KemVariant::MlKem768 => "ML-KEM-768 (NIST FIPS 203)",
            KemVariant::MlKem1024 => "ML-KEM-1024 (NIST FIPS 203)",
            // Handle deprecated variants by forwarding to new ones
            #[allow(deprecated)]
            KemVariant::Kyber512 => "ML-KEM-512 (NIST FIPS 203)",
            #[allow(deprecated)]
            KemVariant::Kyber768 => "ML-KEM-768 (NIST FIPS 203)",
            #[allow(deprecated)]
            KemVariant::Kyber1024 => "ML-KEM-1024 (NIST FIPS 203)",
        },
        "security_level": match variant_enum {
            KemVariant::MlKem512 => 1,
            KemVariant::MlKem768 => 3,
            KemVariant::MlKem1024 => 5,
            // Handle deprecated variants by forwarding to new ones
            #[allow(deprecated)]
            KemVariant::Kyber512 => 1,
            #[allow(deprecated)]
            KemVariant::Kyber768 => 3,
            #[allow(deprecated)]
            KemVariant::Kyber1024 => 5,
        },
        "key_sizes": match variant_enum {
            KemVariant::MlKem512 => json!({"public_key": 800, "secret_key": 1632, "ciphertext": 768, "shared_secret": 32}),
            KemVariant::MlKem768 => json!({"public_key": 1184, "secret_key": 2400, "ciphertext": 1088, "shared_secret": 32}),
            KemVariant::MlKem1024 => json!({"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32}),
            // Handle deprecated variants by forwarding to new ones
            #[allow(deprecated)]
            KemVariant::Kyber512 => json!({"public_key": 800, "secret_key": 1632, "ciphertext": 768, "shared_secret": 32}),
            #[allow(deprecated)]
            KemVariant::Kyber768 => json!({"public_key": 1184, "secret_key": 2400, "ciphertext": 1088, "shared_secret": 32}),
            #[allow(deprecated)]
            KemVariant::Kyber1024 => json!({"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32}),
        },
        "supported_formats": ["base64", "hex", "base64url"],
        "endpoints": [
            format!("/kem/{}/keygen", variant),
            format!("/kem/{}/encapsulate", variant),
            format!("/kem/{}/decapsulate", variant),
        ],
        "nist_compliant_endpoints": [
            "/kem/ml-kem-512/keygen",
            "/kem/ml-kem-768/keygen",
            "/kem/ml-kem-1024/keygen",
            "/kem/ml-kem-512/encapsulate",
            "/kem/ml-kem-768/encapsulate",
            "/kem/ml-kem-1024/encapsulate",
            "/kem/ml-kem-512/decapsulate",
            "/kem/ml-kem-768/decapsulate",
            "/kem/ml-kem-1024/decapsulate"
        ],
        "deprecated_endpoints": [
            "/kem/kyber512/* (use ml-kem-512 instead)",
            "/kem/kyber768/* (use ml-kem-768 instead)",
            "/kem/kyber1024/* (use ml-kem-1024 instead)"
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
        // NIST FIPS 203 compliant names (ML-KEM)
        "ml-kem-512" | "ml_kem_512" => Ok(KemVariant::MlKem512),
        "ml-kem-768" | "ml_kem_768" => Ok(KemVariant::MlKem768),
        "ml-kem-1024" | "ml_kem_1024" => Ok(KemVariant::MlKem1024),

        // Backward compatibility (deprecated)
        "kyber512" => {
            tracing::warn!(
                "Using deprecated 'kyber512', please use 'ml-kem-512' for NIST FIPS 203 compliance"
            );
            Ok(KemVariant::MlKem512)
        }
        "kyber768" => {
            tracing::warn!(
                "Using deprecated 'kyber768', please use 'ml-kem-768' for NIST FIPS 203 compliance"
            );
            Ok(KemVariant::MlKem768)
        }
        "kyber1024" => {
            tracing::warn!("Using deprecated 'kyber1024', please use 'ml-kem-1024' for NIST FIPS 203 compliance");
            Ok(KemVariant::MlKem1024)
        }

        _ => Err(AppError::InvalidVariant),
    }
}

fn variant_to_string(variant: &KemVariant) -> &'static str {
    match variant {
        KemVariant::MlKem512 => "ml-kem-512",
        KemVariant::MlKem768 => "ml-kem-768",
        KemVariant::MlKem1024 => "ml-kem-1024",
        #[allow(deprecated)]
        KemVariant::Kyber512 => "kyber512",
        #[allow(deprecated)]
        KemVariant::Kyber768 => "kyber768",
        #[allow(deprecated)]
        KemVariant::Kyber1024 => "kyber1024",
    }
}
