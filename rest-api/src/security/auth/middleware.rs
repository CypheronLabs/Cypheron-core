use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::{
    errors::AuthError,
    permissions::{check_permission, extract_resource_from_path},
    store::ApiKeyStore,
    utils::extract_api_key,
};
use crate::security::compliance::{ComplianceEventType, ComplianceManager, RiskLevel};

pub async fn auth_middleware(
    State(api_store): State<ApiKeyStore>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let api_key = extract_api_key(&headers)?;

    let validated_key = api_store.validate_key(&api_key).await.ok_or_else(|| {
        if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
            let mut details = HashMap::new();
            details.insert("error".to_string(), "invalid_api_key".to_string());
            details.insert("path".to_string(), request.uri().path().to_string());
            details.insert("method".to_string(), request.method().to_string());

            compliance_manager.log_event_async(
                ComplianceEventType::AccessDenied,
                details,
                RiskLevel::Medium,
            );
        }

        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_api_key".to_string(),
                message: "Invalid or expired API key".to_string(),
                code: 401,
            }),
        )
    })?;

    let path = request.uri().path();
    let resource = extract_resource_from_path(path);

    if !check_permission(&validated_key, &resource) {
        if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
            let mut details = HashMap::new();
            details.insert("error".to_string(), "insufficient_permissions".to_string());
            details.insert("resource".to_string(), resource.clone());
            details.insert("api_key_id".to_string(), validated_key.id.to_string());
            details.insert("path".to_string(), request.uri().path().to_string());
            details.insert("method".to_string(), request.method().to_string());

            compliance_manager.log_event_async(
                ComplianceEventType::AccessDenied,
                details,
                RiskLevel::High,
            );
        }

        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthError {
                error: "insufficient_permissions".to_string(),
                message: format!("Insufficient permissions for resource: {}", resource),
                code: 403,
            }),
        ));
    }

    tracing::info!(
        "API request authorized - key_id: {}, resource: {}, usage_count: {}",
        validated_key.id,
        resource,
        validated_key.usage_count
    );

    if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
        let mut details = HashMap::new();
        details.insert("api_key_id".to_string(), validated_key.id.to_string());
        details.insert("resource".to_string(), resource.clone());
        details.insert("method".to_string(), request.method().to_string());
        details.insert("path".to_string(), request.uri().path().to_string());

        compliance_manager.log_event_async(
            ComplianceEventType::Authentication,
            details,
            RiskLevel::Low,
        );
    }

    // Add user_id and api_key_prefix to request extensions for logging
    request.extensions_mut().insert(validated_key.id.to_string());
    request.extensions_mut().insert(api_key[..8].to_string());

    Ok(next.run(request).await)
}

pub async fn admin_auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let master_admin_key = std::env::var("PQ_MASTER_ADMIN_KEY").map_err(|_| {
        tracing::error!("PQ_MASTER_ADMIN_KEY environment variable not set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError {
                error: "admin_config_error".to_string(),
                message: "Admin authentication not properly configured".to_string(),
                code: 500,
            }),
        )
    })?;

    let provided_key = extract_api_key(&headers).map_err(|e| {
        tracing::warn!(
            "Admin endpoint access attempt without API key from: {:?}",
            request.uri()
        );
        e
    })?;

    if provided_key
        .as_bytes()
        .ct_eq(master_admin_key.as_bytes())
        .into()
    {
        tracing::info!("Master admin authenticated for: {}", request.uri().path());
        Ok(next.run(request).await)
    } else {
        tracing::error!(
            "Unauthorized admin access attempt with key: {}... from: {}",
            &provided_key[..std::cmp::min(10, provided_key.len())],
            request.uri().path()
        );

        Err((
            StatusCode::FORBIDDEN,
            Json(AuthError {
                error: "admin_access_denied".to_string(),
                message: "Admin access requires master admin key".to_string(),
                code: 403,
            }),
        ))
    }
}

pub async fn compliance_middleware(
    State(compliance_manager): State<Arc<ComplianceManager>>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(compliance_manager);
    next.run(request).await
}