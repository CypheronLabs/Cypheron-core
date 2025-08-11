use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use super::{
    demo_auth::{DemoContext, DemoUser},
    jwt_validation::JwtValidator,
    permissions::extract_resource_from_path,
};
use crate::security::compliance::{ComplianceEventType, ComplianceManager, RiskLevel};
use crate::security::error_sanitizer::{ErrorSanitizer, SanitizedError};

pub async fn jwt_auth_middleware(
    State(jwt_validator): State<Arc<JwtValidator>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<SanitizedError>)> {
    let token = extract_jwt_token(&headers).map_err(|(status, error)| {
        (status, Json(ErrorSanitizer::sanitize_auth_error(&error)))
    })?;

    let claims = jwt_validator.validate_demo_token(&token).map_err(|jwt_error| {
        let auth_error = jwt_error.into();
        log_authentication_failure(&request, &auth_error);
        (StatusCode::UNAUTHORIZED, Json(ErrorSanitizer::sanitize_auth_error(&auth_error)))
    })?;

    let demo_user = DemoUser::from(claims);
    let request_id = Uuid::new_v4().to_string();
    let demo_context = DemoContext::new(demo_user, request_id);

    let path = request.uri().path();
    let resource = extract_resource_from_path(path);

    if !demo_context.has_permission(&resource) {
        log_authorization_failure(&request, &demo_context, &resource);
        
        let auth_error = super::errors::AuthError {
            error: "insufficient_permissions".to_string(),
            message: format!("Demo user lacks permission for resource: {}", resource),
            code: 403,
        };
        
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorSanitizer::sanitize_auth_error(&auth_error)),
        ));
    }

    log_successful_authentication(&request, &demo_context, &resource);

    request.extensions_mut().insert(demo_context.clone());
    request.extensions_mut().insert(demo_context.user.sub.clone());

    Ok(next.run(request).await)
}

fn extract_jwt_token(headers: &HeaderMap) -> Result<String, (StatusCode, super::errors::AuthError)> {
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") && auth_str.len() > 7 {
                return Ok(auth_str[7..].to_string());
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        super::errors::AuthError {
            error: "missing_jwt_token".to_string(),
            message: "JWT token required. Use Authorization: Bearer <token> header".to_string(),
            code: 401,
        },
    ))
}

fn log_authentication_failure(request: &Request, auth_error: &super::errors::AuthError) {
    if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
        let mut details = HashMap::new();
        details.insert("error".to_string(), auth_error.error.clone());
        details.insert("path".to_string(), request.uri().path().to_string());
        details.insert("method".to_string(), request.method().to_string());
        details.insert("auth_type".to_string(), "jwt_demo".to_string());

        compliance_manager.log_event_async(
            ComplianceEventType::AccessDenied,
            details,
            RiskLevel::Medium,
        );
    }

    tracing::warn!(
        "JWT authentication failed - path: {}, method: {}, error: {}",
        request.uri().path(),
        request.method(),
        auth_error.error
    );
}

fn log_authorization_failure(request: &Request, demo_context: &DemoContext, resource: &str) {
    if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
        let mut details = HashMap::new();
        details.insert("error".to_string(), "insufficient_permissions".to_string());
        details.insert("resource".to_string(), resource.to_string());
        details.insert("demo_user".to_string(), demo_context.user.sub.clone());
        details.insert("path".to_string(), request.uri().path().to_string());
        details.insert("method".to_string(), request.method().to_string());
        details.insert("auth_type".to_string(), "jwt_demo".to_string());

        compliance_manager.log_event_async(
            ComplianceEventType::AccessDenied,
            details,
            RiskLevel::High,
        );
    }

    tracing::warn!(
        "JWT authorization failed - user: {}, resource: {}, path: {}",
        demo_context.user.sub,
        resource,
        request.uri().path()
    );
}

fn log_successful_authentication(request: &Request, demo_context: &DemoContext, resource: &str) {
    if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
        let mut details = HashMap::new();
        details.insert("demo_user".to_string(), demo_context.user.sub.clone());
        details.insert("resource".to_string(), resource.to_string());
        details.insert("method".to_string(), request.method().to_string());
        details.insert("path".to_string(), request.uri().path().to_string());
        details.insert("auth_type".to_string(), "jwt_demo".to_string());

        compliance_manager.log_event_async(
            ComplianceEventType::Authentication,
            details,
            RiskLevel::Low,
        );
    }

    tracing::info!(
        "JWT demo user authorized - user: {}, resource: {}, path: {}",
        demo_context.user.sub,
        resource,
        request.uri().path()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_jwt_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        );

        let result = extract_jwt_token(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    }

    #[test]
    fn test_extract_jwt_token_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjpwYXNz"));

        let result = extract_jwt_token(&headers);
        assert!(result.is_err());
        
        let (status, error) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.error, "missing_jwt_token");
    }

    #[test]
    fn test_extract_jwt_token_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_jwt_token(&headers);
        assert!(result.is_err());
        
        let (status, error) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.error, "missing_jwt_token");
    }

    #[test]
    fn test_extract_jwt_token_empty_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));

        let result = extract_jwt_token(&headers);
        assert!(result.is_err());
    }
}