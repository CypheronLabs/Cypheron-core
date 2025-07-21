use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid base64 encoding")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Invalid input length")]
    InvalidLength,
    #[error("Unsupported variant")]
    InvalidVariant,
    #[error("Key generation failed")]
    KeyGenFailed,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Invalid Secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid base64 encoding")]
    InvalidBase64,
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Resource not found")]
    NotFound,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            AppError::Base64Decode(_) | AppError::InvalidLength => {
                (StatusCode::BAD_REQUEST, "Invalid input format".to_string())
            }
            AppError::InvalidVariant => {
                (StatusCode::NOT_FOUND, "Algorithm variant not supported".to_string())
            }
            AppError::KeyGenFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Key generation failed".to_string())
            }
            AppError::SigningFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Signing operation failed".to_string())
            }
            AppError::InvalidSecretKey => {
                (StatusCode::BAD_REQUEST, "Invalid secret key".to_string())
            }
            AppError::InvalidPublicKey => {
                (StatusCode::BAD_REQUEST, "Invalid public key".to_string())
            }
            AppError::InvalidBase64 => {
                (StatusCode::BAD_REQUEST, "Invalid base64 encoding".to_string())
            }
            AppError::InvalidSignature => {
                (StatusCode::BAD_REQUEST, "Invalid signature".to_string())
            }
            AppError::ValidationError(ref msg) => {
                (StatusCode::BAD_REQUEST, format!("Validation failed: {}", msg))
            }
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            AppError::EncapsulationFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Encapsulation operation failed".to_string())
            }
            AppError::DecapsulationFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Decapsulation operation failed".to_string())
            }
        };

        tracing::error!("API Error: {:?}", self);

        (code, message).into_response()
    }
}
