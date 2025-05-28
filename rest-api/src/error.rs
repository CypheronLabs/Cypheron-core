use axum::{http::StatusCode, response::{IntoResponse, Response}};
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
    #[error("Signing failed:")]
    SigningFailed,
    #[error("Invalid Secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid base64 encoding")]
    InvalidBase64,
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Invalid Hex encoding")]
    InvalidHex,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = match self {
            AppError::Base64Decode(_) | AppError::InvalidLength => StatusCode::BAD_REQUEST,
            AppError::InvalidVariant => StatusCode::NOT_FOUND,
            AppError::KeyGenFailed => StatusCode::NOT_FOUND,
            AppError::SigningFailed => StatusCode::BAD_REQUEST,
            AppError::InvalidSecretKey => StatusCode::UNAUTHORIZED,
            AppError::InvalidPublicKey => StatusCode::UNAUTHORIZED,
            AppError::InvalidBase64 => StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => StatusCode::BAD_REQUEST,
            AppError::InvalidHex => StatusCode::BAD_REQUEST,
        };
        (code, self.to_string()).into_response()
    }
}
