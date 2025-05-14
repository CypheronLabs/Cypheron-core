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
    #[error("Internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = match self {
            AppError::Base64Decode(_) | AppError::InvalidLength => StatusCode::BAD_REQUEST,
            AppError::InvalidVariant => StatusCode::NOT_FOUND,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}
