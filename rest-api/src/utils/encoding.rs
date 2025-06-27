use base64::{engine::general_purpose, Engine as _};
use crate::error::AppError;
use serde::{Serialize, de::DeserializeOwned};
use hex;

// Standard base64 encoding (used by signature handlers)
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(s: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::STANDARD.decode(s).map_err(|_| AppError::InvalidBase64)
}

// URL-safe base64 (used by hybrid JWT)
pub fn encode_base64_url(data: &[u8]) -> String {
    general_purpose::URL_SAFE.encode(data)
}

pub fn decode_base64_url(s: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::URL_SAFE.decode(s).map_err(|_| AppError::InvalidBase64)
}

// Hex encoding (useful for key material display/debugging)
pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(s).map_err(|_| AppError::InvalidBase64) // Reusing InvalidBase64 for simplicity
}

// Structured data encoding (useful for complex responses)
pub fn encode_struct_base64<T: Serialize>(data: &T) -> Result<String, AppError> {
    let json = serde_json::to_vec(data).map_err(|_| AppError::InvalidBase64)?;
    Ok(encode_base64(&json))
}

pub fn decode_struct_base64<T: DeserializeOwned>(s: &str) -> Result<T, AppError> {
    let bytes = decode_base64(s)?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::InvalidBase64)
}