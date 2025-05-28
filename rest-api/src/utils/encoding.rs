use base64::{engine::general_purpose, Engine as _};
use hex;
use crate::error::AppError;
use std::io::{Read, Write};
use serde::{Serialize, de::DeserializeOwned};

pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(s: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::STANDARD.decode(s).map_err(|_| AppError::InvalidBase64)
}

pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(s).map_err(|_| AppError::InvalidHex)
}
pub fn encode_base64_url(data: &[u8]) -> String {
    general_purpose::URL_SAFE.encode(data)
}
pub fn decode_base64_url(s: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::URL_SAFE.decode(s).map_err(|_| AppError::InvalidBase64)
}
pub fn encode_base64_no_pad(data: &[u8]) -> String {
    general_purpose::STANDARD_NO_PAD.encode(data)
}
pub fn decode_base64_no_pad(s: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::STANDARD_NO_PAD.decode(s).map_err(|_| AppError::InvalidBase64)
}
pub fn encode_struct_base64<T: Serialize>(data: &T) -> Result<String, AppError> {
    let json = serde_json::to_vec(data).map_err(|_| AppError::InvalidBase64)?;
    Ok(encode_base64(&json))
}

pub fn decode_struct_base64<T: DeserializeOwned>(s: &str) -> Result<T, AppError> {
    let bytes = decode_base64(s)?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::InvalidBase64)
}
pub fn encode_base64_stream<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<(), AppError> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).map_err(|_| AppError::InvalidBase64)?;
    let encoded = encode_base64(&buffer);
    writer.write_all(encoded.as_bytes()).map_err(|_| AppError::InvalidBase64)?;
    Ok(())
}
pub fn decode_base64_stream<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<(), AppError> {
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer).map_err(|_| AppError::InvalidBase64)?;
    let decoded = decode_base64(&buffer)?;
    writer.write_all(&decoded).map_err(|_| AppError::InvalidBase64)?;
    Ok(())
}