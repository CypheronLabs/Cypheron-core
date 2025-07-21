use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EncapsulateRequest {
    pub pk: String,
    #[serde(default = "default_format")]
    pub format: String, // "base64", "hex", or "base64url"
}

#[derive(Deserialize)]
pub struct DecapsulateRequest {
    pub ct: String,
    pub sk: String,
    #[serde(default = "default_format")]
    pub format: String,
}

#[derive(Serialize)]
pub struct KeypairResponse {
    pub pk: String,
    pub sk: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pk_hex: Option<String>, // Alternative hex encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sk_hex: Option<String>, // Alternative hex encoding
}

#[derive(Serialize)]
pub struct EncapsulateResponse {
    pub ct: String,
    pub ss: String,
    pub format: String,
}

#[derive(Serialize)]
pub struct DecapsulateResponse {
    pub ss: String,
    pub format: String,
}

fn default_format() -> String {
    "base64".to_string()
}
