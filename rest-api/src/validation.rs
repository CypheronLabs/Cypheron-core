use crate::error::AppError;
use serde_json::Value;
use base64::Engine;

pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; 
#[allow(dead_code)]
pub const MAX_JSON_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; 
pub const MAX_BASE64_KEY_SIZE: usize = 8192; 
pub const MAX_BASE64_SIGNATURE_SIZE: usize = 16384; 
pub const MAX_PATH_PARAMETER_LENGTH: usize = 100;
#[allow(dead_code)]
pub const MAX_API_KEY_NAME_LENGTH: usize = 100;

pub fn validate_message(message: &str) -> Result<(), AppError> {
    if message.is_empty() {
        return Err(AppError::ValidationError("Message cannot be empty".to_string()));
    }
    
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(AppError::ValidationError(
            format!("Message too large. Maximum size: {} bytes", MAX_MESSAGE_SIZE)
        ));
    }
    
    if message.contains('\0') {
        return Err(AppError::ValidationError("Message contains null bytes".to_string()));
    }
    
    Ok(())
}

pub fn validate_base64_key(key: &str) -> Result<(), AppError> {
    if key.is_empty() {
        return Err(AppError::ValidationError("Key cannot be empty".to_string()));
    }
    
    if key.len() > MAX_BASE64_KEY_SIZE {
        return Err(AppError::ValidationError(
            format!("Key too large. Maximum size: {} characters", MAX_BASE64_KEY_SIZE)
        ));
    }
    
    if let Err(_) = base64::engine::general_purpose::STANDARD.decode(key) {
        return Err(AppError::ValidationError("Invalid base64 format for key".to_string()));
    }
    
    Ok(())
}

pub fn validate_base64_signature(signature: &str) -> Result<(), AppError> {
    if signature.is_empty() {
        return Err(AppError::ValidationError("Signature cannot be empty".to_string()));
    }
    
    if signature.len() > MAX_BASE64_SIGNATURE_SIZE {
        return Err(AppError::ValidationError(
            format!("Signature too large. Maximum size: {} characters", MAX_BASE64_SIGNATURE_SIZE)
        ));
    }
    
    // Validate base64 format
    if let Err(_) = base64::engine::general_purpose::STANDARD.decode(signature) {
        return Err(AppError::ValidationError("Invalid base64 format for signature".to_string()));
    }
    
    Ok(())
}

pub fn validate_path_parameter(param: &str) -> Result<(), AppError> {
    if param.is_empty() {
        return Err(AppError::ValidationError("Path parameter cannot be empty".to_string()));
    }
    
    if param.len() > MAX_PATH_PARAMETER_LENGTH {
        return Err(AppError::ValidationError(
            format!("Path parameter too long. Maximum length: {} characters", MAX_PATH_PARAMETER_LENGTH)
        ));
    }
    
    let decoded_param = match urlencoding::decode(param) {
        Ok(decoded) => decoded.to_string(),
        Err(_) => param.to_string(),
    };
    
    let dangerous_chars = ['<', '>', '"', '\'', '&', '\0', '\n', '\r', '\t'];
    if decoded_param.chars().any(|c| dangerous_chars.contains(&c)) {
        return Err(AppError::ValidationError("Path parameter contains invalid characters".to_string()));
    }
    
    let dangerous_patterns = [
        "..", "//", "\\", "../", "..\\", "..%2f", "..%5c",
        "%2e%2e", "%2e%2e%2f", "%2e%2e%5c", "....//", "....\\\\",
        "%2e%2e/", "%2e%2e\\", "..%252f", "..%255c"
    ];
    
    for pattern in &dangerous_patterns {
        if decoded_param.to_lowercase().contains(&pattern.to_lowercase()) {
            return Err(AppError::ValidationError("Path parameter contains traversal patterns".to_string()));
        }
    }
    
    Ok(())
}

#[allow(dead_code)]
pub fn validate_api_key_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::ValidationError("API key name cannot be empty".to_string()));
    }
    
    if name.len() > MAX_API_KEY_NAME_LENGTH {
        return Err(AppError::ValidationError(
            format!("API key name too long. Maximum length: {} characters", MAX_API_KEY_NAME_LENGTH)
        ));
    }
    
    if !name.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_') {
        return Err(AppError::ValidationError(
            "API key name can only contain alphanumeric characters, spaces, hyphens, and underscores".to_string()
        ));
    }
    
    Ok(())
}

#[allow(dead_code)]
pub fn validate_json_payload_size(json: &Value) -> Result<(), AppError> {
    let serialized_size = serde_json::to_string(json)
        .map_err(|_| AppError::ValidationError("Failed to serialize JSON".to_string()))?
        .len();
    
    if serialized_size > MAX_JSON_PAYLOAD_SIZE {
        return Err(AppError::ValidationError(
            format!("JSON payload too large. Maximum size: {} bytes", MAX_JSON_PAYLOAD_SIZE)
        ));
    }
    
    Ok(())
}

#[allow(dead_code)]
pub fn validate_permissions(permissions: &[String]) -> Result<(), AppError> {
    const MAX_PERMISSIONS: usize = 10;
    const VALID_PERMISSIONS: &[&str] = &[
        "kem:*", "kem:keygen", "kem:encapsulate", "kem:decapsulate",
        "sig:*", "sig:keygen", "sig:sign", "sig:verify",
        "hybrid:*", "hybrid:sign",
        "*" // Admin permission
    ];
    
    if permissions.is_empty() {
        return Err(AppError::ValidationError("At least one permission is required".to_string()));
    }
    
    if permissions.len() > MAX_PERMISSIONS {
        return Err(AppError::ValidationError(
            format!("Too many permissions. Maximum: {}", MAX_PERMISSIONS)
        ));
    }
    
    for permission in permissions {
        if !VALID_PERMISSIONS.contains(&permission.as_str()) {
            return Err(AppError::ValidationError(
                format!("Invalid permission: {}", permission)
            ));
        }
    }
    
    Ok(())
}

#[allow(dead_code)]
pub fn validate_rate_limit(rate_limit: u32) -> Result<(), AppError> {
    const MIN_RATE_LIMIT: u32 = 1;
    const MAX_RATE_LIMIT: u32 = 10000; 
    
    if rate_limit < MIN_RATE_LIMIT || rate_limit > MAX_RATE_LIMIT {
        return Err(AppError::ValidationError(
            format!("Rate limit must be between {} and {} requests per minute", 
                MIN_RATE_LIMIT, MAX_RATE_LIMIT)
        ));
    }
    
    Ok(())
}

#[allow(dead_code)]
pub fn sanitize_for_logging(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .take(100) 
        .collect::<String>()
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('\t', " ")
}

pub fn validate_decoded_key_size(algorithm: &str, key_bytes: &[u8], is_public: bool) -> Result<(), AppError> {
    let expected_size = match (algorithm, is_public) {
        ("dilithium2", true) => 1312,
        ("dilithium2", false) => 2560,
        ("dilithium3", true) => 1952,
        ("dilithium3", false) => 4032,
        ("dilithium5", true) => 2592,
        ("dilithium5", false) => 4896,
        ("falcon512", true) => 897,
        ("falcon512", false) => 1281,
        ("falcon1024", true) => 1793,
        ("falcon1024", false) => 2305,
        _ => return Ok(()), 
    };
    
    if key_bytes.len() != expected_size {
        return Err(AppError::ValidationError(
            format!("Invalid key size for {}: expected {} bytes, got {}", 
                algorithm, expected_size, key_bytes.len())
        ));
    }
    
    Ok(())
}