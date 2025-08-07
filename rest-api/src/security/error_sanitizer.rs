use crate::security::auth::AuthError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SanitizedError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

pub struct ErrorSanitizer;

impl ErrorSanitizer {
    /// Sanitizes error messages to prevent information disclosure while maintaining debugging capability
    pub fn sanitize_auth_error(error: &AuthError) -> SanitizedError {
        let (sanitized_error, sanitized_message) = match error.error.as_str() {
            // Database/Infrastructure errors - generic message
            "firestore_init_error" | "firestore_create_error" | "firestore_delete_error" 
            | "database_error" | "database_update_error" => {
                ("database_error".to_string(), "Database operation failed".to_string())
            }
            
            // Encryption errors - generic message
            "encryption_error" | "decryption_error" | "decryption_failed" | "key_error" 
            | "invalid_ciphertext" | "random_error" => {
                ("encryption_error".to_string(), "Encryption operation failed".to_string())
            }
            
            // Configuration errors - generic message but actionable
            "missing_encryption_password" | "missing_salt" | "invalid_salt" 
            | "weak_password" | "invalid_password" => {
                ("configuration_error".to_string(), "Server configuration error".to_string())
            }
            
            // Parsing errors - safe to expose as they don't leak sensitive data
            "parse_error" | "invalid_utf8" | "decode_error" => {
                (error.error.clone(), "Invalid data format".to_string())
            }
            
            // Authentication/Authorization errors - safe to expose
            "invalid_api_key" | "insufficient_permissions" | "admin_access_denied" 
            | "admin_config_error" => {
                (error.error.clone(), error.message.clone())
            }
            
            // Rate limiting errors - safe to expose
            "rate_limit_exceeded" => {
                (error.error.clone(), error.message.clone())
            }
            
            // Validation errors - safe generic message
            "validation_failed" | "validation_incomplete" => {
                ("validation_error".to_string(), "Request validation failed".to_string())
            }
            
            // All other errors get a generic response
            _ => {
                tracing::warn!("Sanitizing unhandled error type: {}", error.error);
                ("internal_error".to_string(), "Internal server error".to_string())
            }
        };

        // Log the original error for debugging while returning sanitized version
        if matches!(error.error.as_str(), 
                   "firestore_init_error" | "firestore_create_error" | "firestore_delete_error" 
                   | "database_error" | "database_update_error" | "encryption_error" 
                   | "decryption_error" | "decryption_failed" | "key_error") {
            tracing::error!("Internal error (sanitized for client): {} - {}", 
                          error.error, error.message);
        }

        SanitizedError {
            error: sanitized_error,
            message: sanitized_message,
            code: error.code,
        }
    }

    /// Sanitizes generic error messages
    pub fn sanitize_generic_error(error_type: &str, message: &str, code: u16) -> SanitizedError {
        let auth_error = AuthError {
            error: error_type.to_string(),
            message: message.to_string(),
            code,
        };
        Self::sanitize_auth_error(&auth_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_database_error() {
        let error = AuthError {
            error: "firestore_create_error".to_string(),
            message: "Failed to connect to projects/my-secret-project/databases/production".to_string(),
            code: 500,
        };

        let sanitized = ErrorSanitizer::sanitize_auth_error(&error);
        assert_eq!(sanitized.error, "database_error");
        assert_eq!(sanitized.message, "Database operation failed");
        assert_eq!(sanitized.code, 500);
    }

    #[test]
    fn test_sanitize_encryption_error() {
        let error = AuthError {
            error: "decryption_failed".to_string(),
            message: "AES-GCM decryption failed with key: abc123...".to_string(),
            code: 500,
        };

        let sanitized = ErrorSanitizer::sanitize_auth_error(&error);
        assert_eq!(sanitized.error, "encryption_error");
        assert_eq!(sanitized.message, "Encryption operation failed");
        assert_eq!(sanitized.code, 500);
    }

    #[test]
    fn test_preserve_safe_errors() {
        let error = AuthError {
            error: "invalid_api_key".to_string(),
            message: "Invalid or expired API key".to_string(),
            code: 401,
        };

        let sanitized = ErrorSanitizer::sanitize_auth_error(&error);
        assert_eq!(sanitized.error, "invalid_api_key");
        assert_eq!(sanitized.message, "Invalid or expired API key");
        assert_eq!(sanitized.code, 401);
    }

    #[test]
    fn test_sanitize_unknown_error() {
        let error = AuthError {
            error: "some_internal_error".to_string(),
            message: "Detailed internal state information".to_string(),
            code: 500,
        };

        let sanitized = ErrorSanitizer::sanitize_auth_error(&error);
        assert_eq!(sanitized.error, "internal_error");
        assert_eq!(sanitized.message, "Internal server error");
        assert_eq!(sanitized.code, 500);
    }
}