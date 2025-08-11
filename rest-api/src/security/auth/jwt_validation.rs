use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoTokenClaims {
    pub sub: String,
    pub tier: String,
    pub exp: u64,
    pub iat: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Token expired")]
    Expired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid tier claim")]
    InvalidTier,
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    #[error("JWT decode error: {0}")]
    DecodeError(#[from] jsonwebtoken::errors::Error),
}

impl From<JwtError> for AuthError {
    fn from(jwt_error: JwtError) -> Self {
        match jwt_error {
            JwtError::InvalidFormat => AuthError {
                error: "invalid_jwt_format".to_string(),
                message: "JWT token has invalid format".to_string(),
                code: 400,
            },
            JwtError::Expired => AuthError {
                error: "jwt_expired".to_string(),
                message: "JWT token has expired".to_string(),
                code: 401,
            },
            JwtError::InvalidSignature => AuthError {
                error: "invalid_jwt_signature".to_string(),
                message: "JWT signature validation failed".to_string(),
                code: 401,
            },
            JwtError::InvalidTier => AuthError {
                error: "invalid_tier".to_string(),
                message: "JWT token tier must be 'demo'".to_string(),
                code: 403,
            },
            JwtError::MissingClaim(claim) => AuthError {
                error: "missing_jwt_claim".to_string(),
                message: format!("JWT token missing required claim: {}", claim),
                code: 400,
            },
            JwtError::DecodeError(e) => AuthError {
                error: "jwt_decode_error".to_string(),
                message: format!("Failed to decode JWT: {}", e),
                code: 400,
            },
        }
    }
}

pub struct JwtValidator {
    secret: String,
    validation: Validation,
}

impl JwtValidator {
    pub fn new(secret: String) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("tier".to_string());

        Self { secret, validation }
    }

    pub fn validate_demo_token(&self, token: &str) -> Result<DemoTokenClaims, JwtError> {
        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());
        
        let token_data = decode::<DemoTokenClaims>(
            token,
            &decoding_key,
            &self.validation,
        )?;

        let claims = token_data.claims;

        if claims.tier != "demo" {
            return Err(JwtError::InvalidTier);
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtError::InvalidFormat)?
            .as_secs();

        if claims.exp < current_time {
            return Err(JwtError::Expired);
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_token(secret: &str, tier: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = DemoTokenClaims {
            sub: "test_user".to_string(),
            tier: tier.to_string(),
            exp: (now as i64 + exp_offset) as u64,
            iat: now,
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());

        encode(&header, &claims, &encoding_key).unwrap()
    }

    #[test]
    fn test_valid_demo_token() {
        let secret = "test_secret";
        let validator = JwtValidator::new(secret.to_string());
        let token = create_test_token(secret, "demo", 3600);

        let result = validator.validate_demo_token(&token);
        assert!(result.is_ok());
        
        let claims = result.unwrap();
        assert_eq!(claims.tier, "demo");
        assert_eq!(claims.sub, "test_user");
    }

    #[test]
    fn test_invalid_tier() {
        let secret = "test_secret";
        let validator = JwtValidator::new(secret.to_string());
        let token = create_test_token(secret, "premium", 3600);

        let result = validator.validate_demo_token(&token);
        assert!(matches!(result, Err(JwtError::InvalidTier)));
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret";
        let validator = JwtValidator::new(secret.to_string());
        let token = create_test_token(secret, "demo", -3600);

        let result = validator.validate_demo_token(&token);
        assert!(matches!(result, Err(JwtError::Expired)));
    }

    #[test]
    fn test_invalid_signature() {
        let validator = JwtValidator::new("correct_secret".to_string());
        let token = create_test_token("wrong_secret", "demo", 3600);

        let result = validator.validate_demo_token(&token);
        assert!(result.is_err());
    }
}