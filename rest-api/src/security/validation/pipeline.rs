use super::{ValidatorType, ValidationContext, ValidationResult, ValidationStep};
use crate::security::auth::{AuthError, PostQuantumEncryption};
use crate::security::auth::hybrid_encryption::HybridEncryption;
use std::sync::Arc;

#[derive(Clone)]
pub struct ValidationPipeline {
    validators: Vec<ValidatorType>,
}

impl ValidationPipeline {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    pub fn add_validator(mut self, validator: ValidatorType) -> Self {
        self.validators.push(validator);
        self
    }

    pub fn new_default(encryption: Arc<PostQuantumEncryption>) -> Self {
        Self::new()
            .add_validator(ValidatorType::DocumentParsing)
            .add_validator(ValidatorType::Decryption(encryption.clone()))
            .add_validator(ValidatorType::Hash(encryption))
            .add_validator(ValidatorType::Expiration)
            .add_validator(ValidatorType::Completion)
    }

    pub fn new_hybrid(legacy: Arc<PostQuantumEncryption>, hybrid: Arc<HybridEncryption>) -> Self {
        Self::new()
            .add_validator(ValidatorType::DocumentParsing)
            .add_validator(ValidatorType::HybridDecryption {
                legacy: legacy.clone(),
                hybrid: hybrid.clone(),
            })
            .add_validator(ValidatorType::HybridHash {
                legacy,
                hybrid,
            })
            .add_validator(ValidatorType::Expiration)
            .add_validator(ValidatorType::Completion)
    }

    pub async fn validate(&self, mut context: ValidationContext) -> Result<ValidationResult, AuthError> {
        for validator in &self.validators {
            match validator.validate(&context).await? {
                ValidationStep::Continue(updated_context) => {
                    context = updated_context;
                }
                ValidationStep::Complete(result) => {
                    return Ok(result);
                }
                ValidationStep::Failed(reason) => {
                    tracing::warn!("Validation failed: {}", reason);
                    return Err(AuthError {
                        error: "validation_failed".to_string(),
                        message: reason,
                        code: 401,
                    });
                }
            }
        }

        Err(AuthError {
            error: "validation_incomplete".to_string(),
            message: "Validation pipeline completed without result".to_string(),
            code: 500,
        })
    }
}

impl Default for ValidationPipeline {
    fn default() -> Self {
        Self::new()
    }
}