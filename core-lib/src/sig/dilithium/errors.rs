// src/sig/dilithium/errors.rs (MUST EXIST)
use thiserror::Error;

/// Represents errors that can occur during Dilithium operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DilithiumError {
    #[error("Random number generation failed during key generation")]
    KeyGenerationRngFailure,
    #[error("An internal error occurred during key generation")]
    KeyGenerationInternalError,
    #[error("Random number generation failed during signing")]
    SigningRngFailure,
    #[error("An internal error occurred during signing")]
    SigningInternalError,
}