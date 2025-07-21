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
    #[error("Dilithium C library returned error code: {code}")]
    CLibraryError { code: i32 },
    #[error("Invalid input parameters provided to Dilithium function")]
    InvalidInput,
    #[error("Memory allocation failed in Dilithium operation")]
    MemoryAllocationFailed,
    #[error("Cryptographic operation failed - possible invalid key or signature")]
    CryptographicFailure,
}

impl DilithiumError {
    /// Maps C library error codes to specific Rust error types
    pub fn from_c_code(code: i32, operation: &str) -> Self {
        match code {
            0 => panic!("Should not map success code 0 to error"),
            -1 => match operation {
                "keypair" => DilithiumError::KeyGenerationInternalError,
                "sign" => DilithiumError::SigningInternalError,
                _ => DilithiumError::CryptographicFailure,
            },
            1 => DilithiumError::InvalidInput,
            2 => DilithiumError::MemoryAllocationFailed,
            3 => match operation {
                "keypair" => DilithiumError::KeyGenerationRngFailure,
                "sign" => DilithiumError::SigningRngFailure,
                _ => DilithiumError::CryptographicFailure,
            },
            _ => DilithiumError::CLibraryError { code },
        }
    }
}
