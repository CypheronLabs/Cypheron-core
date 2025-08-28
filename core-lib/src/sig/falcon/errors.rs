use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FalconErrors {
    #[error("RNG initialization failed (shake256_init_prng_from_system)")]
    RngInitializationFailed,

    #[error("Key generation failed - insufficient entropy")]
    KeyGenerationEntropyFailure,

    #[error("Key generation failed - internal computation error")]
    KeyGenerationInternalError,

    #[error("Key generation failed - invalid parameters")]
    KeyGenerationInvalidParameters,

    #[error("Signing failed - insufficient entropy")]
    SigningEntropyFailure,

    #[error("Signing failed - internal computation error")]
    SigningInternalError,

    #[error("Signing failed - invalid parameters")]
    SigningInvalidParameters,

    #[error("Verification failed - invalid signature format")]
    VerificationInvalidSignature,

    #[error("Invalid input parameters")]
    InvalidInput,

    #[error("Internal consistency error")]
    InternalConsistencyError,

    #[error("FFI validation error: {0}")]
    FfiValidationError(String),

    #[error("Falcon C library returned error code: {code}")]
    CLibraryError { code: i32 },
}

impl FalconErrors {
    pub fn from_c_code(code: i32, operation: &str) -> Self {
        match code {
            0 => panic!("Should not map success code 0 to error"),
            -1 => match operation {
                "keypair" => FalconErrors::KeyGenerationInternalError,
                "sign" => FalconErrors::SigningInternalError,
                "verify" => FalconErrors::VerificationInvalidSignature,
                _ => FalconErrors::InternalConsistencyError,
            },
            -2 => match operation {
                "keypair" => FalconErrors::KeyGenerationEntropyFailure,
                "sign" => FalconErrors::SigningEntropyFailure,
                _ => FalconErrors::RngInitializationFailed,
            },
            -3 => match operation {
                "keypair" => FalconErrors::KeyGenerationInvalidParameters,
                "sign" => FalconErrors::SigningInvalidParameters,
                _ => FalconErrors::InvalidInput,
            },
            _ => FalconErrors::CLibraryError { code },
        }
    }
}

impl From<&str> for FalconErrors {
    fn from(msg: &str) -> Self {
        FalconErrors::FfiValidationError(msg.to_string())
    }
}
