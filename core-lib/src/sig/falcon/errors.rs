// Copyright 2025 Cypheron Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use thiserror::Error;
use crate::security::ValidationError;

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
    
    #[error("Input validation error: {0}")]
    ValidationError(#[from] ValidationError),
}

impl FalconErrors {
    pub fn from_c_code(code: i32, operation: &str) -> Self {
        match code {
            0 => {
                debug_assert!(false, "Should not map success code 0 to error");
                FalconErrors::CLibraryError { code: 0 }
            },
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
