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
pub enum SphincsError {
    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    #[error("Invalid secret key length: expected {expected}, got {actual}")]
    InvalidSecretKeyLength { expected: usize, actual: usize },
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength { expected: usize, actual: usize },
    #[error("Key pair generation failed. FFI call returned code: {0}")]
    KeyPairGenerationFailed(i32),
    #[error("Signing operation failed. FFI call returned code: {0}")]
    SigningFailed(i32),
    #[error("Signature verification failed. The signature is invalid or does not match the message/public key.")]
    VerificationFailed,
    #[error("Opening signed message failed. FFI call returned code: {0}")]
    OpenFailed(i32),
    #[error("An internal cryptographic error occurred in the FFI layer with code: {0}")]
    InternalCryptoError(i32),
    #[error("Output buffer too small during FFI call.")]
    OutputBufferTooSmall,
    #[error("FFI returned unexpected signature length: expected {expected}, got {actual}.")]
    UnexpectedSignatureLength { expected: usize, actual: usize },
    #[error("Message too large for cryptographic operation")]
    MessageTooLarge,
    #[error("Integer overflow detected in size conversion")]
    IntegerOverflow,
    #[error("Input validation error: {0}")]
    ValidationError(#[from] ValidationError),
}
