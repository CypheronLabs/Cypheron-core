use thiserror::Error;
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
}