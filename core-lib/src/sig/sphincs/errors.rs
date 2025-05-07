use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SphincsError {
    #[error("Invalid public key length")]
    InvalidPublicKeyLength,
    #[error("Invalid secret key length")]
    InvalidSecretKeyLength,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
}