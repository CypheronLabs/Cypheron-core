use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FalconErrors {
    #[error("RNG initialization failed (shake256_init_prng_from_system)")]
    RngInitializationFailed,

    #[error("Key generation failed (falcon_keygen_make returned error)")]
    KeyGenerationFailed,

    #[error("Signing failed (falcon_sign_dyn returned error)")]
    SigningFailed,

    #[error("Invalid input (falcon_input returned error)")]
    InvalidInput,

    #[error("Internal consistency error (internal_error returned error")]
    InternalConsistencyError,
}
