// sphincs/mod.rs
pub mod api;
mod bindings;
pub mod engine;
pub mod types;

pub use api::{
    keypair, 
    keypair_from_seed, 
    sign_detached, 
    verify_detached, 
    sign_combined, 
    open_combined,
    ALGORITHM_NAME, 
    public_key_bytes, 
    secret_key_bytes, 
    signature_bytes, 
    seed_bytes,
};
pub use types::{
    PublicKey, 
    SecretKey, 
    Signature, 
    Seed
};
