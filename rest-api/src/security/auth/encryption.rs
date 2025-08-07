use core_lib::platform::secure_random_bytes;
use ring::{aead, pbkdf2};
use std::num::NonZeroU32;

use super::errors::AuthError;

pub struct PostQuantumEncryption {
    key: [u8; 32],
}

impl std::fmt::Debug for PostQuantumEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostQuantumEncryption")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for PostQuantumEncryption {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
        }
    }
}

impl PostQuantumEncryption {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        secure_random_bytes(&mut key).expect("Failed to generate secure random bytes");
        Self { key }
    }

    pub fn from_password(password: &str) -> Result<Self, AuthError> {
        if password.is_empty() {
            return Err(AuthError {
                error: "invalid_password".to_string(),
                message: "Master password cannot be empty".to_string(),
                code: 500,
            });
        }

        if password.len() < 32 {
            return Err(AuthError {
                error: "weak_password".to_string(),
                message: "Master password must be at least 32 characters".to_string(),
                code: 500,
            });
        }
        
        let salt = std::env::var("PQ_ENCRYPTION_SALT").map_err(|_| AuthError {
            error: "missing_salt".to_string(),
            message: "PQ_ENCRYPTION_SALT environment variable is required".to_string(),
            code: 500,
        })?;

        if salt.len() < 16 {
            return Err(AuthError {
                error: "invalid_salt".to_string(),
                message: "Encryption salt must be at least 16 bytes".to_string(),
                code: 500,
            });
        }

        const PBKDF2_ITERATIONS: u32 = 100_000;
        
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt.as_bytes(),
            password.as_bytes(),
            &mut key,
        );
        
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
                .map_err(|_| AuthError {
                    error: "key_error".to_string(),
                    message: "Failed to create encryption key".to_string(),
                    code: 500,
                })?
        );

        let mut nonce_bytes = [0u8; 12];
        secure_random_bytes(&mut nonce_bytes).map_err(|_| AuthError {
            error: "random_error".to_string(),
            message: "Failed to generate nonce".to_string(),
            code: 500,
        })?;
        
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        
        sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| AuthError {
                error: "encryption_error".to_string(),
                message: "Failed to encrypt data".to_string(),
                code: 500,
            })?;

        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        
        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, AuthError> {
        if encrypted_data.len() < 12 + 16 {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Encrypted data too short".to_string(),
                code: 400,
            });
        }

        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
                .map_err(|_| AuthError {
                    error: "key_error".to_string(),
                    message: "Failed to create decryption key".to_string(),
                    code: 500,
                })?
        );

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce_bytes);
        
        let nonce = aead::Nonce::assume_unique_for_key(nonce_array);
        let mut in_out = ciphertext.to_vec();
        
        let plaintext = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| AuthError {
                error: "decryption_error".to_string(),
                message: "Failed to decrypt data".to_string(),
                code: 500,
            })?;

        Ok(plaintext.to_vec())
    }
}