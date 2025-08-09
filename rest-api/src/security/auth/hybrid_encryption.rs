use core_lib::hybrid::{P256MlKem768, HybridCiphertext};
use core_lib::hybrid::composite::{CompositePublicKey, CompositeSecretKey};
use core_lib::hybrid::kem::{P256PublicKeyWrapper, P256SecretKeyWrapper, MlKemPublicKeyWrapper, MlKemSecretKeyWrapper};
use core_lib::hybrid::traits::HybridKemEngine;
use core_lib::platform::secure_random_bytes;
use ring::aead;
use serde::{Deserialize, Serialize};
use super::encryption::PostQuantumEncryption; // For backward compatibility
use super::errors::AuthError;

/// Encryption format versions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionVersion {
    V1AES256 = 1,      // Legacy AES256-GCM
    V2Hybrid = 2,      // P256 + ML-KEM-768 + AES256-GCM
}

impl From<u8> for EncryptionVersion {
    fn from(value: u8) -> Self {
        match value {
            1 => EncryptionVersion::V1AES256,
            2 => EncryptionVersion::V2Hybrid,
            _ => EncryptionVersion::V1AES256, // Default to V1 for compatibility
        }
    }
}

/// Versioned encrypted data format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedEncryptedData {
    pub version: u8,
    pub data: Vec<u8>,
}

/// Hybrid encryption using P256 + ML-KEM-768 for API key storage
pub struct HybridEncryption {
    // Optional master key for V1 compatibility
    legacy_encryption: Option<PostQuantumEncryption>,
    // Master keypair for hybrid encryption (stored securely)
    master_keypair: Option<(CompositePublicKey<P256PublicKeyWrapper, MlKemPublicKeyWrapper>, CompositeSecretKey<P256SecretKeyWrapper, MlKemSecretKeyWrapper>)>,
}

impl std::fmt::Debug for HybridEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridEncryption")
            .field("legacy_encryption", &self.legacy_encryption.is_some())
            .field("master_keypair", &self.master_keypair.is_some())
            .finish()
    }
}

impl Clone for HybridEncryption {
    fn clone(&self) -> Self {
        Self {
            legacy_encryption: self.legacy_encryption.clone(),
            master_keypair: None, // Don't clone secret keys for security
        }
    }
}

impl HybridEncryption {
    /// Create new hybrid encryption instance (V2 only)
    pub fn new() -> Result<Self, AuthError> {
        // Generate master keypair for this instance
        let (public_key, secret_key) = P256MlKem768::keypair()
            .map_err(|e| AuthError {
                error: "hybrid_keygen_failed".to_string(),
                message: format!("Failed to generate master keypair: {}", e),
                code: 500,
            })?;

        Ok(Self {
            legacy_encryption: None,
            master_keypair: Some((public_key, secret_key)),
        })
    }

    /// Create hybrid encryption with legacy support for existing keys
    pub fn with_legacy_support(password: &str) -> Result<Self, AuthError> {
        // Generate master keypair for hybrid encryption
        let (public_key, secret_key) = P256MlKem768::keypair()
            .map_err(|e| AuthError {
                error: "hybrid_keygen_failed".to_string(),
                message: format!("Failed to generate master keypair: {}", e),
                code: 500,
            })?;

        Ok(Self {
            legacy_encryption: Some(PostQuantumEncryption::from_password(password)?),
            master_keypair: Some((public_key, secret_key)),
        })
    }

    /// Encrypt data using hybrid P256 + ML-KEM-768 scheme (V2)
    pub fn encrypt_hybrid(&self, plaintext: &[u8]) -> Result<VersionedEncryptedData, AuthError> {
        // Use the master public key for encryption
        let public_key = match &self.master_keypair {
            Some((pk, _)) => pk,
            None => return Err(AuthError {
                error: "no_master_key".to_string(),
                message: "No master keypair available for hybrid encryption".to_string(),
                code: 500,
            }),
        };

        // Encapsulate to get shared secret and ciphertext
        let (hybrid_ciphertext, shared_secret) = P256MlKem768::encapsulate(public_key)
            .map_err(|e| AuthError {
                error: "hybrid_encapsulation_failed".to_string(),
                message: format!("Failed to encapsulate: {}", e),
                code: 500,
            })?;

        // Use shared secret as AES-256-GCM key
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, shared_secret.as_bytes())
                .map_err(|_| AuthError {
                    error: "aes_key_error".to_string(),
                    message: "Failed to create AES key from shared secret".to_string(),
                    code: 500,
                })?
        );

        // Generate random nonce for AES
        let mut nonce_bytes = [0u8; 12];
        secure_random_bytes(&mut nonce_bytes).map_err(|_| AuthError {
            error: "random_error".to_string(),
            message: "Failed to generate AES nonce".to_string(),
            code: 500,
        })?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut aes_plaintext = plaintext.to_vec();

        // Encrypt with AES-256-GCM
        sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut aes_plaintext)
            .map_err(|_| AuthError {
                error: "aes_encryption_error".to_string(),
                message: "Failed to encrypt with AES-256-GCM".to_string(),
                code: 500,
            })?;

        // Serialize the complete encrypted structure
        // Note: secret_key_bytes is empty as the secret key is stored securely in the instance
        let encrypted_data = HybridEncryptedData {
            hybrid_ciphertext,
            aes_nonce: nonce_bytes.to_vec(),
            aes_ciphertext: aes_plaintext,
            secret_key_bytes: vec![], // Secret key stored securely in master_keypair
        };

        let serialized_data = serde_json::to_vec(&encrypted_data)
            .map_err(|e| AuthError {
                error: "serialization_error".to_string(),
                message: format!("Failed to serialize encrypted data: {}", e),
                code: 500,
            })?;

        Ok(VersionedEncryptedData {
            version: EncryptionVersion::V2Hybrid as u8,
            data: serialized_data,
        })
    }

    /// Decrypt versioned encrypted data
    pub fn decrypt(&self, encrypted_data: &VersionedEncryptedData) -> Result<Vec<u8>, AuthError> {
        let version = EncryptionVersion::from(encrypted_data.version);
        
        match version {
            EncryptionVersion::V1AES256 => {
                // Use legacy AES256 decryption
                match &self.legacy_encryption {
                    Some(legacy) => legacy.decrypt(&encrypted_data.data),
                    None => Err(AuthError {
                        error: "no_legacy_support".to_string(),
                        message: "Cannot decrypt V1 data without legacy password".to_string(),
                        code: 500,
                    }),
                }
            },
            EncryptionVersion::V2Hybrid => {
                self.decrypt_hybrid(&encrypted_data.data)
            },
        }
    }

    /// Decrypt hybrid encrypted data (V2)
    fn decrypt_hybrid(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        // Deserialize the encrypted data structure
        let encrypted_data: HybridEncryptedData = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| AuthError {
                error: "deserialization_error".to_string(),
                message: format!("Failed to deserialize encrypted data: {}", e),
                code: 500,
            })?;

        // Get the master secret key for decryption
        let secret_key = match &self.master_keypair {
            Some((_, sk)) => sk,
            None => return Err(AuthError {
                error: "no_master_key".to_string(),
                message: "No master keypair available for hybrid decryption".to_string(),
                code: 500,
            }),
        };

        // Decapsulate to get shared secret
        let shared_secret = P256MlKem768::decapsulate(&encrypted_data.hybrid_ciphertext, secret_key)
            .map_err(|e| AuthError {
                error: "hybrid_decapsulation_failed".to_string(),
                message: format!("Failed to decapsulate: {}", e),
                code: 500,
            })?;

        // Reconstruct AES-256-GCM key
        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, shared_secret.as_bytes())
                .map_err(|_| AuthError {
                    error: "aes_key_error".to_string(),
                    message: "Failed to create AES key from shared secret".to_string(),
                    code: 500,
                })?
        );

        // Reconstruct nonce
        if encrypted_data.aes_nonce.len() != 12 {
            return Err(AuthError {
                error: "invalid_nonce".to_string(),
                message: "Invalid AES nonce length".to_string(),
                code: 500,
            });
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&encrypted_data.aes_nonce);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Decrypt with AES-256-GCM
        let mut aes_ciphertext = encrypted_data.aes_ciphertext;
        let plaintext = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut aes_ciphertext)
            .map_err(|_| AuthError {
                error: "aes_decryption_error".to_string(),
                message: "Failed to decrypt with AES-256-GCM".to_string(),
                code: 500,
            })?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt using the default (latest) version
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<VersionedEncryptedData, AuthError> {
        self.encrypt_hybrid(plaintext)
    }
}

/// Internal structure for hybrid encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HybridEncryptedData {
    pub hybrid_ciphertext: HybridCiphertext,
    pub aes_nonce: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
    pub secret_key_bytes: Vec<u8>, // Serialized secret key for decryption
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = b"test-api-key-12345";

        // Encrypt
        let encrypted = encryption.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.version, EncryptionVersion::V2Hybrid as u8);

        // Decrypt
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertexts() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = b"test-api-key";

        let encrypted1 = encryption.encrypt(plaintext).unwrap();
        let encrypted2 = encryption.encrypt(plaintext).unwrap();

        // Different encryptions should produce different ciphertexts
        assert_ne!(encrypted1.data, encrypted2.data);

        // But both should decrypt to the same plaintext
        assert_eq!(encryption.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(encryption.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_legacy_compatibility() {
        let test_password = "a".repeat(32); // 32-character password
        let encryption = HybridEncryption::with_legacy_support(&test_password).unwrap();
        
        // Should work with hybrid encryption
        let plaintext = b"test-hybrid-encryption";
        let encrypted = encryption.encrypt_hybrid(plaintext).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encryption_version_handling() {
        // Test version enum conversion
        assert_eq!(EncryptionVersion::from(1), EncryptionVersion::V1AES256);
        assert_eq!(EncryptionVersion::from(2), EncryptionVersion::V2Hybrid);
        assert_eq!(EncryptionVersion::from(99), EncryptionVersion::V1AES256); // Unknown defaults to V1
    }

    #[test]
    fn test_versioned_encrypted_data_serialization() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = b"serialization-test-data";

        let encrypted = encryption.encrypt(plaintext).unwrap();
        
        // Test serialization/deserialization
        let serialized = serde_json::to_vec(&encrypted).unwrap();
        let deserialized: VersionedEncryptedData = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(encrypted.version, deserialized.version);
        assert_eq!(encrypted.data, deserialized.data);

        // Verify it still decrypts correctly
        let decrypted = encryption.decrypt(&deserialized).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_multiple_api_keys_different_encryption() {
        let encryption = HybridEncryption::new().unwrap();
        let api_keys = [
            b"pq_test_1234567890abcdef",
            b"pq_prod_fedcba0987654321", 
            b"pq_dev_1111222233334444",
        ];

        let mut encrypted_keys = Vec::new();

        // Encrypt all keys
        for key in &api_keys {
            let encrypted = encryption.encrypt(key).unwrap();
            assert_eq!(encrypted.version, EncryptionVersion::V2Hybrid as u8);
            encrypted_keys.push(encrypted);
        }

        // Verify all encrypted data is different
        for i in 0..encrypted_keys.len() {
            for j in i + 1..encrypted_keys.len() {
                assert_ne!(encrypted_keys[i].data, encrypted_keys[j].data);
            }
        }

        // Verify all keys decrypt correctly
        for (i, encrypted) in encrypted_keys.iter().enumerate() {
            let decrypted = encryption.decrypt(encrypted).unwrap();
            assert_eq!(&decrypted, api_keys[i]);
        }
    }

    #[test]
    fn test_backward_compatibility_v1_simulation() {
        let test_password = "a".repeat(32);
        let encryption = HybridEncryption::with_legacy_support(&test_password).unwrap();
        let plaintext = b"legacy-api-key-test";

        // Simulate V1 encrypted data using legacy encryption directly
        let legacy_enc = PostQuantumEncryption::from_password(&test_password).unwrap();
        let legacy_encrypted = legacy_enc.encrypt(plaintext).unwrap();

        let v1_data = VersionedEncryptedData {
            version: EncryptionVersion::V1AES256 as u8,
            data: legacy_encrypted,
        };

        // Should be able to decrypt V1 data
        let decrypted = encryption.decrypt(&v1_data).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_without_legacy_support_fails_v1() {
        let encryption = HybridEncryption::new().unwrap(); // No legacy support

        let v1_data = VersionedEncryptedData {
            version: EncryptionVersion::V1AES256 as u8,
            data: vec![1, 2, 3, 4], // Dummy data
        };

        // Should fail to decrypt V1 data without legacy support
        let result = encryption.decrypt(&v1_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().error.contains("no_legacy_support"));
    }

    #[test]
    fn test_empty_data_encryption() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = b"";

        let encrypted = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_large_data_encryption() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = vec![0xAA; 10000]; // 10KB of data

        let encrypted = encryption.encrypt(&plaintext).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_randomness() {
        let encryption = HybridEncryption::new().unwrap();
        let plaintext = b"randomness-test";

        // Encrypt same data multiple times
        let mut encrypted_datas = Vec::new();
        for _ in 0..10 {
            let encrypted = encryption.encrypt(plaintext).unwrap();
            encrypted_datas.push(encrypted);
        }

        // All should be different due to randomness in hybrid KEM and AES nonces
        for i in 0..encrypted_datas.len() {
            for j in i + 1..encrypted_datas.len() {
                assert_ne!(encrypted_datas[i].data, encrypted_datas[j].data);
            }
        }

        // All should decrypt to same plaintext
        for encrypted in &encrypted_datas {
            let decrypted = encryption.decrypt(encrypted).unwrap();
            assert_eq!(&decrypted, plaintext);
        }
    }

    #[test]
    fn test_invalid_json_handling() {
        let encryption = HybridEncryption::new().unwrap();

        // Test invalid JSON in V2 data
        let invalid_v2_data = VersionedEncryptedData {
            version: EncryptionVersion::V2Hybrid as u8,
            data: b"not-valid-json".to_vec(),
        };

        let result = encryption.decrypt(&invalid_v2_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().error.contains("deserialization_error"));
    }

    #[test] 
    fn test_api_key_typical_sizes() {
        let encryption = HybridEncryption::new().unwrap();
        
        // Test typical API key formats
        let test_keys = [
            b"pq_test_abcd1234efgh5678", // 24 chars
            b"pq_live_1234567890123456789012345678901234567890", // 48 chars  
            b"pk_test_51234567890123456789012345678901234567890123456789012345", // 64 chars
        ];

        for key in &test_keys {
            let encrypted = encryption.encrypt(key).unwrap();
            let decrypted = encryption.decrypt(&encrypted).unwrap();
            assert_eq!(&decrypted, key);
            
            // Verify version
            assert_eq!(encrypted.version, EncryptionVersion::V2Hybrid as u8);
        }
    }

    #[test]
    fn test_concurrent_encryption() {
        use std::thread;
        use std::sync::Arc;

        let encryption = Arc::new(HybridEncryption::new());
        let plaintext = Arc::new(b"concurrent-test-data".to_vec());

        let mut handles = Vec::new();

        // Spawn multiple threads doing encryption/decryption
        for i in 0..10 {
            let enc = encryption.clone();
            let data = plaintext.clone();
            
            handles.push(thread::spawn(move || {
                let mut test_data = data.as_slice().to_vec();
                test_data.extend(format!("-thread-{}", i).bytes());
                
                let encrypted = enc.encrypt(&test_data).unwrap();
                let decrypted = enc.decrypt(&encrypted).unwrap();
                
                assert_eq!(decrypted, test_data);
                encrypted
            }));
        }

        // Collect results and verify all different
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // All results should be different
        for i in 0..results.len() {
            for j in i + 1..results.len() {
                assert_ne!(results[i].data, results[j].data);
            }
        }
    }
}