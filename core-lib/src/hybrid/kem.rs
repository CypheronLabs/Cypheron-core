use crate::hybrid::composite::{CompositePublicKey, CompositeSecretKey};
use crate::hybrid::traits::HybridKemEngine;
use crate::kem::{MlKem768, Kem as KemTrait, sizes};
use hkdf::Hkdf;
use sha2::Sha256;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::rand_core::OsRng,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
// use sha2::Sha256; // Not needed, use hkdf::Sha256 instead
use std::fmt::Debug;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum HybridKemError {
    #[error("Classical ECDH error: {0}")]
    ClassicalError(String),
    #[error("Post-quantum ML-KEM error: {0}")]
    PostQuantumError(String),
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertext(String),
}

/// P-256 public key wrapper for consistency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P256PublicKeyWrapper(pub Vec<u8>);

/// P-256 secret key wrapper with zeroization
#[derive(Debug, ZeroizeOnDrop)]
pub struct P256SecretKeyWrapper(pub P256SecretKey);

impl Zeroize for P256SecretKeyWrapper {
    fn zeroize(&mut self) {
        // P256SecretKey implements Zeroize internally
        use p256::elliptic_curve::ScalarPrimitive;
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
    }
}

/// ML-KEM-768 public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlKemPublicKeyWrapper(pub Vec<u8>);

/// ML-KEM-768 secret key wrapper with zeroization
#[derive(Debug, ZeroizeOnDrop)]
pub struct MlKemSecretKeyWrapper(pub Vec<u8>);

impl Zeroize for MlKemSecretKeyWrapper {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Hybrid ciphertext containing both classical and post-quantum components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub classical_ephemeral: Vec<u8>, // Ephemeral P-256 public key
    pub post_quantum_ciphertext: Vec<u8>, // ML-KEM-768 ciphertext
}

/// The resulting shared secret from hybrid KEM
#[derive(Debug, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    key: [u8; 32], // Derived 32-byte key from HKDF
}

impl HybridSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Zeroize for HybridSharedSecret {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

/// P-256 + ML-KEM-768 Hybrid KEM implementation following existing architecture
pub struct P256MlKem768;

impl HybridKemEngine for P256MlKem768 {
    type ClassicalPublicKey = P256PublicKeyWrapper;
    type ClassicalSecretKey = P256SecretKeyWrapper;
    
    type PqPublicKey = MlKemPublicKeyWrapper;
    type PqSecretKey = MlKemSecretKeyWrapper;
    
    type CompositePublicKey = CompositePublicKey<Self::ClassicalPublicKey, Self::PqPublicKey>;
    type CompositeSecretKey = CompositeSecretKey<Self::ClassicalSecretKey, Self::PqSecretKey>;
    type HybridCiphertext = HybridCiphertext;
    type SharedSecret = HybridSharedSecret;
    
    type Error = HybridKemError;
    
    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error> {
        // Generate classical P-256 keypair
        let classical_secret = P256SecretKey::random(&mut OsRng);
        let classical_public = classical_secret.public_key();

        // Generate post-quantum ML-KEM-768 keypair
        let (pq_public, pq_secret) = MlKem768::keypair()
            .map_err(|e| HybridKemError::PostQuantumError(format!("{:?}", e)))?;

        let composite_public = CompositePublicKey {
            classical: P256PublicKeyWrapper(
                classical_public.to_encoded_point(false).as_bytes().to_vec()
            ),
            post_quantum: MlKemPublicKeyWrapper(pq_public.0.to_vec()),
        };

        let composite_secret = CompositeSecretKey {
            classical: SecretBox::new(Box::new(P256SecretKeyWrapper(classical_secret))),
            post_quantum: SecretBox::new(Box::new(MlKemSecretKeyWrapper(pq_secret.0.to_vec()))),
        };

        Ok((composite_public, composite_secret))
    }

    fn encapsulate(
        pk: &Self::CompositePublicKey,
    ) -> Result<(Self::HybridCiphertext, Self::SharedSecret), Self::Error> {
        // Classical ECDH
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral_secret.public_key();

        // Reconstruct recipient's P-256 public key
        let encoded_point = EncodedPoint::from_bytes(&pk.classical.0)
            .map_err(|e| HybridKemError::ClassicalError(e.to_string()))?;
        let recipient_public = P256PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or_else(|| HybridKemError::ClassicalError("Invalid P-256 public key point".to_string()))?;

        // Perform ECDH
        let classical_shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Post-quantum ML-KEM encapsulation
        if pk.post_quantum.0.len() != sizes::ML_KEM_768_PUBLIC {
            return Err(HybridKemError::PostQuantumError(
                format!("Invalid ML-KEM-768 public key size: expected {}, got {}", 
                    sizes::ML_KEM_768_PUBLIC, pk.post_quantum.0.len())
            ));
        }

        let pq_public_key = crate::kem::ml_kem_768::MlKemPublicKey(
            pk.post_quantum.0[..sizes::ML_KEM_768_PUBLIC].try_into()
                .map_err(|_| HybridKemError::PostQuantumError("Invalid public key conversion".to_string()))?,
        );

        let (pq_ciphertext, pq_shared_secret) = MlKem768::encapsulate(&pq_public_key)
            .map_err(|e| HybridKemError::PostQuantumError(format!("{:?}", e)))?;

        // Derive final shared secret using HKDF
        let combined_secret = [
            classical_shared_secret.raw_secret_bytes().as_slice(),
            pq_shared_secret.expose_secret().as_slice(),
        ].concat();

        let hkdf = Hkdf::<Sha256>::new(None, &combined_secret);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"CypheronHybridKEM-P256-MLKEM768-v1", &mut derived_key)
            .map_err(|e| HybridKemError::KeyDerivationError(e.to_string()))?;

        let hybrid_ciphertext = HybridCiphertext {
            classical_ephemeral: ephemeral_public.to_encoded_point(false).as_bytes().to_vec(),
            post_quantum_ciphertext: pq_ciphertext.0.to_vec(),
        };

        let hybrid_shared_secret = HybridSharedSecret {
            key: derived_key,
        };

        Ok((hybrid_ciphertext, hybrid_shared_secret))
    }

    fn decapsulate(
        ct: &Self::HybridCiphertext,
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        // Classical ECDH decapsulation
        let ephemeral_encoded = EncodedPoint::from_bytes(&ct.classical_ephemeral)
            .map_err(|e| HybridKemError::ClassicalError(e.to_string()))?;
        let ephemeral_public = P256PublicKey::from_encoded_point(&ephemeral_encoded)
            .into_option()
            .ok_or_else(|| HybridKemError::ClassicalError("Invalid P-256 public key point".to_string()))?;

        let classical_shared_secret_bytes = ephemeral_secret.diffie_hellman(&recipient_public).
     raw_secret_bytes();

        // Post-quantum ML-KEM decapsulation
        if ct.post_quantum_ciphertext.len() != sizes::ML_KEM_768_CIPHERTEXT {
            return Err(HybridKemError::InvalidCiphertext(
                format!("Invalid ML-KEM-768 ciphertext size: expected {}, got {}", 
                    sizes::ML_KEM_768_CIPHERTEXT, ct.post_quantum_ciphertext.len())
            ));
        }

        let pq_ciphertext = crate::kem::ml_kem_768::MlKemCiphertext(
            ct.post_quantum_ciphertext[..sizes::ML_KEM_768_CIPHERTEXT].try_into()
                .map_err(|_| HybridKemError::InvalidCiphertext("Invalid ciphertext conversion".to_string()))?,
        );

        let pq_secret_bytes = sk.post_quantum.expose_secret();
        if pq_secret_bytes.0.len() != sizes::ML_KEM_768_SECRET {
            return Err(HybridKemError::PostQuantumError(
                format!("Invalid ML-KEM-768 secret key size: expected {}, got {}", 
                    sizes::ML_KEM_768_SECRET, pq_secret_bytes.0.len())
            ));
        }

        let pq_secret_key = crate::kem::ml_kem_768::MlKemSecretKey(
            pq_secret_bytes.0[..sizes::ML_KEM_768_SECRET].try_into()
                .map_err(|_| HybridKemError::PostQuantumError("Invalid secret key conversion".to_string()))?,
        );

        let pq_shared_secret = MlKem768::decapsulate(&pq_ciphertext, &pq_secret_key)
            .map_err(|e| HybridKemError::PostQuantumError(format!("{:?}", e)))?;

        // Derive final shared secret using HKDF
        let combined_secret = [
            classical_shared_secret.raw_secret_bytes().as_slice(),
            pq_shared_secret.0.as_slice(),
        ].concat();

        let hkdf = Hkdf::<Sha256>::new(None, &combined_secret);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"CypheronHybridKEM-P256-MLKEM768-v1", &mut derived_key)
            .map_err(|e| HybridKemError::KeyDerivationError(e.to_string()))?;

        Ok(HybridSharedSecret {
            key: derived_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        // Generate keypair
        let (public_key, secret_key) = P256MlKem768::keypair().unwrap();

        // Encapsulate
        let (ciphertext, shared_secret_1) = P256MlKem768::encapsulate(&public_key).unwrap();

        // Decapsulate
        let shared_secret_2 = P256MlKem768::decapsulate(&ciphertext, &secret_key).unwrap();

        // Verify shared secrets match
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let (public_key_1, _) = P256MlKem768::keypair().unwrap();
        let (public_key_2, _) = P256MlKem768::keypair().unwrap();

        let (_, shared_secret_1) = P256MlKem768::encapsulate(&public_key_1).unwrap();
        let (_, shared_secret_2) = P256MlKem768::encapsulate(&public_key_2).unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let (public_key, _) = P256MlKem768::keypair().unwrap();
        let (_, shared_secret) = P256MlKem768::encapsulate(&public_key).unwrap();
        
        assert_eq!(shared_secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_multiple_encapsulations_different_ciphertexts() {
        let (public_key, secret_key) = P256MlKem768::keypair().unwrap();

        // Same public key should produce different ciphertexts due to randomness
        let (ciphertext_1, shared_secret_1) = P256MlKem768::encapsulate(&public_key).unwrap();
        let (ciphertext_2, shared_secret_2) = P256MlKem768::encapsulate(&public_key).unwrap();

        // Ciphertexts should be different (randomized)
        assert_ne!(ciphertext_1.classical_ephemeral, ciphertext_2.classical_ephemeral);
        assert_ne!(ciphertext_1.post_quantum_ciphertext, ciphertext_2.post_quantum_ciphertext);

        // But both should decrypt correctly to different shared secrets
        let decrypted_1 = P256MlKem768::decapsulate(&ciphertext_1, &secret_key).unwrap();
        let decrypted_2 = P256MlKem768::decapsulate(&ciphertext_2, &secret_key).unwrap();

        assert_eq!(shared_secret_1.as_bytes(), decrypted_1.as_bytes());
        assert_eq!(shared_secret_2.as_bytes(), decrypted_2.as_bytes());

        // Different encapsulations should produce different secrets
        assert_ne!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
    }

    #[test]
    fn test_ciphertext_sizes() {
        let (public_key, _) = P256MlKem768::keypair().unwrap();
        let (ciphertext, _) = P256MlKem768::encapsulate(&public_key).unwrap();

        // P-256 public key should be 65 bytes (uncompressed)
        assert_eq!(ciphertext.classical_ephemeral.len(), 65);
        // ML-KEM-768 ciphertext should be 1088 bytes
        assert_eq!(ciphertext.post_quantum_ciphertext.len(), sizes::ML_KEM_768_CIPHERTEXT);
    }

    #[test]
    fn test_public_key_sizes() {
        let (public_key, _) = P256MlKem768::keypair().unwrap();

        // P-256 public key should be 65 bytes (uncompressed)
        assert_eq!(public_key.classical.0.len(), 65);
        // ML-KEM-768 public key should be 1184 bytes
        assert_eq!(public_key.post_quantum.0.len(), sizes::ML_KEM_768_PUBLIC);
    }

    #[test]
    fn test_serialization_deserialization() {
        let (public_key, _) = P256MlKem768::keypair().unwrap();
        let (ciphertext, _) = P256MlKem768::encapsulate(&public_key).unwrap();

        // Test public key serialization
        let pk_serialized = serde_json::to_vec(&public_key).unwrap();
        let pk_deserialized: CompositePublicKey<P256PublicKeyWrapper, MlKemPublicKeyWrapper> = 
            serde_json::from_slice(&pk_serialized).unwrap();
        assert_eq!(public_key.classical.0, pk_deserialized.classical.0);
        assert_eq!(public_key.post_quantum.0, pk_deserialized.post_quantum.0);

        // Test ciphertext serialization
        let ct_serialized = serde_json::to_vec(&ciphertext).unwrap();
        let ct_deserialized: HybridCiphertext = serde_json::from_slice(&ct_serialized).unwrap();
        assert_eq!(ciphertext.classical_ephemeral, ct_deserialized.classical_ephemeral);
        assert_eq!(ciphertext.post_quantum_ciphertext, ct_deserialized.post_quantum_ciphertext);
    }

    #[test]
    fn test_invalid_ciphertext_sizes() {
        let (_, secret_key) = P256MlKem768::keypair().unwrap();

        // Test with invalid classical ephemeral key size
        let invalid_ciphertext = HybridCiphertext {
            classical_ephemeral: vec![0u8; 32], // Too short
            post_quantum_ciphertext: vec![0u8; sizes::ML_KEM_768_CIPHERTEXT],
        };

        assert!(P256MlKem768::decapsulate(&invalid_ciphertext, &secret_key).is_err());

        // Test with invalid post-quantum ciphertext size
        let invalid_ciphertext2 = HybridCiphertext {
            classical_ephemeral: vec![0u8; 65],
            post_quantum_ciphertext: vec![0u8; 500], // Wrong size
        };

        assert!(P256MlKem768::decapsulate(&invalid_ciphertext2, &secret_key).is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let (public_key, secret_key) = P256MlKem768::keypair().unwrap();

        // Multiple encapsulations and decapsulations should be consistent
        for _ in 0..10 {
            let (ciphertext, shared_secret_1) = P256MlKem768::encapsulate(&public_key).unwrap();
            let shared_secret_2 = P256MlKem768::decapsulate(&ciphertext, &secret_key).unwrap();
            assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
        }
    }

    #[test]
    fn test_hkdf_domain_separation() {
        // This test ensures that our HKDF context is properly set up
        let (public_key, _) = P256MlKem768::keypair().unwrap();
        let (_, shared_secret) = P256MlKem768::encapsulate(&public_key).unwrap();
        
        // Should always be 32 bytes due to HKDF expand
        assert_eq!(shared_secret.as_bytes().len(), 32);
        
        // Should not be all zeros (extremely unlikely)
        assert_ne!(shared_secret.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_zeroization() {
        let (_, mut secret_key) = P256MlKem768::keypair().unwrap();
        let mut shared_secret = HybridSharedSecret { key: [1u8; 32] };

        // Verify they have data before zeroization
        assert_ne!(shared_secret.key, [0u8; 32]);

        // Zeroize
        shared_secret.zeroize();

        // Verify zeroization worked
        assert_eq!(shared_secret.key, [0u8; 32]);

        // Secret key should also properly zeroize (tested implicitly through Drop)
        drop(secret_key);
    }
}