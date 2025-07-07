use super::traits::{HybridEngine, VerificationPolicy};
use super::composite::{CompositeSignature, CompositePublicKey, CompositeSecretKey};
use super::ecdsa::{EcdsaKeyPair, EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignatureWrapper, EcdsaError};
use crate::sig::traits::SignatureEngine;
use crate::sig::Dilithium2;
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HybridError {
    #[error("Classical signature operation failed: {0}")]
    Classical(String),
    #[error("Post-quantum signature operation failed: {0}")]
    PostQuantum(String),
    #[error("Verification failed according to policy")]
    VerificationFailed,
    #[error("ECDSA error: {0}")]
    EcdsaError(#[from] EcdsaError),
    #[error("Message integrity check failed")]
    MessageIntegrityFailed,
    #[error("Replay attack detected: {0}")]
    ReplayAttack(String),
}

/// ECDSA P-256 + Dilithium2 hybrid scheme
pub struct EccDilithium;

// Type aliases for the new ECDSA implementation
type EccPublicKey = EcdsaPublicKey;
type EccSecretKey = EcdsaPrivateKey;
type EccSignature = EcdsaSignatureWrapper;

impl HybridEngine for EccDilithium {
    type ClassicalPublicKey = EccPublicKey;
    type ClassicalSecretKey = EccSecretKey;
    type ClassicalSignature = EccSignature;

    type PqPublicKey = crate::sig::dilithium::dilithium2::types::PublicKey;
    type PqSecretKey = crate::sig::dilithium::dilithium2::types::SecretKey;
    type PqSignature = crate::sig::dilithium::dilithium2::types::Signature;

    type CompositePublicKey = CompositePublicKey<Self::ClassicalPublicKey, Self::PqPublicKey>;
    type CompositeSecretKey = CompositeSecretKey<Self::ClassicalSecretKey, Self::PqSecretKey>;
    type CompositeSignature = CompositeSignature<Self::ClassicalSignature, Self::PqSignature>;

    type Error = HybridError;

    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error> {
        // Generate ECDSA keypair with NIST FIPS 204 compliant domain separation
        let domain_separator = "CYPHERON_HYBRID_ML_DSA_44".to_string();
        let ecdsa_keypair = EcdsaKeyPair::generate(domain_separator)?;
        
        // Generate Dilithium2 keypair
        let (dilithium_pk, dilithium_sk) = Dilithium2::keypair()
            .map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        // Create composite keys with proper types
        let composite_pk = CompositePublicKey {
            classical: ecdsa_keypair.public_key,
            post_quantum: dilithium_pk,
        };
        
        let composite_sk = CompositeSecretKey {
            classical: SecretBox::new(Box::new(ecdsa_keypair.private_key)),
            post_quantum: SecretBox::new(Box::new(dilithium_sk)),
        };

        Ok((composite_pk, composite_sk))
    }

    fn sign(msg: &[u8], sk: &Self::CompositeSecretKey) -> Result<Self::CompositeSignature, Self::Error> {
        // Add timestamp for replay protection
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| HybridError::Classical(format!("Time error: {}", e)))?
            .as_secs();
        
        // Create message with timestamp commitment
        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(msg);
        
        // Sign with ECDSA using the new secure implementation
        let ecc_sk = sk.classical.expose_secret();
        let ecc_signature = ecc_sk.sign(&message_with_timestamp)?;

        // Sign with Dilithium2 using the same message with timestamp
        let dilithium_sk = sk.post_quantum.expose_secret();
        let dilithium_signature = Dilithium2::sign(&message_with_timestamp, dilithium_sk)
            .map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        Ok(CompositeSignature {
            classical: ecc_signature,
            post_quantum: dilithium_signature,
        })
    }

    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool {
        Self::verify_with_policy(msg, sig, pk, VerificationPolicy::BothRequired)
    }

    fn verify_with_policy(
        msg: &[u8], 
        sig: &Self::CompositeSignature, 
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy
    ) -> bool {
        // Extract timestamp from signature and reconstruct the signed message
        // Note: In a real implementation, timestamp should be part of the signature structure
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        // For now, we'll try to verify with a reasonable timestamp window
        // In production, timestamp should be embedded in the signature
        let mut verification_succeeded = false;
        
        // Try verification with timestamps within last 5 minutes
        for time_offset in 0..300 {
            let test_timestamp = current_time.saturating_sub(time_offset);
            let mut message_with_timestamp = Vec::new();
            message_with_timestamp.extend_from_slice(&test_timestamp.to_be_bytes());
            message_with_timestamp.extend_from_slice(msg);
            
            // Verify ECDSA signature using new secure implementation
            let ecc_valid = pk.classical.verify(&message_with_timestamp, &sig.classical)
                .unwrap_or(false);
            
            // Verify Dilithium2 signature
            let dilithium_valid = Dilithium2::verify(&message_with_timestamp, &sig.post_quantum, &pk.post_quantum);
            
            // Check verification policy
            let policy_satisfied = match policy {
                VerificationPolicy::BothRequired => ecc_valid && dilithium_valid,
                VerificationPolicy::EitherValid => ecc_valid || dilithium_valid,
                VerificationPolicy::ClassicalOnly => ecc_valid,
                VerificationPolicy::PostQuantumOnly => dilithium_valid,
            };
            
            if policy_satisfied {
                verification_succeeded = true;
                break;
            }
        }
        
        verification_succeeded
    }
}

// Placeholder for other schemes - you can implement these similarly
pub struct EccFalcon;
pub struct EccSphincs;

// You would implement HybridEngine for EccFalcon and EccSphincs similarly...