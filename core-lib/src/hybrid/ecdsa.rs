use p256::{ecdsa::{signature::{Signer, Verifier}, Signature as EcdsaSignature, SigningKey, VerifyingKey}, elliptic_curve::rand_core::OsRng, EncodedPoint, FieldBytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum EcdsaError {
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Signature generation failed: {0}")]
    SigningFailed(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Key serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Key deserialization failed: {0}")]
    DeserializationFailed(String),
}

#[derive(Clone, Debug)]
pub struct EcdsaPrivateKey {
    inner: SigningKey,
    domain_separator: String,
}

impl Zeroize for EcdsaPrivateKey {
    fn zeroize(&mut self) {
        self.inner = SigningKey::random(&mut OsRng);
        self.domain_separator.zeroize();
    }
}

impl Drop for EcdsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaPublicKey {
    encoded_point: Vec<u8>,
    domain_separator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaSignatureWrapper {
    signature: Vec<u8>,
    domain_separator: String,
    message_hash: Vec<u8>,
}

impl EcdsaPrivateKey {
    pub fn generate(domain_separator: String) -> Result<Self, EcdsaError> {
        let inner = SigningKey::random(&mut OsRng);
        Ok(Self { inner, domain_separator })
    }

    pub fn from_bytes(bytes: &FieldBytes, domain_separator: String) -> Result<Self, EcdsaError> {
        let inner = SigningKey::from_bytes(bytes)
            .map_err(|e| EcdsaError::InvalidPrivateKey(format!("Invalid key bytes: {}", e)))?;
        Ok(Self { inner, domain_separator })
    }

    pub fn public_key(&self) -> EcdsaPublicKey {
        let verifying_key = VerifyingKey::from(&self.inner);
        let encoded_point = verifying_key.to_encoded_point(true);

        EcdsaPublicKey {
            encoded_point: encoded_point.as_bytes().to_vec(),
            domain_separator: self.domain_separator.clone(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<EcdsaSignatureWrapper, EcdsaError> {
        let domain_separated_hash = self.create_domain_separated_hash(message);

        let signature: EcdsaSignature = self.inner.sign(&domain_separated_hash);

        Ok(EcdsaSignatureWrapper {
            signature: signature.to_bytes().to_vec(),
            domain_separator: self.domain_separator.clone(),
            message_hash: domain_separated_hash.to_vec(),
        })
    }

    fn create_domain_separated_hash(&self, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"CYPHERON_HYBRID_ECDSA_V1");
        hasher.update(self.domain_separator.as_bytes());
        hasher.update(&(message.len() as u64).to_be_bytes());
        hasher.update(message);
        hasher.finalize().into()
    }

    pub fn to_bytes(&self) -> FieldBytes {
        self.inner.to_bytes()
    }
}

impl EcdsaPublicKey {
    pub fn from_bytes(bytes: &[u8], domain_separator: String) -> Result<Self, EcdsaError> {
        let encoded_point = EncodedPoint::from_bytes(bytes)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid encoded point: {}", e)))?;

        VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid curve point: {}", e)))?;

        Ok(Self { encoded_point: bytes.to_vec(), domain_separator })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &EcdsaSignatureWrapper,
    ) -> Result<bool, EcdsaError> {
        if signature.domain_separator != self.domain_separator {
            return Ok(false);
        }

        let expected_hash = self.create_domain_separated_hash(message);

        if signature.message_hash != expected_hash {
            return Ok(false);
        }

        let encoded_point = EncodedPoint::from_bytes(&self.encoded_point)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid stored point: {}", e)))?;

        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid verifying key: {}", e)))?;

        if signature.signature.len() != 64 {
            return Ok(false);
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature.signature);
        let ecdsa_sig = EcdsaSignature::from_bytes(&sig_array.into())
            .map_err(|_| EcdsaError::VerificationFailed)?;

        Ok(verifying_key.verify(&expected_hash, &ecdsa_sig).is_ok())
    }

    fn create_domain_separated_hash(&self, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"CYPHERON_HYBRID_ECDSA_V1");
        hasher.update(self.domain_separator.as_bytes());
        hasher.update(&(message.len() as u64).to_be_bytes());
        hasher.update(message);
        hasher.finalize().into()
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.encoded_point
    }

    pub fn domain_separator(&self) -> &str {
        &self.domain_separator
    }
}

pub struct EcdsaKeyPair {
    pub private_key: EcdsaPrivateKey,
    pub public_key: EcdsaPublicKey,
}

impl EcdsaKeyPair {
    pub fn generate(domain_separator: String) -> Result<Self, EcdsaError> {
        let private_key = EcdsaPrivateKey::generate(domain_separator)?;
        let public_key = private_key.public_key();

        Ok(Self { private_key, public_key })
    }
}

pub mod validation {
    use super::*;

    pub fn validate_private_key(key: &EcdsaPrivateKey) -> Result<(), EcdsaError> {
        if key.domain_separator.is_empty() {
            return Err(EcdsaError::InvalidPrivateKey("Empty domain separator".to_string()));
        }

        Ok(())
    }

    pub fn validate_public_key(key: &EcdsaPublicKey) -> Result<(), EcdsaError> {
        if key.domain_separator.is_empty() {
            return Err(EcdsaError::InvalidPublicKey("Empty domain separator".to_string()));
        }

        let encoded_point = EncodedPoint::from_bytes(&key.encoded_point)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid encoded point: {}", e)))?;

        VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|e| EcdsaError::InvalidPublicKey(format!("Invalid curve point: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_roundtrip() {
        let domain = "test-hybrid".to_string();
        let keypair = EcdsaKeyPair::generate(domain.clone()).unwrap();
        let message = b"test message for hybrid signature";

        let signature = keypair.private_key.sign(message).unwrap();
        let is_valid = keypair.public_key.verify(message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_domain_separation() {
        let message = b"test message";

        let keypair1 = EcdsaKeyPair::generate("domain1".to_string()).unwrap();
        let keypair2 = EcdsaKeyPair::generate("domain2".to_string()).unwrap();

        let signature1 = keypair1.private_key.sign(message).unwrap();

        let is_valid = keypair2.public_key.verify(message, &signature1).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_message_integrity() {
        let keypair = EcdsaKeyPair::generate("test".to_string()).unwrap();
        let message1 = b"original message";
        let message2 = b"different message";

        let signature = keypair.private_key.sign(message1).unwrap();

        let is_valid = keypair.public_key.verify(message2, &signature).unwrap();
        assert!(!is_valid);
    }
}
