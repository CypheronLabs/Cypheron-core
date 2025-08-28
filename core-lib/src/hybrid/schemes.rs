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

use secrecy::{SecretBox, ExposeSecret};
use crate::hybrid::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use crate::hybrid::ecdsa::{EcdsaPublicKey, EcdsaPrivateKey, EcdsaSignatureWrapper, EcdsaKeyPair};
use crate::hybrid::traits::{HybridEngine, VerificationPolicy};
use crate::sig::{Dilithium2, Falcon512};
use crate::sig::traits::SignatureEngine;
use std::error::Error as StdError;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum HybridError {
    Classical(String),
    PostQuantum(String),
}

impl Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HybridError::Classical(msg) => write!(f, "Classical cryptography error: {}", msg),
            HybridError::PostQuantum(msg) => write!(f, "Post-quantum cryptography error: {}", msg),
        }
    }
}

impl StdError for HybridError {}

impl From<crate::hybrid::ecdsa::EcdsaError> for HybridError {
    fn from(err: crate::hybrid::ecdsa::EcdsaError) -> Self {
        HybridError::Classical(err.to_string())
    }
}

pub struct EccDilithium;

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
        let domain_separator = "CYPHERON_HYBRID_ML_DSA_44".to_string();
        let ecdsa_keypair = EcdsaKeyPair::generate(domain_separator)?;

        let (dilithium_pk, dilithium_sk) =
            <Dilithium2 as SignatureEngine>::keypair().map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        let composite_pk =
            CompositePublicKey { classical: ecdsa_keypair.public_key, post_quantum: dilithium_pk };

        let composite_sk = CompositeSecretKey {
            classical: SecretBox::new(Box::new(ecdsa_keypair.private_key)),
            post_quantum: SecretBox::new(Box::new(dilithium_sk)),
        };

        Ok((composite_pk, composite_sk))
    }

    fn sign(
        msg: &[u8],
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::CompositeSignature, Self::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| HybridError::Classical(format!("Time error: {}", e)))?
            .as_secs();

        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_sk = sk.classical.expose_secret();
        let ecc_signature = ecc_sk.sign(&message_with_timestamp)?;

        let dilithium_sk = sk.post_quantum.expose_secret();
        let dilithium_signature = <Dilithium2 as SignatureEngine>::sign(&message_with_timestamp, dilithium_sk)
            .map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        Ok(CompositeSignature {
            classical: ecc_signature,
            post_quantum: dilithium_signature,
            timestamp,
            nonce,
        })
    }

    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool {
        Self::verify_with_policy(msg, sig, pk, VerificationPolicy::BothRequired)
    }

    fn verify_with_policy(
        msg: &[u8],
        sig: &Self::CompositeSignature,
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy,
    ) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if sig.timestamp + 30 < current_time || sig.timestamp > current_time + 5 {
            return false;
        }

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&sig.timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&sig.nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_valid =
            pk.classical.verify(&message_with_timestamp, &sig.classical).unwrap_or(false);

        let dilithium_valid =
            <Dilithium2 as SignatureEngine>::verify(&message_with_timestamp, &sig.post_quantum, &pk.post_quantum);

        match policy {
            VerificationPolicy::BothRequired => ecc_valid && dilithium_valid,
            VerificationPolicy::EitherValid => ecc_valid || dilithium_valid,
            VerificationPolicy::ClassicalOnly => ecc_valid,
            VerificationPolicy::PostQuantumOnly => dilithium_valid,
        }
    }
}

pub struct EccFalcon;
impl HybridEngine for EccFalcon {
    type ClassicalPublicKey = EccPublicKey;
    type ClassicalSecretKey = EccSecretKey;
    type ClassicalSignature = EccSignature;

    type PqPublicKey = crate::sig::falcon::falcon512::types::Falcon512PublicKey;
    type PqSecretKey = crate::sig::falcon::falcon512::types::Falcon512SecretKey;
    type PqSignature = crate::sig::falcon::falcon512::types::Falcon512Signature;

    type CompositePublicKey = CompositePublicKey<Self::ClassicalPublicKey, Self::PqPublicKey>;
    type CompositeSecretKey = CompositeSecretKey<Self::ClassicalSecretKey, Self::PqSecretKey>;
    type CompositeSignature = CompositeSignature<Self::ClassicalSignature, Self::PqSignature>;

    type Error = HybridError;

    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error> {
        let domain_separator = "CYPHERON_HYBRID_FALCON_512".to_string();
        let ecdsa_keypair = EcdsaKeyPair::generate(domain_separator)?;

        let (falcon_pk, falcon_sk) =
            <Falcon512 as SignatureEngine>::keypair().map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        let composite_pk =
            CompositePublicKey { classical: ecdsa_keypair.public_key, post_quantum: falcon_pk };

        let composite_sk = CompositeSecretKey {
            classical: SecretBox::new(Box::new(ecdsa_keypair.private_key)),
            post_quantum: SecretBox::new(Box::new(falcon_sk)),
        };

        Ok((composite_pk, composite_sk))
    }
    fn sign(
        msg: &[u8],
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::CompositeSignature, Self::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| HybridError::Classical(format!("Time error: {}", e)))?
            .as_secs();

        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_sk = sk.classical.expose_secret();
        let ecc_signature = ecc_sk.sign(&message_with_timestamp)?;

        let falcon_sk = sk.post_quantum.expose_secret();
        let falcon_signature = <Falcon512 as SignatureEngine>::sign(&message_with_timestamp, falcon_sk)
            .map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        Ok(CompositeSignature {
            classical: ecc_signature,
            post_quantum: falcon_signature,
            timestamp,
            nonce,
        })
    }
    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool {
        Self::verify_with_policy(msg, sig, pk, VerificationPolicy::BothRequired)
    }
    fn verify_with_policy(
        msg: &[u8],
        sig: &Self::CompositeSignature,
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy,
    ) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if sig.timestamp + 30 < current_time || sig.timestamp > current_time + 5 {
            return false;
        }

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&sig.timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&sig.nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_valid =
            pk.classical.verify(&message_with_timestamp, &sig.classical).unwrap_or(false);

        let falcon_valid =
            <Falcon512 as SignatureEngine>::verify(&message_with_timestamp, &sig.post_quantum, &pk.post_quantum);

        match policy {
            VerificationPolicy::BothRequired => ecc_valid && falcon_valid,
            VerificationPolicy::EitherValid => ecc_valid || falcon_valid,
            VerificationPolicy::ClassicalOnly => ecc_valid,
            VerificationPolicy::PostQuantumOnly => falcon_valid,
        }
    }
}
pub struct EccSphincs;
impl HybridEngine for EccSphincs {
    type ClassicalPublicKey = EccPublicKey;
    type ClassicalSecretKey = EccSecretKey;
    type ClassicalSignature = EccSignature;

    type PqPublicKey = crate::sig::sphincs::shake_128f::types::PublicKey;
    type PqSecretKey = crate::sig::sphincs::shake_128f::types::SecretKey;
    type PqSignature = crate::sig::sphincs::shake_128f::types::Signature;

    type CompositePublicKey = CompositePublicKey<Self::ClassicalPublicKey, Self::PqPublicKey>;
    type CompositeSecretKey = CompositeSecretKey<Self::ClassicalSecretKey, Self::PqSecretKey>;
    type CompositeSignature = CompositeSignature<Self::ClassicalSignature, Self::PqSignature>;

    type Error = HybridError;
    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error> {
        let domain_separator = "CYPHERON_HYBRID_SPHINCS_SHAKE_128F".to_string();
        let ecdsa_keypair = EcdsaKeyPair::generate(domain_separator)?;

        let (sphincs_pk, sphincs_sk) =
            crate::sig::sphincs::shake_128f::keypair().map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        let composite_pk =
            CompositePublicKey { classical: ecdsa_keypair.public_key, post_quantum: sphincs_pk };

        let composite_sk = CompositeSecretKey {
            classical: SecretBox::new(Box::new(ecdsa_keypair.private_key)),
            post_quantum: SecretBox::new(Box::new(sphincs_sk)),
        };

        Ok((composite_pk, composite_sk))
    }
    fn sign(
        msg: &[u8],
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::CompositeSignature, Self::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| HybridError::Classical(format!("Time error: {}", e)))?
            .as_secs();

        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_sk = sk.classical.expose_secret();
        let ecc_signature = ecc_sk.sign(&message_with_timestamp)?;

        let shake_128f_sk = sk.post_quantum.expose_secret();
        let shake_128f_signature =
            crate::sig::sphincs::shake_128f::sign_detached(&message_with_timestamp, shake_128f_sk)
                .map_err(|e| HybridError::PostQuantum(e.to_string()))?;

        Ok(CompositeSignature {
            classical: ecc_signature,
            post_quantum: shake_128f_signature,
            timestamp,
            nonce,
        })
    }
    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool {
        Self::verify_with_policy(msg, sig, pk, VerificationPolicy::BothRequired)
    }
    fn verify_with_policy(
        msg: &[u8],
        sig: &Self::CompositeSignature,
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy,
    ) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if sig.timestamp + 30 < current_time || sig.timestamp > current_time + 5 {
            return false;
        }

        let mut message_with_timestamp = Vec::new();
        message_with_timestamp.extend_from_slice(&sig.timestamp.to_be_bytes());
        message_with_timestamp.extend_from_slice(&sig.nonce);
        message_with_timestamp.extend_from_slice(msg);

        let ecc_valid =
            pk.classical.verify(&message_with_timestamp, &sig.classical).unwrap_or(false);

        let shake_128f_valid = crate::sig::sphincs::shake_128f::verify_detached(
            &sig.post_quantum,
            &message_with_timestamp,
            &pk.post_quantum,
        )
        .is_ok();

        match policy {
            VerificationPolicy::BothRequired => ecc_valid && shake_128f_valid,
            VerificationPolicy::EitherValid => ecc_valid || shake_128f_valid,
            VerificationPolicy::ClassicalOnly => ecc_valid,
            VerificationPolicy::PostQuantumOnly => shake_128f_valid,
        }
    }
}
