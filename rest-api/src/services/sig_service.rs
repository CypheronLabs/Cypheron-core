use base64::{engine::general_purpose, Engine as _};
use core_lib::sig::Falcon512;
use core_lib::sig::Falcon1024;
use core_lib::sig::traits::SignatureEngine;
use secrecy::ExposeSecret;
use crate::{error::AppError, validation};
use core_lib::sig::dilithium::common::*;
use crate::models::sig::*;
use core_lib::sig::dilithium::{dilithium2::Dilithium2, dilithium3::Dilithium3, dilithium5::Dilithium5};
use core_lib::sig::sphincs::{haraka_192f, sha2_256s, shake_128f};

use core_lib::sig::sphincs::haraka_192f::types::{PublicKey as Haraka192fPublicKey, SecretKey as Haraka192fSecretKey, Signature as Haraka192fSignature};
use core_lib::sig::sphincs::sha2_256s::types::{PublicKey as Sha2_256sPublicKey, SecretKey as Sha2_256sSecretKey, Signature as Sha2_256sSignature};
use core_lib::sig::sphincs::shake_128f::types::{PublicKey as Shake128fPublicKey, SecretKey as Shake128fSecretKey, Signature as Shake128fSignature};
use core_lib::sig::falcon::falcon1024::constants::FALCON_SECRET;

pub struct SigService;

impl SigService {
    pub fn generate_keypair(variant: SigVariant) -> Result<KeypairResponse, AppError> {
        match variant {
            // NIST FIPS 204 compliant variants (ML-DSA)
            SigVariant::MlDsa44 => {
                let (pk, sk) = Dilithium2::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::MlDsa65 => {
                let (pk, sk) = Dilithium3::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::MlDsa87 => {
                let (pk, sk) = Dilithium5::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::Falcon512 => {
                let (pk, sk) = Falcon512::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::Falcon1024 => {
                let (pk, sk) = Falcon1024::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::SlhDsaHaraka192f => {
                let (pk, sk) = haraka_192f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            SigVariant::SlhDsaSha2256s => {
                let (pk, sk) = sha2_256s::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            SigVariant::SlhDsaShake128f => {
                let (pk, sk) = shake_128f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            // Handle deprecated variants by forwarding to new implementations
            #[allow(deprecated)]
            SigVariant::Dilithium2 => {
                let (pk, sk) = Dilithium2::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            #[allow(deprecated)]
            SigVariant::Dilithium3 => {
                let (pk, sk) = Dilithium3::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            #[allow(deprecated)]
            SigVariant::Dilithium5 => {
                let (pk, sk) = Dilithium5::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            #[allow(deprecated)]
            SigVariant::Haraka192f => {
                let (pk, sk) = haraka_192f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            #[allow(deprecated)]
            SigVariant::Sha2_256s => {
                let (pk, sk) = sha2_256s::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            #[allow(deprecated)]
            SigVariant::Shake128f => {
                let (pk, sk) = shake_128f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
        }
    }

    pub fn sign(variant: SigVariant, message: &str, sk_b64: &str) -> Result<AnySignature, AppError> {
        validation::validate_message(message)?;
        validation::validate_base64_key(sk_b64)?;
        
        let sk_bytes = general_purpose::STANDARD
            .decode(sk_b64)
            .map_err(|_| AppError::InvalidSecretKey)?;
        let message_bytes = message.as_bytes();
        
        let algorithm_name = match variant {
            SigVariant::MlDsa44 => "dilithium2",
            SigVariant::MlDsa65 => "dilithium3",
            SigVariant::MlDsa87 => "dilithium5",
            SigVariant::Falcon512 => "falcon512",
            SigVariant::Falcon1024 => "falcon1024",
            #[allow(deprecated)]
            SigVariant::Dilithium2 => "dilithium2",
            #[allow(deprecated)]
            SigVariant::Dilithium3 => "dilithium3",
            #[allow(deprecated)]
            SigVariant::Dilithium5 => "dilithium5",
            _ => "", 
        };
        
        if !algorithm_name.is_empty() {
            validation::validate_decoded_key_size(algorithm_name, &sk_bytes, false)?;
        }
        match variant {
            SigVariant::MlDsa44 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium2::types::SecretKey;
                let arr: [u8; ML_DSA_44_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium2::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium2(sig))
            }
            SigVariant::MlDsa65 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium3::types::SecretKey;
                let arr: [u8; ML_DSA_65_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium3::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium3(sig))
            }
            SigVariant::MlDsa87 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium5::types::SecretKey;
                let arr: [u8; ML_DSA_87_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium5::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium5(sig))
            }
            SigVariant::Falcon512 => {
                use secrecy::SecretBox;
                use core_lib::sig::falcon::falcon512::types::SecretKey as Falcon512SecretKey;
                let arr: [u8; core_lib::sig::falcon::falcon512::constants::FALCON_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = Falcon512SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Falcon512::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Falcon512(sig))
            }
            SigVariant::Falcon1024 => {
                use secrecy::SecretBox;
                use core_lib::sig::falcon::falcon1024::types::SecretKey as Falcon1024SecretKey;
                let arr: [u8; FALCON_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = Falcon1024SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Falcon1024::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Falcon1024(sig))
            }
            SigVariant::SlhDsaHaraka192f => {
                let sk = Haraka192fSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = haraka_192f::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Haraka192f(sig))
            }
            SigVariant::SlhDsaSha2256s => {
                let sk = Sha2_256sSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = sha2_256s::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Sha2_256s(sig))
            }
            SigVariant::SlhDsaShake128f => {
                let sk = Shake128fSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = shake_128f::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Shake128f(sig))
            }
            // Handle deprecated variants by forwarding to new implementations
            #[allow(deprecated)]
            SigVariant::Dilithium2 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium2::types::SecretKey;
                let arr: [u8; ML_DSA_44_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium2::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium2(sig))
            }
            #[allow(deprecated)]
            SigVariant::Dilithium3 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium3::types::SecretKey;
                let arr: [u8; ML_DSA_65_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium3::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium3(sig))
            }
            #[allow(deprecated)]
            SigVariant::Dilithium5 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium5::types::SecretKey;
                let arr: [u8; ML_DSA_87_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium5::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium5(sig))
            }
            #[allow(deprecated)]
            SigVariant::Haraka192f => {
                let sk = Haraka192fSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = haraka_192f::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Haraka192f(sig))
            }
            #[allow(deprecated)]
            SigVariant::Sha2_256s => {
                let sk = Sha2_256sSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = sha2_256s::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Sha2_256s(sig))
            }
            #[allow(deprecated)]
            SigVariant::Shake128f => {
                let sk = Shake128fSecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = shake_128f::sign_detached(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Shake128f(sig))
            }
        }
    }
    
    pub fn verify(variant: SigVariant, pk_b64: &str, msg: &str, sig_b64: &str) -> Result<bool, AppError> {
        validation::validate_base64_key(pk_b64)?;
        validation::validate_message(msg)?;
        validation::validate_base64_signature(sig_b64)?;
        
        let pk_bytes = general_purpose::STANDARD.decode(pk_b64).map_err(|_| AppError::InvalidBase64)?;
        let sig_bytes = general_purpose::STANDARD.decode(sig_b64).map_err(|_| AppError::InvalidBase64)?;
        let msg_bytes = msg.as_bytes();
        
        let algorithm_name = match variant {
            SigVariant::MlDsa44 => "dilithium2",
            SigVariant::MlDsa65 => "dilithium3",
            SigVariant::MlDsa87 => "dilithium5",
            SigVariant::Falcon512 => "falcon512",
            SigVariant::Falcon1024 => "falcon1024",
            #[allow(deprecated)]
            SigVariant::Dilithium2 => "dilithium2",
            #[allow(deprecated)]
            SigVariant::Dilithium3 => "dilithium3",
            #[allow(deprecated)]
            SigVariant::Dilithium5 => "dilithium5",
            _ => "", 
        };
        
        if !algorithm_name.is_empty() {
            validation::validate_decoded_key_size(algorithm_name, &pk_bytes, true)?;
        }
        match variant {
            SigVariant::MlDsa44 => {
                let pk = core_lib::sig::dilithium::dilithium2::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium2::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium2::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::MlDsa65 => {
                let pk = core_lib::sig::dilithium::dilithium3::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium3::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium3::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::MlDsa87 => {
                let pk = core_lib::sig::dilithium::dilithium5::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium5::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium5::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Falcon512 => {
                use core_lib::sig::falcon::falcon512::types::PublicKey as Falcon512PublicKey;
                use core_lib::sig::falcon::falcon512::types::Signature as Falcon512Signature;
                let pk = Falcon512PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = Falcon512Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Falcon512::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Falcon1024 => {
                use core_lib::sig::falcon::falcon1024::types::{PublicKey as Falcon1024PublicKey, Signature as Falcon1024Signature};
                let pk = Falcon1024PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = Falcon1024Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Falcon1024::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::SlhDsaHaraka192f => {
                let pk = Haraka192fPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Haraka192fSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(haraka_192f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            SigVariant::SlhDsaSha2256s => {
                let pk = Sha2_256sPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Sha2_256sSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(sha2_256s::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            SigVariant::SlhDsaShake128f => {
                let pk = Shake128fPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Shake128fSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(shake_128f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            // Handle deprecated variants by forwarding to new implementations
            #[allow(deprecated)]
            SigVariant::Dilithium2 => {
                let pk = core_lib::sig::dilithium::dilithium2::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium2::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium2::verify(msg_bytes, &sig, &pk))
            }
            #[allow(deprecated)]
            SigVariant::Dilithium3 => {
                let pk = core_lib::sig::dilithium::dilithium3::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium3::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium3::verify(msg_bytes, &sig, &pk))
            }
            #[allow(deprecated)]
            SigVariant::Dilithium5 => {
                let pk = core_lib::sig::dilithium::dilithium5::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium5::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium5::verify(msg_bytes, &sig, &pk))
            }
            #[allow(deprecated)]
            SigVariant::Haraka192f => {
                let pk = Haraka192fPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Haraka192fSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(haraka_192f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            #[allow(deprecated)]
            SigVariant::Sha2_256s => {
                let pk = Sha2_256sPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Sha2_256sSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(sha2_256s::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            #[allow(deprecated)]
            SigVariant::Shake128f => {
                let pk = Shake128fPublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Shake128fSignature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(shake_128f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum AnySignature {
    Dilithium2(core_lib::sig::dilithium::dilithium2::types::Signature),
    Dilithium3(core_lib::sig::dilithium::dilithium3::types::Signature),
    Dilithium5(core_lib::sig::dilithium::dilithium5::types::Signature),
    Falcon512(core_lib::sig::falcon::falcon512::types::Signature<{core_lib::sig::falcon::falcon512::constants::FALCON_SIGNATURE}>),
    Falcon1024(core_lib::sig::falcon::falcon1024::types::Signature<{core_lib::sig::falcon::falcon1024::constants::FALCON_SIGNATURE}>),
    Haraka192f(core_lib::sig::sphincs::haraka_192f::types::Signature),
    Sha2_256s(core_lib::sig::sphincs::sha2_256s::types::Signature),
    Shake128f(core_lib::sig::sphincs::shake_128f::types::Signature),
}