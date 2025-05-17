use base64::{engine::general_purpose, Engine as _};
use core_lib::sig::Falcon512;
use core_lib::sig::Falcon1024;
use core_lib::sig::traits::SignatureEngine;
use secrecy::ExposeSecret;
use crate::error::AppError;
use crate::models::sig::*;
use core_lib::sig::dilithium::{dilithium2::Dilithium2, dilithium3::Dilithium3, dilithium5::Dilithium5};
use core_lib::sig::sphincs::{haraka_192f, sha2_256s, shake_128f};

pub enum AnySecretKey {
    Dilithium2(core_lib::sig::dilithium::dilithium2::types::SecretKey),
    Dilithium3(core_lib::sig::dilithium::dilithium3::types::SecretKey),
    Dilithium5(core_lib::sig::dilithium::dilithium5::types::SecretKey),
    Falcon512(core_lib::sig::falcon::falcon512::types::SecretKey<{
        core_lib::sig::falcon::falcon512::constants::FALCON_SECRET
    }>),
    Falcon1024(core_lib::sig::falcon::falcon1024::types::SecretKey<{
        core_lib::sig::falcon::falcon1024::constants::FALCON_SECRET
    }>),
    Haraka192f(haraka_192f::SecretKey),
    Sha2_256s(sha2_256s::SecretKey),
    Shake128f(shake_128f::SecretKey),
}
pub enum AnySignature {
    Dilithium2(core_lib::sig::dilithium::dilithium2::types::Signature),
    Dilithium3(core_lib::sig::dilithium::dilithium3::types::Signature),
    Dilithium5(core_lib::sig::dilithium::dilithium5::types::Signature),
    Falcon512(core_lib::sig::falcon::falcon512::types::Signature<{core_lib::sig::falcon::falcon512::constants::FALCON_SIGNATURE}>),
    Falcon1024(core_lib::sig::falcon::falcon1024::types::Signature<{core_lib::sig::falcon::falcon1024::constants::FALCON_SIGNATURE}>),
    Haraka192f(haraka_192f::Signature),
    Sha2_256s(sha2_256s::Signature),
    Shake128f(shake_128f::Signature),
}
pub enum SigScheme {
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Falcon512,
    Falcon1024,
    Haraka192f,
    Sha2_256s,
    Shake128f,
}
pub trait SignatureService {
    fn generate_keypair(variant: SigVariant) -> Result<KeypairResponse, AppError>;
    fn sign(scheme: SigScheme, message: &[u8], sk: AnySecretKey) -> Result<AnySignature, AppError>;
    fn verify(variant: SigVariant, pk_b64: &str, msg: &str, sig_b64: &str) -> Result<bool, AppError>;
}
pub struct SigService;
impl SignatureService for SigService {
    fn generate_keypair(variant: SigVariant) -> Result<KeypairResponse, AppError> {
        match variant {
            SigVariant::Dilithium2 => {
                let (pk, sk) = Dilithium2::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::Dilithium3 => {
                let (pk, sk) = Dilithium3::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::Dilithium5 => {
                let (pk, sk) = Dilithium5::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::FALCON512 => {
                let (pk, sk) = Falcon512::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::FALCON1024 => {
                let (pk, sk) = Falcon1024::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(&pk.0),
                    sk: general_purpose::STANDARD.encode(&sk.0.expose_secret()),
                })
            }
            SigVariant::Haraka192f => {
                let (pk, sk) = haraka_192f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            SigVariant::Sha2_256s => {
                let (pk, sk) = sha2_256s::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
            SigVariant::Shake128f => {
                let (pk, sk) = shake_128f::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok(KeypairResponse {
                    pk: general_purpose::STANDARD.encode(pk.as_bytes()),
                    sk: general_purpose::STANDARD.encode(sk.as_bytes()),
                })
            }
        }
    }

    fn sign(scheme: SigScheme, message: &[u8], sk: AnySecretKey) -> Result<AnySignature, AppError> {
        match (scheme, sk) {
            (SigScheme::Dilithium2, AnySecretKey::Dilithium2(sk)) => {
                let sig = Dilithium2::sign(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium2(sig))
            }
            (SigScheme::Dilithium3, AnySecretKey::Dilithium3(sk)) => {
                let sig = Dilithium3::sign(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium3(sig))
            }
            (SigScheme::Dilithium5, AnySecretKey::Dilithium5(sk)) => {
                let sig = Dilithium5::sign(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Dilithium5(sig))
            }
            (SigScheme::Falcon512, AnySecretKey::Falcon512(sk)) => {
                let sig = Falcon512::sign(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Falcon512(sig))
            }
            (SigScheme::Falcon1024, AnySecretKey::Falcon1024(sk)) => {
                let sig = Falcon1024::sign(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Falcon1024(sig))
            }
            (SigScheme::Haraka192f, AnySecretKey::Haraka192f(sk)) => {
                let sig = haraka_192f::sign_detached(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Haraka192f(sig))
            }
            (SigScheme::Sha2_256s, AnySecretKey::Sha2_256s(sk)) => {
                let sig = sha2_256s::sign_detached(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Sha2_256s(sig))
            }
            (SigScheme::Shake128f, AnySecretKey::Shake128f(sk)) => {
                let sig = shake_128f::sign_detached(message, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(AnySignature::Shake128f(sig))
            }
            _ => Err(AppError::InvalidVariant),
        }
    }

    fn verify(variant: SigVariant, pk_b64: &str, msg: &str, sig_b64: &str) -> Result<bool, AppError> {
        let pk_bytes = general_purpose::STANDARD.decode(pk_b64).map_err(|_| AppError::InvalidBase64)?;
        let sig_bytes = general_purpose::STANDARD.decode(sig_b64).map_err(|_| AppError::InvalidBase64)?;
        let msg_bytes = msg.as_bytes();
        match variant {
            SigVariant::Dilithium2 => {
                let pk = core_lib::sig::dilithium::dilithium2::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium2::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium2::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Dilithium3 => {
                let pk = core_lib::sig::dilithium::dilithium3::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium3::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium3::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Dilithium5 => {
                let pk = core_lib::sig::dilithium::dilithium5::types::PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = core_lib::sig::dilithium::dilithium5::types::Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Dilithium5::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::FALCON512 => {
                use core_lib::sig::falcon::falcon512::types::PublicKey as Falcon512PublicKey;
                use core_lib::sig::falcon::falcon512::types::Signature as Falcon512Signature;
                let pk = Falcon512PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = Falcon512Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Falcon512::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::FALCON1024 => {
                use core_lib::sig::falcon::falcon1024::types::{PublicKey as Falcon1024PublicKey, Signature as Falcon1024Signature};
                let pk = Falcon1024PublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidPublicKey)?);
                let sig = Falcon1024Signature(sig_bytes.try_into().map_err(|_| AppError::InvalidSignature)?);
                Ok(Falcon1024::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Haraka192f => {
                let pk = haraka_192f::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = haraka_192f::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(haraka_192f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            SigVariant::Sha2_256s => {
                let pk = sha2_256s::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = sha2_256s::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(sha2_256s::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
            SigVariant::Shake128f => {
                let pk = shake_128f::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = shake_128f::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(shake_128f::verify_detached(&sig, msg_bytes, &pk).is_ok())
            }
        }
    }
}
