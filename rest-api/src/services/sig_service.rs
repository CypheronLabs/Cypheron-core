use base64::{engine::general_purpose, Engine as _};
use core_lib::sig::falcon::falcon1024::constants::FALCON_SECRET;
use core_lib::sig::falcon::falcon512::types::SecretKey;
use core_lib::sig::Falcon512;
use core_lib::sig::Falcon1024;
use core_lib::sig::traits::SignatureEngine;
use secrecy::ExposeSecret;
use crate::error::AppError;
use core_lib::sig::dilithium::common::*;
use crate::models::sig::*;
use core_lib::sig::dilithium::{dilithium2::Dilithium2, dilithium3::Dilithium3, dilithium5::Dilithium5};
use core_lib::sig::sphincs::{haraka_192f, sha2_256s, shake_128f};
use core_lib::sig::sphincs::haraka_192f::Haraka192f;
use core_lib::sig::sphincs::sha2_256s::Sha2_256s;
use core_lib::sig::sphincs::shake_128f::Shake128f;

pub struct SigService;

impl SigService {
    pub fn generate_keypair(variant: SigVariant) -> Result<KeypairResponse, AppError> {
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
                //let (pk, sk) = crate::services.map_err(|_| AppError::KeyGenFailed)?;
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

    pub fn sign(variant: SigVariant, message: &str, sk_b64: &str) -> Result<SignResponse, AppError> {
        let sk_bytes = general_purpose::STANDARD
            .decode(sk_b64)
            .map_err(|_| AppError::InvalidSecretKey)?;
        let message_bytes = message
            .as_bytes();
        match variant {
            SigVariant::Dilithium2 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium2::types::SecretKey;

                let arr: [u8; DILITHIUM2_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium2::sign(message_bytes, &sk)  
                    .map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.0),
                })
            }
            SigVariant::Dilithium3 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium3::types::SecretKey;

                let arr: [u8; DILITHIUM3_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium3::sign(message_bytes, &sk)
                    .map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.0),
                })
            }
            SigVariant::Dilithium5 => {
                use secrecy::SecretBox;
                use core_lib::sig::dilithium::dilithium5::types::SecretKey;

                let arr: [u8; DILITHIUM5_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;

                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Dilithium5::sign(message_bytes, &sk)
                    .map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.0),
                })
            }
            SigVariant::FALCON512 => {
                use secrecy::SecretBox;
                use core_lib::sig::Falcon512;

                use core_lib::sig::falcon::falcon512::constants::FALCON_SECRET as FALCON512_SECRET;
                let arr: [u8; FALCON512_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Falcon512::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.0),
                })
            }
            SigVariant::FALCON1024 => {
                use secrecy::SecretBox;
                use core_lib::sig::Falcon1024;
                use core_lib::sig::falcon::falcon1024::constants::FALCON_SECRET;
                use core_lib::sig::falcon::falcon1024::types::SecretKey as Falcon1024SecretKey;

                let arr: [u8; FALCON_SECRET] = sk_bytes
                    .try_into()
                    .map_err(|_| AppError::InvalidSecretKey)?;
                let sk = Falcon1024SecretKey(SecretBox::new(Box::new(arr)));
                let sig = Falcon1024::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.0),
                })
            }
            SigVariant::Haraka192f => {
                let sk = Haraka192f::SecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = Haraka192f::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.as_bytes()),
                })
            }
            SigVariant::Sha2_256s => {
                let sk = Sha2_256s::SecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = Sha2_256s::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.as_bytes()),
                })
            }
            SigVariant::Shake128f => {
                let sk = Shake128f::SecretKey::from_bytes(&sk_bytes).map_err(|_| AppError::InvalidSecretKey)?;
                let sig = Shake128f::sign(message_bytes, &sk).map_err(|_| AppError::SigningFailed)?;
                Ok(SignResponse {
                    signature: general_purpose::STANDARD.encode(sig.as_bytes()),
                })
            }

            _ => Err(AppError::InvalidVariant),
        }
    }
    
    pub fn verify(variant: SigVariant, pk_b64: &str, msg: &str, sig_b64: &str) -> Result<bool, AppError> {
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
                let pk = Haraka192f::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Haraka192f::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(Haraka192f::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Sha2_256s => {
                let pk = Sha2_256s::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Sha2_256s::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(Sha2_256s::verify(msg_bytes, &sig, &pk))
            }
            SigVariant::Shake128f => {
                let pk = Shake128f::PublicKey::from_bytes(&pk_bytes).map_err(|_| AppError::InvalidPublicKey)?;
                let sig = Shake128f::Signature::from_bytes(&sig_bytes).map_err(|_| AppError::InvalidSignature)?;
                Ok(Shake128f::verify(msg_bytes, &sig, &pk))
            }

            _ => Err(AppError::InvalidVariant),
        }
    }
}