use core_lib::kem::{self, Kem, KemVariant, Kyber512, Kyber768, Kyber1024};
use secrecy::ExposeSecret;
use base64::{engine::general_purpose, Engine as _};
use crate::error::AppError;

pub struct KemService;

impl KemService {
    pub fn generate_keypair(variant: KemVariant) -> Result<(String, String), AppError> {
        match variant {
            KemVariant::Kyber512 => {
                let(pk, sk) = Kyber512::keypair();
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                    ))
            }
            KemVariant::Kyber768 => {
                let (pk, sk) = Kyber768::keypair();
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            KemVariant::Kyber1024 => {
                let(pk, sk) = Kyber1024::keypair();
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                    ))
            }

        }
    }
    pub fn encapsulate(variant: KemVariant, pk_64: &str) -> Result<(String, String), AppError> {
        let pk_bytes = general_purpose::STANDARD.decode(pk_64)?;

        match variant {
            KemVariant::Kyber512 => {
                let pk = kem::kyber512::KyberPublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?);
                let (ct, ss) = Kyber512::encapsulate(&pk);
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                    ))
            }
            KemVariant::Kyber768 => {
                let pk = kem::kyber768::KyberPublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?);
                let (ct, ss) = Kyber768::encapsulate(&pk);
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            KemVariant::Kyber1024 => {
                let pk = kem::kyber1024::KyberPublicKey(pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?);
                let (ct, ss) = Kyber1024::encapsulate(&pk);
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
        }
    }
    pub fn decapsulate(variant: KemVariant, ct_b64: &str, sk_b64: &str) -> Result<String, AppError> {
        let ct = general_purpose::STANDARD.decode(ct_b64)?;
        let sk = general_purpose::STANDARD.decode(sk_b64)?;

        match variant {
            KemVariant::Kyber512 => {
                let sk = core_lib::kem::kyber512::KyberSecretKey(sk.try_into().map_err(|_| AppError::InvalidLength)?);
                let ss = Kyber512::decapsulate(&ct, &sk);
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            KemVariant::Kyber768 => {
                let sk = core_lib::kem::kyber768::KyberSecretKey(sk.try_into().map_err(|_| AppError::InvalidLength)?);
                let ss = Kyber768::decapsulate(&ct, &sk);
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            KemVariant::Kyber1024 => {
                let sk = core_lib::kem::kyber1024::KyberSecretKey(sk.try_into().map_err(|_| AppError::InvalidLength)?);
                let ss = Kyber1024::decapsulate(&ct, &sk);
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
        }
    }
}