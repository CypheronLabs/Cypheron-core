use core_lib::kem::{self, Kem, KemVariant, Kyber512, Kyber768, Kyber1024};
use secrecy::ExposeSecret;
use base64::{engine::general_purpose, Engine as _};
use crate::{error::AppError, validation};
use crate::utils::encoding::{encode_base64, encode_hex, encode_base64_url, decode_base64, decode_hex, decode_base64_url};

pub struct KemService;

impl KemService {
    #[allow(dead_code)]
    fn encode_data(data: &[u8], format: &str) -> String {
        match format {
            "hex" => encode_hex(data),
            "base64url" => encode_base64_url(data),
            _ => encode_base64(data), 
        }
    }
    
    #[allow(dead_code)]
    fn decode_data(data: &str, format: &str) -> Result<Vec<u8>, AppError> {
        match format {
            "hex" => decode_hex(data),
            "base64url" => decode_base64_url(data),
            _ => decode_base64(data), 
        }
    }
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
        validation::validate_base64_key(pk_64)?;
        
        let pk_bytes = general_purpose::STANDARD.decode(pk_64)?;
        
        let expected_pk_size = match variant {
            KemVariant::Kyber512 => 800,
            KemVariant::Kyber768 => 1184,
            KemVariant::Kyber1024 => 1568,
        };
        
        if pk_bytes.len() != expected_pk_size {
            return Err(AppError::ValidationError(
                format!("Invalid public key size for {:?}: expected {} bytes, got {}", 
                    variant, expected_pk_size, pk_bytes.len())
            ));
        }
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
        validation::validate_base64_key(ct_b64)?;
        validation::validate_base64_key(sk_b64)?;
        
        let ct = general_purpose::STANDARD.decode(ct_b64)?;
        let sk = general_purpose::STANDARD.decode(sk_b64)?;
        
        let (expected_ct_size, expected_sk_size) = match variant {
            KemVariant::Kyber512 => (768, 1632),
            KemVariant::Kyber768 => (1088, 2400),
            KemVariant::Kyber1024 => (1568, 3168),
        };
        
        if ct.len() != expected_ct_size {
            return Err(AppError::ValidationError(
                format!("Invalid ciphertext size for {:?}: expected {} bytes, got {}", 
                    variant, expected_ct_size, ct.len())
            ));
        }
        
        if sk.len() != expected_sk_size {
            return Err(AppError::ValidationError(
                format!("Invalid secret key size for {:?}: expected {} bytes, got {}", 
                    variant, expected_sk_size, sk.len())
            ));
        }

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