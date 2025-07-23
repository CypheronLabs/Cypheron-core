use crate::utils::encoding::{
    decode_base64, decode_base64_url, decode_hex, encode_base64, encode_base64_url, encode_hex,
};
use crate::{error::AppError, validation};
use base64::{engine::general_purpose, Engine as _};
use core_lib::kem::{self, Kem, KemVariant, MlKem1024, MlKem512, MlKem768};
use secrecy::ExposeSecret;

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
        let service_start = std::time::Instant::now();
        eprintln!(
            "DEBUG: KemService::generate_keypair entry for {:?} at {:?}",
            variant,
            service_start.elapsed()
        );

        match variant {
            // NIST FIPS 203 compliant variants (primary implementations)
            KemVariant::MlKem512 => {
                eprintln!(
                    "DEBUG: About to call MlKem512::keypair at {:?}",
                    service_start.elapsed()
                );
                let (pk, sk) = MlKem512::keypair().map_err(|_| AppError::KeyGenFailed)?;
                eprintln!("DEBUG: MlKem512::keypair completed at {:?}", service_start.elapsed());
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            KemVariant::MlKem768 => {
                eprintln!(
                    "DEBUG: About to call MlKem768::keypair at {:?}",
                    service_start.elapsed()
                );
                let (pk, sk) = MlKem768::keypair().map_err(|_| AppError::KeyGenFailed)?;
                eprintln!("DEBUG: MlKem768::keypair completed at {:?}", service_start.elapsed());
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            KemVariant::MlKem1024 => {
                let (pk, sk) = MlKem1024::keypair().map_err(|_| AppError::KeyGenFailed)?;
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            // Backward compatibility for deprecated variants
            #[allow(deprecated)]
            KemVariant::Kyber512 => {
                let (pk, sk) = MlKem512::keypair().map_err(|_| AppError::KeyGenFailed)?; // Forward to NIST implementation
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            #[allow(deprecated)]
            KemVariant::Kyber768 => {
                let (pk, sk) = MlKem768::keypair().map_err(|_| AppError::KeyGenFailed)?; // Forward to NIST implementation
                Ok((
                    general_purpose::STANDARD.encode(&pk.0),
                    general_purpose::STANDARD.encode(&sk.0),
                ))
            }
            #[allow(deprecated)]
            KemVariant::Kyber1024 => {
                let (pk, sk) = MlKem1024::keypair().map_err(|_| AppError::KeyGenFailed)?; // Forward to NIST implementation
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
            // NIST FIPS 203 compliant variants (primary)
            KemVariant::MlKem512 => 800,
            KemVariant::MlKem768 => 1184,
            KemVariant::MlKem1024 => 1568,
            // Backward compatibility for deprecated variants
            #[allow(deprecated)]
            KemVariant::Kyber512 => 800,
            #[allow(deprecated)]
            KemVariant::Kyber768 => 1184,
            #[allow(deprecated)]
            KemVariant::Kyber1024 => 1568,
        };

        if pk_bytes.len() != expected_pk_size {
            return Err(AppError::ValidationError(format!(
                "Invalid public key size for {:?}: expected {} bytes, got {}",
                variant,
                expected_pk_size,
                pk_bytes.len()
            )));
        }
        match variant {
            // NIST FIPS 203 compliant variants (primary implementations)
            KemVariant::MlKem512 => {
                let pk = kem::ml_kem_512::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem512::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?;
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            KemVariant::MlKem768 => {
                let pk = kem::ml_kem_768::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem768::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?;
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            KemVariant::MlKem1024 => {
                let pk = kem::ml_kem_1024::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem1024::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?;
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            // Backward compatibility for deprecated variants
            #[allow(deprecated)]
            KemVariant::Kyber512 => {
                let pk = kem::ml_kem_512::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem512::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?; // Forward to NIST implementation
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            #[allow(deprecated)]
            KemVariant::Kyber768 => {
                let pk = kem::ml_kem_768::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem768::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?; // Forward to NIST implementation
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
            #[allow(deprecated)]
            KemVariant::Kyber1024 => {
                let pk = kem::ml_kem_1024::MlKemPublicKey(
                    pk_bytes.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let (ct, ss) =
                    MlKem1024::encapsulate(&pk).map_err(|_| AppError::EncapsulationFailed)?; // Forward to NIST implementation
                Ok((
                    general_purpose::STANDARD.encode(&ct),
                    general_purpose::STANDARD.encode(&ss.expose_secret()),
                ))
            }
        }
    }
    pub fn decapsulate(
        variant: KemVariant,
        ct_b64: &str,
        sk_b64: &str,
    ) -> Result<String, AppError> {
        validation::validate_base64_key(ct_b64)?;
        validation::validate_base64_key(sk_b64)?;

        let ct = general_purpose::STANDARD.decode(ct_b64)?;
        let sk = general_purpose::STANDARD.decode(sk_b64)?;

        let (expected_ct_size, expected_sk_size) = match variant {
            // NIST FIPS 203 compliant variants (primary)
            KemVariant::MlKem512 => (768, 1632),
            KemVariant::MlKem768 => (1088, 2400),
            KemVariant::MlKem1024 => (1568, 3168),
            // Backward compatibility for deprecated variants
            #[allow(deprecated)]
            KemVariant::Kyber512 => (768, 1632),
            #[allow(deprecated)]
            KemVariant::Kyber768 => (1088, 2400),
            #[allow(deprecated)]
            KemVariant::Kyber1024 => (1568, 3168),
        };

        if ct.len() != expected_ct_size {
            return Err(AppError::ValidationError(format!(
                "Invalid ciphertext size for {:?}: expected {} bytes, got {}",
                variant,
                expected_ct_size,
                ct.len()
            )));
        }

        if sk.len() != expected_sk_size {
            return Err(AppError::ValidationError(format!(
                "Invalid secret key size for {:?}: expected {} bytes, got {}",
                variant,
                expected_sk_size,
                sk.len()
            )));
        }

        match variant {
            // NIST FIPS 203 compliant variants (primary implementations)
            KemVariant::MlKem512 => {
                let sk = core_lib::kem::ml_kem_512::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem512::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?;
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            KemVariant::MlKem768 => {
                let sk = core_lib::kem::ml_kem_768::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem768::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?;
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            KemVariant::MlKem1024 => {
                let sk = core_lib::kem::ml_kem_1024::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem1024::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?;
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            // Backward compatibility for deprecated variants
            #[allow(deprecated)]
            KemVariant::Kyber512 => {
                let sk = core_lib::kem::ml_kem_512::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem512::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?; // Forward to NIST implementation
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            #[allow(deprecated)]
            KemVariant::Kyber768 => {
                let sk = core_lib::kem::ml_kem_768::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem768::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?; // Forward to NIST implementation
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
            #[allow(deprecated)]
            KemVariant::Kyber1024 => {
                let sk = core_lib::kem::ml_kem_1024::MlKemSecretKey(
                    sk.try_into().map_err(|_| AppError::InvalidLength)?,
                );
                let ss =
                    MlKem1024::decapsulate(&ct, &sk).map_err(|_| AppError::DecapsulationFailed)?; // Forward to NIST implementation
                Ok(general_purpose::STANDARD.encode(ss.expose_secret()))
            }
        }
    }
}
