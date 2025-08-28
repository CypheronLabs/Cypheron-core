use crate::kem::sizes;
use crate::kem::{Kem, KemVariant};

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(not(rust_analyzer))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/ml_kem_512_bindings.rs"));
}
use bindings::*;

pub struct MlKemSecretKey(pub SecretBox<[u8; sizes::ML_KEM_512_SECRET]>);

#[deprecated(since = "0.2.0", note = "Use MlKemSecretKey instead for NIST FIPS 203 compliance")]
pub type KyberSecretKey = MlKemSecretKey;

#[derive(Clone)]
pub struct MlKemPublicKey(pub [u8; sizes::ML_KEM_512_PUBLIC]);

#[deprecated(since = "0.2.0", note = "Use MlKemPublicKey instead for NIST FIPS 203 compliance")]
pub type KyberPublicKey = MlKemPublicKey;

#[derive(Error, Debug)]
pub enum MlKemError {
    #[error("Key generation failed - entropy failure")]
    KeyGenerationEntropyFailure,
    #[error("Key generation failed - internal error")]
    KeyGenerationInternalError,
    #[error("Encapsulation failed - invalid public key")]
    EncapsulationInvalidKey,
    #[error("Encapsulation failed - internal error")]
    EncapsulationInternalError,
    #[error("Decapsulation failed - invalid ciphertext")]
    DecapsulationInvalidCiphertext,
    #[error("Decapsulation failed - internal error")]
    DecapsulationInternalError,
    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },
    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    #[error("Invalid secret key length: expected {expected}, got {actual}")]
    InvalidSecretKeyLength { expected: usize, actual: usize },
    #[error("ML-KEM C library returned error code: {code}")]
    CLibraryError { code: i32 },
}

#[deprecated(since = "0.2.0", note = "Use MlKemError instead for NIST FIPS 203 compliance")]
pub type KyberError = MlKemError;

impl MlKemError {
    pub fn from_c_code(code: i32, operation: &str) -> Self {
        match code {
            0 => panic!("Should not map success code 0 to error"),
            -1 => match operation {
                "keypair" => MlKemError::KeyGenerationInternalError,
                "encapsulate" => MlKemError::EncapsulationInternalError,
                "decapsulate" => MlKemError::DecapsulationInternalError,
                _ => MlKemError::CLibraryError { code },
            },
            -2 => match operation {
                "keypair" => MlKemError::KeyGenerationEntropyFailure,
                "encapsulate" => MlKemError::EncapsulationInvalidKey,
                "decapsulate" => MlKemError::DecapsulationInvalidCiphertext,
                _ => MlKemError::CLibraryError { code },
            },
            _ => MlKemError::CLibraryError { code },
        }
    }
}

pub struct MlKem512;

#[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
pub type Kyber512 = MlKem512;

impl MlKem512 {
    pub fn variant() -> KemVariant {
        KemVariant::MlKem512
    }

    #[deprecated(since = "0.2.0", note = "Use variant() instead for NIST FIPS 203 compliance")]
    pub fn legacy_variant() -> KemVariant {
        #[allow(deprecated)]
        KemVariant::Kyber512
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::ML_KEM_512_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for MlKem512 {
    type PublicKey = MlKemPublicKey;
    type SecretKey = MlKemSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::ML_KEM_512_SHARED]>;
    type Error = MlKemError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; sizes::ML_KEM_512_PUBLIC];
        let mut sk = [0u8; sizes::ML_KEM_512_SECRET];

        let result = unsafe { pqcrystals_kyber512_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

        if result != 0 {
            pk.zeroize();
            sk.zeroize();
            return Err(MlKemError::from_c_code(result, "keypair"));
        }

        Ok((MlKemPublicKey(pk), MlKemSecretKey(SecretBox::new(Box::new(sk)))))
    }

    fn encapsulate(
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        if pk.0.len() != sizes::ML_KEM_512_PUBLIC {
            return Err(MlKemError::InvalidPublicKeyLength {
                expected: sizes::ML_KEM_512_PUBLIC,
                actual: pk.0.len(),
            });
        }

        let mut ct = vec![0u8; sizes::ML_KEM_512_CIPHERTEXT];
        let mut ss = [0u8; sizes::ML_KEM_512_SHARED];

        let result =
            unsafe { pqcrystals_kyber512_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr()) };

        if result != 0 {
            ss.zeroize();
            return Err(MlKemError::from_c_code(result, "encapsulate"));
        }

        Ok((ct, SecretBox::new(ss.into())))
    }

    fn decapsulate(
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        if ct.len() != sizes::ML_KEM_512_CIPHERTEXT {
            return Err(MlKemError::InvalidCiphertextLength {
                expected: sizes::ML_KEM_512_CIPHERTEXT,
                actual: ct.len(),
            });
        }
        if sk.0.expose_secret().len() != sizes::ML_KEM_512_SECRET {
            return Err(MlKemError::InvalidSecretKeyLength {
                expected: sizes::ML_KEM_512_SECRET,
                actual: sk.0.expose_secret().len(),
            });
        }

        let mut ss = [0u8; sizes::ML_KEM_512_SHARED];

        let result =
            unsafe { pqcrystals_kyber512_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.0.expose_secret().as_ptr()) };

        if result != 0 {
            ss.zeroize();
            return Err(MlKemError::from_c_code(result, "decapsulate"));
        }

        Ok(SecretBox::new(ss.into())) // WRAP IN Ok()
    }
}
