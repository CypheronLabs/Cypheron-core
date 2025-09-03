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

use crate::kem::sizes;
use crate::kem::{Kem, KemVariant};
use crate::security::{validate_ffi_kem_buffer, validate_ffi_kem_ptr, FfiSafe};

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(not(rust_analyzer))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/ml_kem_768_bindings.rs"));
}
use bindings::*;

pub struct MlKemSecretKey(pub SecretBox<[u8; sizes::ML_KEM_768_SECRET]>);

#[deprecated(
    since = "0.2.0",
    note = "Use MlKemSecretKey instead for NIST FIPS 203 compliance"
)]
pub type KyberSecretKey = MlKemSecretKey;

#[derive(Clone)]
pub struct MlKemPublicKey(pub [u8; sizes::ML_KEM_768_PUBLIC]);

#[deprecated(
    since = "0.2.0",
    note = "Use MlKemPublicKey instead for NIST FIPS 203 compliance"
)]
pub type KyberPublicKey = MlKemPublicKey;

#[derive(Error, Debug)]
pub enum MlKemError {
    #[error("Key generation failed - entropy failure (ERROR-KEM-001)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-001")]
    KeyGenerationEntropyFailure,
    #[error("Key generation failed - internal error (ERROR-KEM-004)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-004")]
    KeyGenerationInternalError,
    #[error("Encapsulation failed - invalid public key (ERROR-KEM-003)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-003")]
    EncapsulationInvalidKey,
    #[error("Encapsulation failed - internal error (ERROR-KEM-005)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-005")]
    EncapsulationInternalError,
    #[error("Decapsulation failed - invalid ciphertext (ERROR-KEM-002)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-002")]
    DecapsulationInvalidCiphertext,
    #[error("Decapsulation failed - internal error (ERROR-KEM-006)\nSee: https://docs.rs/cypheron-core/troubleshooting/errors.html#error-kem-006")]
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

#[deprecated(
    since = "0.2.0",
    note = "Use MlKemError instead for NIST FIPS 203 compliance"
)]
pub type KyberError = MlKemError;

impl MlKemError {
    pub fn from_c_code(code: i32, operation: &str) -> Self {
        match code {
            0 => {
                debug_assert!(false, "Should not map success code 0 to error");
                MlKemError::CLibraryError { code: 0 }
            },
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

pub struct MlKem768;

#[deprecated(
    since = "0.2.0",
    note = "Use MlKem768 instead for NIST FIPS 203 compliance"
)]
pub type Kyber768 = MlKem768;

impl MlKem768 {
    pub fn variant() -> KemVariant {
        KemVariant::MlKem768
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use variant() instead for NIST FIPS 203 compliance"
    )]
    pub fn legacy_variant() -> KemVariant {
        #[allow(deprecated)]
        KemVariant::Kyber768
    }

    pub fn expose_shared(secret: &SecretBox<[u8; sizes::ML_KEM_768_SHARED]>) -> &[u8] {
        secret.expose_secret()
    }
}

impl Kem for MlKem768 {
    type PublicKey = MlKemPublicKey;
    type SecretKey = MlKemSecretKey;
    type Ciphertext = Vec<u8>;
    type SharedSecret = SecretBox<[u8; sizes::ML_KEM_768_SHARED]>;
    type Error = MlKemError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; sizes::ML_KEM_768_PUBLIC];
        let mut sk = [0u8; sizes::ML_KEM_768_SECRET];

        validate_ffi_kem_buffer!(&pk, sizes::ML_KEM_768_PUBLIC);
        validate_ffi_kem_buffer!(&sk, sizes::ML_KEM_768_SECRET);
        validate_ffi_kem_ptr!(pk.as_mut_ptr());
        validate_ffi_kem_ptr!(sk.as_mut_ptr());

        let result = unsafe { pqcrystals_kyber768_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

        if result != 0 {
            pk.zeroize();
            sk.zeroize();
            return Err(MlKemError::from_c_code(result, "keypair"));
        }

        Ok((
            MlKemPublicKey(pk),
            MlKemSecretKey(SecretBox::new(Box::new(sk))),
        ))
    }

    fn encapsulate(
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        validate_ffi_kem_buffer!(&pk.0, sizes::ML_KEM_768_PUBLIC);

        let mut ct = vec![0u8; sizes::ML_KEM_768_CIPHERTEXT];
        let mut ss = [0u8; sizes::ML_KEM_768_SHARED];

        validate_ffi_kem_buffer!(&ct, sizes::ML_KEM_768_CIPHERTEXT);
        validate_ffi_kem_buffer!(&ss, sizes::ML_KEM_768_SHARED);
        validate_ffi_kem_ptr!(ct.as_mut_ptr());
        validate_ffi_kem_ptr!(ss.as_mut_ptr());
        validate_ffi_kem_ptr!(pk.0.as_ptr());

        let result =
            unsafe { pqcrystals_kyber768_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr()) };

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
        validate_ffi_kem_buffer!(ct, sizes::ML_KEM_768_CIPHERTEXT);
        let sk_bytes = sk.0.expose_secret();
        validate_ffi_kem_buffer!(sk_bytes, sizes::ML_KEM_768_SECRET);

        let mut ss = [0u8; sizes::ML_KEM_768_SHARED];
        validate_ffi_kem_buffer!(&ss, sizes::ML_KEM_768_SHARED);
        
        validate_ffi_kem_ptr!(ss.as_mut_ptr());
        validate_ffi_kem_ptr!(ct.as_ptr());
        validate_ffi_kem_ptr!(sk_bytes.as_ptr());

        let result = unsafe {
            pqcrystals_kyber768_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk_bytes.as_ptr())
        };

        if result != 0 {
            ss.zeroize();
            return Err(MlKemError::from_c_code(result, "decapsulate"));
        }

        Ok(SecretBox::new(ss.into()))
    }
}
