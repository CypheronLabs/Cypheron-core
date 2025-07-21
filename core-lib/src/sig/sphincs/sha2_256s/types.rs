use super::bindings::ffi;
use crate::sig::sphincs::errors::SphincsError;
use once_cell::sync::Lazy;
use std::{fmt, vec};
use zeroize::Zeroize;

static PUBLIC_KEY_BYTES_REF: Lazy<usize> =
    Lazy::new(|| unsafe { ffi::crypto_sign_publickeybytes() as usize });
static SECRET_KEY_BYTES_REF: Lazy<usize> =
    Lazy::new(|| unsafe { ffi::crypto_sign_secretkeybytes() as usize });
static SIGNATURE_BYTES_REF: Lazy<usize> =
    Lazy::new(|| unsafe { ffi::crypto_sign_bytes() as usize });

static SEED_BYTES_REF: Lazy<usize> = Lazy::new(|| unsafe { ffi::crypto_sign_seedbytes() as usize });

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);
impl PublicKey {
    pub(crate) fn new_uninitialized() -> Self {
        PublicKey(vec![0u8; *PUBLIC_KEY_BYTES_REF])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        let expected_len = *PUBLIC_KEY_BYTES_REF;
        if bytes.len() != expected_len {
            Err(SphincsError::InvalidPublicKeyLength {
                expected: expected_len,
                actual: bytes.len(),
            })
        } else {
            Ok(PublicKey(bytes.to_vec()))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    pub fn length() -> usize {
        *PUBLIC_KEY_BYTES_REF
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeySha2_256fRobust") // <--- Optional: Specific debug name
            .field("len", &self.0.len())
            .field(
                "bytes_prefix",
                &self.0.get(..std::cmp::min(self.0.len(), 8)).unwrap_or_default(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(Vec<u8>);
impl SecretKey {
    pub(crate) fn new_uninitialized() -> Self {
        SecretKey(vec![0u8; *SECRET_KEY_BYTES_REF])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *SECRET_KEY_BYTES_REF {
            Err(SphincsError::InvalidSecretKeyLength {
                expected: *SECRET_KEY_BYTES_REF,
                actual: bytes.len(),
            })
        } else {
            Ok(SecretKey(bytes.to_vec()))
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn length() -> usize {
        *SECRET_KEY_BYTES_REF
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKeyShake192f").field("len", &Self::length()).finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);
impl Signature {
    pub(crate) fn new_uninitialized() -> Self {
        Signature(vec![0u8; *SIGNATURE_BYTES_REF])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *SIGNATURE_BYTES_REF {
            Err(SphincsError::InvalidSignatureLength {
                expected: *SIGNATURE_BYTES_REF,
                actual: bytes.len(),
            })
        } else {
            Ok(Signature(bytes.to_vec()))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn length() -> usize {
        *SIGNATURE_BYTES_REF
    }
}
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureSha2_256fRobust")
            .field("len", &self.0.len())
            .field(
                "bytes_prefix",
                &self.0.get(..std::cmp::min(self.0.len(), 8)).unwrap_or_default(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed(Vec<u8>);
impl Seed {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *SEED_BYTES_REF {
            Err(SphincsError::InvalidSeedLength { expected: *SEED_BYTES_REF, actual: bytes.len() })
        } else {
            Ok(Seed(bytes.to_vec()))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn length() -> usize {
        *SEED_BYTES_REF
    }
}
impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedSha2_256fRobust").field("len", &Self::length()).finish_non_exhaustive()
    }
}
