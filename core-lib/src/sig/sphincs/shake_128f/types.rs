// pq-core/core-lib/src/sig/sphincs/shake_192f/types.rs (or your variant)

use super::bindings;
use crate::sig::sphincs::errors::SphincsError;
use std::fmt;
use zeroize::Zeroize;

use once_cell::sync::Lazy;

static PUBLIC_KEY_BYTES_USIZE: Lazy<usize> =
    Lazy::new(|| unsafe { bindings::robust_ffi::crypto_sign_publickeybytes() as usize });
static SECRET_KEY_BYTES_USIZE: Lazy<usize> =
    Lazy::new(|| unsafe { bindings::robust_ffi::crypto_sign_secretkeybytes() as usize });
static SIGNATURE_BYTES_USIZE: Lazy<usize> =
    Lazy::new(|| unsafe { bindings::robust_ffi::crypto_sign_bytes() as usize });
static SEED_BYTES_USIZE: Lazy<usize> =
    Lazy::new(|| unsafe { bindings::robust_ffi::crypto_sign_seedbytes() as usize });

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub(crate) fn new_uninitialized() -> Self {
        PublicKey(vec![0u8; *PUBLIC_KEY_BYTES_USIZE])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *PUBLIC_KEY_BYTES_USIZE {
            Err(SphincsError::InvalidPublicKeyLength {
                expected: *PUBLIC_KEY_BYTES_USIZE,
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
        *PUBLIC_KEY_BYTES_USIZE
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyShake192f")
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
        SecretKey(vec![0u8; *SECRET_KEY_BYTES_USIZE])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *SECRET_KEY_BYTES_USIZE {
            Err(SphincsError::InvalidSecretKeyLength {
                expected: *SECRET_KEY_BYTES_USIZE,
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
        *SECRET_KEY_BYTES_USIZE
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
        Signature(vec![0u8; *SIGNATURE_BYTES_USIZE])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphincsError> {
        if bytes.len() != *SIGNATURE_BYTES_USIZE {
            Err(SphincsError::InvalidSignatureLength {
                expected: *SIGNATURE_BYTES_USIZE,
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
        *SIGNATURE_BYTES_USIZE
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureShake192f")
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
        if bytes.len() != *SEED_BYTES_USIZE {
            Err(SphincsError::InvalidSeedLength {
                expected: *SEED_BYTES_USIZE,
                actual: bytes.len(),
            })
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
        *SEED_BYTES_USIZE
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedShake192f").field("len", &Self::length()).finish_non_exhaustive()
    }
}
