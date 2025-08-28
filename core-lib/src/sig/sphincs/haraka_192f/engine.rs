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

use super::bindings::robust_ffi as ffi;
use super::types::{PublicKey, SecretKey, Seed, Signature};
use crate::sig::sphincs::errors::SphincsError;

pub fn public_key_bytes() -> usize {
    unsafe { ffi::crypto_sign_publickeybytes() as usize }
}
pub fn secret_key_bytes() -> usize {
    unsafe { ffi::crypto_sign_secretkeybytes() as usize }
}
pub fn signature_bytes() -> usize {
    unsafe { ffi::crypto_sign_bytes() as usize }
}
pub fn seed_bytes() -> usize {
    unsafe { ffi::crypto_sign_seedbytes() as usize }
}

pub fn keypair_from_seed_generate(seed: &Seed) -> Result<(PublicKey, SecretKey), SphincsError> {
    if seed.as_bytes().len() != seed_bytes() {
        return Err(SphincsError::InvalidSeedLength {
            expected: seed_bytes(),
            actual: seed.as_bytes().len(),
        });
    }

    let mut pk = PublicKey::new_uninitialized();
    let mut sk = SecretKey::new_uninitialized();

    let ret_code =
        unsafe { ffi::crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };

    if ret_code == 0 {
        Ok((pk, sk))
    } else {
        Err(SphincsError::KeyPairGenerationFailed(ret_code))
    }
}

pub fn keypair_generate() -> Result<(PublicKey, SecretKey), SphincsError> {
    let mut pk = PublicKey::new_uninitialized();
    let mut sk = SecretKey::new_uninitialized();

    let ret_code = unsafe { ffi::crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

    if ret_code == 0 {
        Ok((pk, sk))
    } else {
        Err(SphincsError::KeyPairGenerationFailed(ret_code))
    }
}

pub fn sign_detached_create(message: &[u8], sk: &SecretKey) -> Result<Signature, SphincsError> {
    if sk.as_bytes().len() != secret_key_bytes() {
        return Err(SphincsError::InvalidSecretKeyLength {
            expected: secret_key_bytes(),
            actual: sk.as_bytes().len(),
        });
    }

    let mut sig = Signature::new_uninitialized();
    let mut sig_len_written: usize = 0;

    let ret_code = unsafe {
        ffi::crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut sig_len_written,
            message.as_ptr(),
            message.len(),
            sk.as_ptr(),
        )
    };

    if ret_code == 0 {
        if sig_len_written != signature_bytes() {
            return Err(SphincsError::UnexpectedSignatureLength {
                expected: signature_bytes(),
                actual: sig_len_written,
            });
        }
        Ok(sig)
    } else {
        Err(SphincsError::SigningFailed(ret_code))
    }
}

pub fn verify_detached_check(
    signature: &Signature,
    message: &[u8],
    pk: &PublicKey,
) -> Result<(), SphincsError> {
    if signature.as_bytes().len() != signature_bytes() {
        return Err(SphincsError::InvalidSignatureLength {
            expected: signature_bytes(),
            actual: signature.as_bytes().len(),
        });
    }
    if pk.as_bytes().len() != public_key_bytes() {
        return Err(SphincsError::InvalidPublicKeyLength {
            expected: public_key_bytes(),
            actual: pk.as_bytes().len(),
        });
    }

    let ret_code = unsafe {
        ffi::crypto_sign_verify(
            signature.as_ptr(),
            signature.as_bytes().len(),
            message.as_ptr(),
            message.len(),
            pk.as_bytes().as_ptr(),
        )
    };

    if ret_code == 0 {
        Ok(())
    } else {
        Err(SphincsError::VerificationFailed)
    }
}

pub fn sign_combined_create(message: &[u8], sk: &SecretKey) -> Result<Vec<u8>, SphincsError> {
    if sk.as_bytes().len() != secret_key_bytes() {
        return Err(SphincsError::InvalidSecretKeyLength {
            expected: secret_key_bytes(),
            actual: sk.as_bytes().len(),
        });
    }

    
    if message.len() > u64::MAX as usize {
        return Err(SphincsError::MessageTooLarge);
    }

    let mut signed_msg_buf = vec![0u8; message.len() + signature_bytes()];
    let mut signed_msg_len_written: u64 = 0;

    let ret_code = unsafe {
        ffi::crypto_sign(
            signed_msg_buf.as_mut_ptr(),
            &mut signed_msg_len_written,
            message.as_ptr(),
            message.len() as u64,
            sk.as_ptr(),
        )
    };

    if ret_code == 0 {
        let written_len = signed_msg_len_written as usize;
        if signed_msg_len_written > usize::MAX as u64 {
            return Err(SphincsError::IntegerOverflow);
        }
        signed_msg_buf.truncate(written_len);
        Ok(signed_msg_buf)
    } else {
        Err(SphincsError::SigningFailed(ret_code))
    }
}

pub fn open_combined_verify(
    signed_message: &[u8],
    pk: &PublicKey,
) -> Result<Vec<u8>, SphincsError> {
    if pk.as_bytes().len() != public_key_bytes() {
        return Err(SphincsError::InvalidPublicKeyLength {
            expected: public_key_bytes(),
            actual: pk.as_bytes().len(),
        });
    }

    if signed_message.len() > u64::MAX as usize {
        return Err(SphincsError::MessageTooLarge);
    }

    let mut original_msg_buf = vec![0u8; signed_message.len()];
    let mut original_msg_len_written: u64 = 0;

    let ret_code = unsafe {
        ffi::crypto_sign_open(
            original_msg_buf.as_mut_ptr(),
            &mut original_msg_len_written,
            signed_message.as_ptr(),
            signed_message.len() as u64,
            pk.as_bytes().as_ptr(),
        )
    };

    if ret_code == 0 {
        if original_msg_len_written > usize::MAX as u64 {
            return Err(SphincsError::IntegerOverflow);
        }
        original_msg_buf.truncate(original_msg_len_written as usize);
        Ok(original_msg_buf)
    } else {
        Err(SphincsError::OpenFailed(ret_code))
    }
}
