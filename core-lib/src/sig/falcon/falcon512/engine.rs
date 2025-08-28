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

use crate::security::{validate_ffi_fixed_buffer, validate_message_bounds, safe_cast_to_c_void, FfiSafe};
use crate::sig::falcon::bindings::shake256_context;
use libc::c_int;
use rand::TryRngCore;
use secrecy::{ExposeSecret, SecretBox};
use std::ffi::c_void;
use std::mem::MaybeUninit;
use zeroize::Zeroize;

use crate::sig::falcon::bindings::*;
use crate::sig::falcon::errors::FalconErrors;
use crate::sig::falcon::falcon512::constants::*;
use crate::sig::falcon::falcon512::types::*;
use crate::sig::traits::SignatureEngine;

const FALCON_SEED_LENGTH: usize = 48;

struct SecureRngState {
    state: MaybeUninit<shake256_context>,
    initialized: bool,
}

impl SecureRngState {
    fn new() -> Result<Self, FalconErrors> {
        let mut seed = [0u8; FALCON_SEED_LENGTH];
        let mut state = MaybeUninit::<shake256_context>::uninit();

        rand::rng().try_fill_bytes(&mut seed).map_err(|_| {
            FalconErrors::RngInitializationFailed
        })?;

        unsafe {
            shake256_init_prng_from_seed(
                state.as_mut_ptr(),
                safe_cast_to_c_void!(seed.as_ptr()),
                seed.len(),
            );
        }

        seed.zeroize();
        
        Ok(SecureRngState {
            state,
            initialized: true,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut shake256_context {
        if !self.initialized {
            panic!("Attempting to use uninitialized RNG state");
        }
        self.state.as_mut_ptr()
    }
}

impl Drop for SecureRngState {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                std::ptr::write_bytes(self.state.as_mut_ptr(), 0, 1);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Falcon512Engine;

impl SignatureEngine for Falcon512Engine {
    type PublicKey = Falcon512PublicKey;
    type SecretKey = Falcon512SecretKey;
    type Signature = Falcon512Signature;
    type Error = FalconErrors;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk_buf = [0u8; FALCON_PUBLIC];
        let mut sk_buf = [0u8; FALCON_SECRET];
        let mut tmp = vec![0u8; FALCON_TMPSIZE_KEYGEN];

        validate_ffi_fixed_buffer!(&pk_buf, FALCON_PUBLIC);
        validate_ffi_fixed_buffer!(&sk_buf, FALCON_SECRET);
        validate_ffi_fixed_buffer!(&tmp, FALCON_TMPSIZE_KEYGEN);

        let mut rng_state = SecureRngState::new()?;

        let keygen_result: c_int = unsafe {
            falcon_keygen_make(
                rng_state.as_mut_ptr(),
                FALCON_LOGN as u32,
                safe_cast_to_c_void!(mut sk_buf.as_mut_ptr()),
                sk_buf.len(),
                safe_cast_to_c_void!(mut pk_buf.as_mut_ptr()),
                pk_buf.len(),
                safe_cast_to_c_void!(mut tmp.as_mut_ptr()),
                tmp.len(),
            )
        };

        tmp.zeroize();

        if keygen_result != 0 {
            sk_buf.zeroize();
            return Err(FalconErrors::from_c_code(keygen_result, "keypair"));
        }

        Ok((PublicKey(pk_buf), SecretKey(SecretBox::new(Box::from(sk_buf)))))
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        validate_message_bounds!(msg);
        
        let sk_bytes = sk.0.expose_secret();
        let mut sig_buf = [0u8; FALCON_SIGNATURE];
        let mut siglen: usize = FALCON_SIGNATURE;
        let mut tmp = vec![0u8; FALCON_TMPSIZE_SIGNDYN];

        validate_ffi_fixed_buffer!(sk_bytes, FALCON_SECRET);
        validate_ffi_fixed_buffer!(&tmp, FALCON_TMPSIZE_SIGNDYN);

        let mut rng_state = SecureRngState::new()?;

        let sign_result: c_int = unsafe {
            falcon_sign_dyn(
                rng_state.as_mut_ptr(),
                safe_cast_to_c_void!(mut sig_buf.as_mut_ptr()),
                &mut siglen,
                FALCON_SIG_COMPRESSED,
                safe_cast_to_c_void!(sk_bytes.as_ptr()),
                sk_bytes.len(),
                safe_cast_to_c_void!(msg.as_ptr()),
                msg.len(),
                safe_cast_to_c_void!(mut tmp.as_mut_ptr()),
                tmp.len(),
            )
        };

        tmp.zeroize();

        if sign_result != 0 {
            sig_buf.zeroize();
            return Err(FalconErrors::from_c_code(sign_result, "sign"));
        }

        if siglen > FALCON_SIGNATURE {
            sig_buf.zeroize();
            return Err(FalconErrors::SigningInternalError);
        }

        let mut actual_sig = [0u8; FALCON_SIGNATURE];
        actual_sig[..siglen].copy_from_slice(&sig_buf[..siglen]);
        
        for i in siglen..FALCON_SIGNATURE {
            actual_sig[i] = 0;
        }
        
        sig_buf.zeroize();
        Ok(Signature(actual_sig))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        if msg.len() > usize::MAX / 2 {
            return false;
        }
        if !msg.is_valid_for_ffi() && !msg.is_empty() {
            return false;
        }

        let sig_bytes = &sig.0;
        let pk_bytes = &pk.0;

        if sig_bytes.len() != FALCON_SIGNATURE || !sig_bytes.is_valid_for_ffi() {
            return false;
        }
        if pk_bytes.len() != FALCON_PUBLIC || !pk_bytes.is_valid_for_ffi() {
            return false;
        }

        let mut actual_sig_len = sig_bytes.len();
        while actual_sig_len > 0 && sig_bytes[actual_sig_len - 1] == 0 {
            actual_sig_len -= 1;
        }

        if actual_sig_len == 0 {
            return false;
        }

        let mut tmp = vec![0u8; FALCON_TMPSIZE_VERIFY];

        let verify_result: c_int = unsafe {
            falcon_verify(
                safe_cast_to_c_void!(sig_bytes.as_ptr()),
                actual_sig_len,
                FALCON_SIG_COMPRESSED,
                safe_cast_to_c_void!(pk_bytes.as_ptr()),
                pk_bytes.len(),
                safe_cast_to_c_void!(msg.as_ptr()),
                msg.len(),
                safe_cast_to_c_void!(mut tmp.as_mut_ptr()),
                tmp.len(),
            )
        };

        tmp.zeroize();
        verify_result == 0
    }
}
