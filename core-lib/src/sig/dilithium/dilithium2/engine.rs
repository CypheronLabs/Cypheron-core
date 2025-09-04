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

use super::bindings::*;
use super::types::*;
use crate::security::{
    validate_dilithium_message_bounds, validate_dilithium_signature_output,
    validate_ffi_dilithium_buffer, validate_ffi_dilithium_ptr, verify_buffer_initialized, FfiSafe,
};
use crate::sig::dilithium::common::*;
use crate::sig::dilithium::errors::DilithiumError;
use crate::sig::traits::SignatureEngine;

use secrecy::{ExposeSecret, SecretBox};

#[derive(Debug, Clone, Copy, Default)]
pub struct Dilithium2Engine;

impl SignatureEngine for Dilithium2Engine {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = DilithiumError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk = [0u8; ML_DSA_44_PUBLIC];
        let mut sk = [0u8; ML_DSA_44_SECRET];

        validate_ffi_dilithium_buffer!(&pk, ML_DSA_44_PUBLIC);
        validate_ffi_dilithium_buffer!(&sk, ML_DSA_44_SECRET);
        validate_ffi_dilithium_ptr!(pk.as_mut_ptr());
        validate_ffi_dilithium_ptr!(sk.as_mut_ptr());

        let result = unsafe { pqcrystals_dilithium2_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        match result {
            0 => Ok((PublicKey(pk), SecretKey(SecretBox::new(sk.into())))),
            code => Err(DilithiumError::from_c_code(code, "keypair")),
        }
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        validate_dilithium_message_bounds!(msg);

        let mut sig_buffer = [0u8; ML_DSA_44_SIGNATURE];
        let mut siglen = 0usize;
        let sk_bytes = sk.0.expose_secret();

        validate_ffi_dilithium_buffer!(sk_bytes, ML_DSA_44_SECRET);
        validate_ffi_dilithium_buffer!(&sig_buffer, ML_DSA_44_SIGNATURE);
        validate_ffi_dilithium_ptr!(sig_buffer.as_mut_ptr());
        validate_ffi_dilithium_ptr!(msg.as_ptr());
        validate_ffi_dilithium_ptr!(sk_bytes.as_ptr());

        let result = unsafe {
            pqcrystals_dilithium2_ref_signature(
                sig_buffer.as_mut_ptr(),
                &mut siglen,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_bytes.as_ptr(),
            )
        };

        match result {
            0 => {
                validate_dilithium_signature_output!(sig_buffer, siglen, ML_DSA_44_SIGNATURE);
                Ok(Signature(sig_buffer))
            }
            code => Err(DilithiumError::from_c_code(code, "sign")),
        }
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        if msg.len() > usize::MAX / 2 {
            return false;
        }
        if !msg.is_valid_for_ffi() && !msg.is_empty() {
            return false;
        }

        if sig.0.len() != ML_DSA_44_SIGNATURE {
            return false;
        }
        if pk.0.len() != ML_DSA_44_PUBLIC {
            return false;
        }

        if !sig.0.is_valid_for_ffi() {
            return false;
        }
        if !pk.0.is_valid_for_ffi() {
            return false;
        }

        if sig.0.as_ptr().is_null() || msg.as_ptr().is_null() || pk.0.as_ptr().is_null() {
            return false;
        }

        let sig_len = sig.0.len();
        let result = unsafe {
            pqcrystals_dilithium2_ref_verify(
                sig.0.as_ptr(),
                sig_len,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                pk.0.as_ptr(),
            )
        };
        result == 0
    }
}
