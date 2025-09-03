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

use crate::sig::dilithium::common::*;
use secrecy::SecretBox;
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; ML_DSA_44_PUBLIC]);
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey([... {} bytes ...])", ML_DSA_44_PUBLIC)
    }
}
pub struct SecretKey(pub SecretBox<[u8; ML_DSA_44_SECRET]>);
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED {} bytes])", ML_DSA_44_SECRET)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; ML_DSA_44_SIGNATURE]);
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        let display_len = std::cmp::min(len, 16);
        write!(
            f,
            "Signature({:02X?}... {} bytes total ...)",
            &self.0[..display_len],
            len
        )
    }
}
