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

use secrecy::SecretBox;
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey([... {} bytes ...])", N)
    }
}

pub struct SecretKey<const N: usize>(pub SecretBox<[u8; N]>);
impl<const N: usize> Zeroize for SecretKey<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED {} bytes])", N)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature<const N: usize>(pub [u8; N]);
impl<const N: usize> fmt::Debug for Signature<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        let display_len = std::cmp::min(len, 16);
        write!(f, "Signature({:02X?}... {} bytes total ...)", &self.0[..display_len], len)
    }
}
use crate::sig::falcon::falcon512::constants::{FALCON_PUBLIC, FALCON_SECRET, FALCON_SIGNATURE};

pub type Falcon512PublicKey = PublicKey<FALCON_PUBLIC>;
pub type Falcon512SecretKey = SecretKey<FALCON_SECRET>;
pub type Falcon512Signature = Signature<FALCON_SIGNATURE>;
