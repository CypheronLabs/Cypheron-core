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

use super::engine::Falcon1024Engine;
use super::types::{Falcon1024PublicKey, Falcon1024SecretKey, Falcon1024Signature};
use crate::sig::falcon::errors::FalconErrors;
use crate::sig::traits::{SignatureEngine, SignatureScheme};
#[derive(Debug, Clone, Copy, Default)]
pub struct Falcon1024;

impl SignatureEngine for Falcon1024 {
    type PublicKey = Falcon1024PublicKey;
    type SecretKey = Falcon1024SecretKey;
    type Signature = Falcon1024Signature;
    type Error = FalconErrors;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        Falcon1024Engine::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        Falcon1024Engine::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Falcon1024Engine::verify(msg, sig, pk)
    }
}
impl SignatureScheme for Falcon1024 {}
