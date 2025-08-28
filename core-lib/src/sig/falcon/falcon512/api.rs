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

use super::engine::Falcon512Engine;
use super::types::{Falcon512PublicKey, Falcon512SecretKey, Falcon512Signature};
use crate::sig::falcon::errors::FalconErrors;
use crate::sig::traits::{SignatureEngine, SignatureScheme};
#[derive(Debug, Clone, Copy, Default)]
pub struct Falcon512;

impl SignatureEngine for Falcon512 {
    type PublicKey = Falcon512PublicKey;
    type SecretKey = Falcon512SecretKey;
    type Signature = Falcon512Signature;
    type Error = FalconErrors;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        Falcon512Engine::keypair()
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        Falcon512Engine::sign(msg, sk)
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Falcon512Engine::verify(msg, sig, pk)
    }
}
impl SignatureScheme for Falcon512 {}
