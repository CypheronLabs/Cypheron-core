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

use super::engine::Dilithium3Engine;
use super::types::{PublicKey, SecretKey, Signature};
use crate::sig::dilithium::errors::DilithiumError;
use crate::sig::traits::{SignatureEngine, SignatureScheme};

#[derive(Clone, Debug, Copy, Default)]
pub struct Dilithium3;

impl SignatureEngine for Dilithium3 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Error = DilithiumError;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        Ok(Dilithium3Engine::keypair()?)
    }
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        Dilithium3Engine::sign(msg, sk)
    }
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        Dilithium3Engine::verify(msg, sig, pk)
    }
}

impl SignatureScheme for Dilithium3 {}
