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

use std::error::Error as StdError;
use std::fmt::Debug;
use zeroize::Zeroize;

pub trait HybridEngine {
    type ClassicalPublicKey: Clone + Debug + Send + Sync + 'static;
    type ClassicalSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type ClassicalSignature: Clone + Debug + Send + Sync + 'static;

    type PqPublicKey: Clone + Debug + Send + Sync + 'static;
    type PqSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type PqSignature: Clone + Debug + Send + Sync + 'static;

    type CompositePublicKey: Clone + Debug + Send + Sync + 'static;
    type CompositeSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type CompositeSignature: Clone + Debug + Send + Sync + 'static;

    type Error: StdError + Debug + Send + Sync + 'static;

    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error>;

    fn sign(
        msg: &[u8],
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::CompositeSignature, Self::Error>;

    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool;

    fn verify_with_policy(
        msg: &[u8],
        sig: &Self::CompositeSignature,
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy,
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationPolicy {
    BothRequired,
    EitherValid,
    ClassicalOnly,
    PostQuantumOnly,
}

pub trait HybridScheme: HybridEngine {}

pub trait HybridKemEngine {
    type ClassicalPublicKey: Clone + Debug + Send + Sync + 'static;
    type ClassicalSecretKey: Zeroize + Debug + Send + Sync + 'static;

    type PqPublicKey: Clone + Debug + Send + Sync + 'static;
    type PqSecretKey: Zeroize + Debug + Send + Sync + 'static;

    type CompositePublicKey: Clone + Debug + Send + Sync + 'static;
    type CompositeSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type HybridCiphertext: Clone + Debug + Send + Sync + 'static;
    type SharedSecret: Zeroize + Debug + Send + Sync + 'static;

    type Error: StdError + Debug + Send + Sync + 'static;

    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error>;

    fn encapsulate(
        pk: &Self::CompositePublicKey,
    ) -> Result<(Self::HybridCiphertext, Self::SharedSecret), Self::Error>;

    fn decapsulate(
        ct: &Self::HybridCiphertext,
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::SharedSecret, Self::Error>;
}
