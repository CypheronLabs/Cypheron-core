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
pub trait SignatureEngine {
    type PublicKey: Clone + Debug + Send + Sync + 'static;

    type SecretKey: Zeroize + Debug + Send + Sync + 'static;

    type Signature: Clone + Debug + Send + Sync + 'static;

    type Error: StdError + Debug + Send + Sync + 'static;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error>;
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool;
}
pub trait SignatureScheme: SignatureEngine {}
