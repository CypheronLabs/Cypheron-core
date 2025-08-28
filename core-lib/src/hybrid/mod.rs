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

pub mod composite;
pub mod ecdsa;
pub mod kem;
pub mod schemes;
pub mod traits;

pub use composite::{CompositeKeypair, CompositeSignature};
pub use kem::{P256MlKem768, HybridCiphertext, HybridSharedSecret};
pub use schemes::{EccDilithium, EccFalcon, EccSphincs};
pub use traits::{HybridEngine, HybridKemEngine, HybridScheme};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HybridVariant {
    EccMlDsa44,
    EccMlDsa65,
    EccMlDsa87,
    EccFalcon512,
    EccFalcon1024,
    EccSlhDsa,

    #[deprecated(since = "0.2.0", note = "Use EccMlDsa44 instead for NIST FIPS 204 compliance")]
    EccDilithium2,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa65 instead for NIST FIPS 204 compliance")]
    EccDilithium3,
    #[deprecated(since = "0.2.0", note = "Use EccMlDsa87 instead for NIST FIPS 204 compliance")]
    EccDilithium5,
    #[deprecated(since = "0.2.0", note = "Use EccSlhDsa instead for NIST FIPS 205 compliance")]
    EccSphincs,
}
