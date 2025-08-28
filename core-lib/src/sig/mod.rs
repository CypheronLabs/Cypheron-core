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

pub mod dilithium;
pub mod falcon;
pub mod sphincs;
pub mod traits;

pub use dilithium::dilithium2::Dilithium2 as MlDsa44;
pub use dilithium::dilithium3::Dilithium3 as MlDsa65;
pub use dilithium::dilithium5::Dilithium5 as MlDsa87;

#[deprecated(since = "0.2.0", note = "Use MlDsa44 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium2::Dilithium2;
#[deprecated(since = "0.2.0", note = "Use MlDsa65 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium3::Dilithium3;
#[deprecated(since = "0.2.0", note = "Use MlDsa87 instead for NIST FIPS 204 compliance")]
pub use dilithium::dilithium5::Dilithium5;

pub use falcon::falcon1024::Falcon1024;
pub use falcon::falcon512::Falcon512;

pub use traits::SignatureScheme;
