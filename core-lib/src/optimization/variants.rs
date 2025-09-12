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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmVariant {
    Reference,
    Avx2,
    AesNi,
    Avx2AesNi,
    Neon,
}

impl AlgorithmVariant {
    pub fn name(&self) -> &'static str {
        match self {
            AlgorithmVariant::Reference => "reference",
            AlgorithmVariant::Avx2 => "avx2",
            AlgorithmVariant::AesNi => "aesni",
            AlgorithmVariant::Avx2AesNi => "avx2_aesni",
            AlgorithmVariant::Neon => "neon",
        }
    }

    pub fn is_optimized(&self) -> bool {
        !matches!(self, AlgorithmVariant::Reference)
    }

    pub fn requires_x86(&self) -> bool {
        matches!(
            self,
            AlgorithmVariant::Avx2 | AlgorithmVariant::AesNi | AlgorithmVariant::Avx2AesNi
        )
    }

    pub fn requires_arm(&self) -> bool {
        matches!(self, AlgorithmVariant::Neon)
    }
}
