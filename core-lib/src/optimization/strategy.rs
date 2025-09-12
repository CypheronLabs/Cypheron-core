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

use super::{AlgorithmVariant, CpuCapabilities, OptimizationLevel};

pub trait OptimizationStrategy {
    fn select_variant(
        &self,
        level: OptimizationLevel,
        capabilities: &CpuCapabilities,
    ) -> AlgorithmVariant;

    fn should_use_optimized(&self, capabilities: &CpuCapabilities) -> bool;
}

pub struct ConservativeStrategy;

impl OptimizationStrategy for ConservativeStrategy {
    fn select_variant(
        &self,
        level: OptimizationLevel,
        capabilities: &CpuCapabilities,
    ) -> AlgorithmVariant {
        match level {
            OptimizationLevel::Reference => AlgorithmVariant::Reference,
            OptimizationLevel::Optimized => {
                if capabilities.has_avx2() {
                    AlgorithmVariant::Avx2
                } else if capabilities.has_aes_ni() {
                    AlgorithmVariant::AesNi
                } else {
                    AlgorithmVariant::Reference
                }
            }
            OptimizationLevel::Aggressive => {
                if capabilities.has_avx2() && capabilities.has_aes_ni() {
                    AlgorithmVariant::Avx2AesNi
                } else if capabilities.has_avx2() {
                    AlgorithmVariant::Avx2
                } else if capabilities.has_aes_ni() {
                    AlgorithmVariant::AesNi
                } else {
                    AlgorithmVariant::Reference
                }
            }
        }
    }

    fn should_use_optimized(&self, capabilities: &CpuCapabilities) -> bool {
        capabilities.is_x86_optimized() || capabilities.is_arm_optimized()
    }
}

pub struct PerformanceStrategy;

impl OptimizationStrategy for PerformanceStrategy {
    fn select_variant(
        &self,
        level: OptimizationLevel,
        capabilities: &CpuCapabilities,
    ) -> AlgorithmVariant {
        if capabilities.has_avx2() && capabilities.has_aes_ni() {
            AlgorithmVariant::Avx2AesNi
        } else if capabilities.has_avx2() {
            AlgorithmVariant::Avx2
        } else if capabilities.has_aes_ni() {
            AlgorithmVariant::AesNi
        } else if capabilities.has_neon() {
            AlgorithmVariant::Neon
        } else {
            match level {
                OptimizationLevel::Reference => AlgorithmVariant::Reference,
                _ => AlgorithmVariant::Reference,
            }
        }
    }

    fn should_use_optimized(&self, _capabilities: &CpuCapabilities) -> bool {
        true
    }
}
