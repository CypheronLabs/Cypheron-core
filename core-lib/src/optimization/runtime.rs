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

use super::CpuFeature;
use once_cell::sync::Lazy;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct CpuCapabilities {
    features: HashSet<CpuFeature>,
}

impl CpuCapabilities {
    pub fn detect() -> Self {
        Self {
            features: detect_cpu_features(),
        }
    }

    pub fn new() -> Self {
        Self::detect()
    }

    pub fn has_feature(&self, feature: CpuFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn has_avx2(&self) -> bool {
        self.has_feature(CpuFeature::Avx2)
    }

    pub fn has_aes_ni(&self) -> bool {
        self.has_feature(CpuFeature::AesNi)
    }

    pub fn has_sse2(&self) -> bool {
        self.has_feature(CpuFeature::Sse2)
    }

    pub fn has_neon(&self) -> bool {
        self.has_feature(CpuFeature::Neon)
    }

    pub fn is_x86_optimized(&self) -> bool {
        self.has_avx2() || self.has_aes_ni()
    }

    pub fn is_arm_optimized(&self) -> bool {
        self.has_neon()
    }
}

impl Default for CpuCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL_CPU_CAPABILITIES: Lazy<CpuCapabilities> = Lazy::new(CpuCapabilities::detect);

pub fn global_cpu_capabilities() -> &'static CpuCapabilities {
    &GLOBAL_CPU_CAPABILITIES
}

fn detect_cpu_features() -> HashSet<CpuFeature> {
    let mut features = HashSet::new();

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            features.insert(CpuFeature::Avx2);
        }
        if std::arch::is_x86_feature_detected!("aes") {
            features.insert(CpuFeature::AesNi);
        }
        if std::arch::is_x86_feature_detected!("sse2") {
            features.insert(CpuFeature::Sse2);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            features.insert(CpuFeature::Neon);
        }
    }

    features
}
