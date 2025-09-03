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

pub mod hybrid;
pub mod kat;
pub mod kem;
pub mod platform;
pub mod security;
pub mod sig;

pub use platform::{get_platform_info, secure_random_bytes, secure_zero, PlatformInfo};
pub use security::benchmark_utils::{BenchmarkResult, bench_crypto_op, bench_validate};

pub use hybrid::traits::{HybridEngine, HybridKemEngine, VerificationPolicy};
pub use kem::{Kem, KemVariant};
pub use sig::traits::{SignatureEngine, SignatureScheme};

pub use kem::{MlKem1024, MlKem512, MlKem768};

pub use sig::{Falcon1024, Falcon512, MlDsa44, MlDsa65, MlDsa87};

pub use hybrid::{
    CompositeKeypair, CompositeSignature, EccDilithium, EccFalcon, EccSphincs, HybridCiphertext,
    HybridSharedSecret, P256MlKem768,
};

pub mod sphincs {
    pub use crate::sig::sphincs::haraka_192f;
    pub use crate::sig::sphincs::sha2_256s;
    pub use crate::sig::sphincs::shake_128f;
}

pub mod kyber {
    #[deprecated(
        since = "0.2.0",
        note = "Use MlKem1024 instead for NIST FIPS 203 compliance"
    )]
    pub use crate::kem::MlKem1024 as Kyber1024;
    #[deprecated(
        since = "0.2.0",
        note = "Use MlKem512 instead for NIST FIPS 203 compliance"
    )]
    pub use crate::kem::MlKem512 as Kyber512;
    #[deprecated(
        since = "0.2.0",
        note = "Use MlKem768 instead for NIST FIPS 203 compliance"
    )]
    pub use crate::kem::MlKem768 as Kyber768;
}

pub mod prelude {

    pub use crate::{HybridEngine, HybridKemEngine, Kem, SignatureEngine, VerificationPolicy};

    pub use crate::{EccDilithium, MlDsa44, MlKem768, P256MlKem768};

    pub use crate::{MlKem1024, MlKem512};

    pub use crate::{Falcon1024, Falcon512, MlDsa65, MlDsa87};

    pub use crate::{EccFalcon, EccSphincs};

    pub use crate::{secure_random_bytes, secure_zero};

    pub use crate::{CompositeKeypair, CompositeSignature, HybridCiphertext, HybridSharedSecret};
}

pub mod security_levels {

    pub mod level1 {
        pub use crate::sphincs::sha2_256s;
        pub use crate::sphincs::shake_128f;
        pub use crate::{Falcon512, MlKem512};
    }

    pub mod level2 {
        pub use crate::MlDsa44;
    }

    pub mod level3 {
        pub use crate::sphincs::haraka_192f;
        pub use crate::{MlDsa65, MlKem768};
    }

    pub mod level5 {
        pub use crate::{Falcon1024, MlDsa87, MlKem1024};
    }

    pub mod recommended {

        pub mod balanced {
            pub use crate::{EccDilithium, MlDsa44, MlKem768};
        }

        pub mod high_security {
            pub use crate::{MlDsa87, MlKem1024};
        }

        pub mod low_latency {
            pub use crate::{MlDsa44, MlKem512};
        }
    }
}
