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

//! Cypheron Core Library
//!
//! A comprehensive post-quantum cryptography library providing NIST-standardized
//! algorithms and hybrid classical+post-quantum schemes.
//!
//! # Quick Start
//!
//! ```rust
//! use core_lib::prelude::*;
//!
//! // Key Encapsulation (recommended: ML-KEM-768)
//! let (pk, sk) = MlKem768::keypair()?;
//! let (ciphertext, shared_secret_1) = MlKem768::encapsulate(&pk)?;
//! let shared_secret_2 = MlKem768::decapsulate(&ciphertext, &sk)?;
//!
//! // Digital Signatures (recommended: ML-DSA-44)
//! let (pk, sk) = MlDsa44::keypair()?;
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa44::sign(message, &sk)?;
//! let is_valid = MlDsa44::verify(message, &signature, &pk);
//!
//! // Hybrid Cryptography (classical + post-quantum)
//! let (pk, sk) = EccDilithium::keypair()?;
//! let signature = EccDilithium::sign(message, &sk)?;
//! let is_valid = EccDilithium::verify(message, &signature, &pk);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod hybrid;
pub mod kem;
pub mod platform;
pub mod security;
pub mod sig;

// Platform utilities
pub use platform::{get_platform_info, secure_random_bytes, secure_zero, PlatformInfo};

// Core traits
pub use hybrid::traits::{HybridEngine, HybridKemEngine, VerificationPolicy};
pub use kem::{Kem, KemVariant};
pub use sig::traits::{SignatureEngine, SignatureScheme};

// Key Encapsulation Mechanisms (NIST FIPS 203)
pub use kem::{MlKem512, MlKem768, MlKem1024};

// Digital Signature Algorithms
pub use sig::{
    // NIST FIPS 204 (ML-DSA)
    MlDsa44, MlDsa65, MlDsa87,
    // NIST Round 3 Finalists
    Falcon512, Falcon1024,
};

// Hybrid Schemes (Classical + Post-Quantum)
pub use hybrid::{
    // Hybrid Signatures
    EccDilithium, EccFalcon, EccSphincs,
    // Hybrid KEM
    P256MlKem768,
    // Hybrid Types
    HybridCiphertext, HybridSharedSecret,
    CompositeKeypair, CompositeSignature,
};

// SPHINCS+ variants (available through explicit imports)
pub mod sphincs {
    pub use crate::sig::sphincs::shake_128f;
    pub use crate::sig::sphincs::sha2_256s;
    pub use crate::sig::sphincs::haraka_192f;
}

// Legacy Kyber aliases (deprecated)
pub mod kyber {
    #[deprecated(since = "0.2.0", note = "Use MlKem512 instead for NIST FIPS 203 compliance")]
    pub use crate::kem::MlKem512 as Kyber512;
    #[deprecated(since = "0.2.0", note = "Use MlKem768 instead for NIST FIPS 203 compliance")]
    pub use crate::kem::MlKem768 as Kyber768;
    #[deprecated(since = "0.2.0", note = "Use MlKem1024 instead for NIST FIPS 203 compliance")]
    pub use crate::kem::MlKem1024 as Kyber1024;
}

// Prelude module for convenient imports
pub mod prelude {
    //! Common imports for most use cases
    //!
    //! ```rust
    //! use core_lib::prelude::*;
    //! ```

    // Essential traits
    pub use crate::{SignatureEngine, Kem, HybridEngine, HybridKemEngine, VerificationPolicy};

    // Recommended algorithms
    pub use crate::{MlKem768, MlDsa44, EccDilithium, P256MlKem768};

    // All KEM variants
    pub use crate::{MlKem512, MlKem1024};

    // All signature algorithms
    pub use crate::{MlDsa65, MlDsa87, Falcon512, Falcon1024};

    // All hybrid schemes
    pub use crate::{EccFalcon, EccSphincs};

    // Platform utilities
    pub use crate::{secure_random_bytes, secure_zero};

    // Common types
    pub use crate::{HybridCiphertext, HybridSharedSecret, CompositeKeypair, CompositeSignature};
}

// Security level mappings for easy algorithm selection
pub mod security_levels {
    //! Algorithm recommendations by security level
    //!
    //! Security levels correspond to NIST categories:
    //! - Level 1: Equivalent to AES-128 (128-bit security)
    //! - Level 2: Equivalent to SHA-256 (128-bit security)
    //! - Level 3: Equivalent to AES-192 (192-bit security)
    //! - Level 5: Equivalent to AES-256 (256-bit security)

    /// Security Level 1 algorithms (128-bit equivalent)
    pub mod level1 {
        pub use crate::{MlKem512, Falcon512};
        pub use crate::sphincs::shake_128f;
        pub use crate::sphincs::sha2_256s;
    }

    /// Security Level 2 algorithms (128-bit equivalent)
    pub mod level2 {
        pub use crate::MlDsa44;
    }

    /// Security Level 3 algorithms (192-bit equivalent)
    pub mod level3 {
        pub use crate::{MlKem768, MlDsa65};
        pub use crate::sphincs::haraka_192f;
    }

    /// Security Level 5 algorithms (256-bit equivalent)
    pub mod level5 {
        pub use crate::{MlKem1024, MlDsa87, Falcon1024};
    }

    /// Recommended combinations for each security level
    pub mod recommended {
        /// High performance, good security (Level 2-3)
        pub mod balanced {
            pub use crate::{MlKem768, MlDsa44, EccDilithium};
        }

        /// Maximum security (Level 5)
        pub mod high_security {
            pub use crate::{MlKem1024, MlDsa87};
        }

        /// Real-time applications (lowest latency)
        pub mod low_latency {
            pub use crate::{MlKem512, MlDsa44};
        }
    }
}