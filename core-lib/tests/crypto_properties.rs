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

use cypheron_core::kem::{MlKem512, MlKem768, MlKem1024, Kem};
use cypheron_core::sig::{MlDsa44, MlDsa65, MlDsa87};
use cypheron_core::sig::traits::SignatureEngine;
use cypheron_core::hybrid::{EccDilithium, HybridEngine};
use proptest::prelude::*;

fn arbitrary_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=1024)
}

fn arbitrary_crypto_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=65536)
}

mod ml_kem_properties {
    use super::*;

    proptest! {
        #[test]
        fn ml_kem_512_roundtrip_property(seed in any::<u64>()) {
            let (pk, sk) = MlKem512::keypair();
            
            let (ct, ss1) = MlKem512::encapsulate(&pk);
            
            let ss2 = MlKem512::decapsulate(&ct, &sk);
            
            prop_assert_eq!(
                MlKem512::expose_shared(&ss1), 
                MlKem512::expose_shared(&ss2),
                "ML-KEM-512 roundtrip failed: shared secrets don't match"
            );
            
            prop_assert_eq!(
                MlKem512::expose_shared(&ss1).len(), 
                32,
                "ML-KEM-512 shared secret length invalid"
            );
        }

        #[test]
        fn ml_kem_768_roundtrip_property(seed in any::<u64>()) {
            let (pk, sk) = MlKem768::keypair();
            let (ct, ss1) = MlKem768::encapsulate(&pk);
            let ss2 = MlKem768::decapsulate(&ct, &sk);
            
            prop_assert_eq!(
                MlKem768::expose_shared(&ss1), 
                MlKem768::expose_shared(&ss2),
                "ML-KEM-768 roundtrip failed"
            );
            
            prop_assert_eq!(
                MlKem768::expose_shared(&ss1).len(), 
                32,
                "ML-KEM-768 shared secret length invalid"
            );
        }

        #[test]
        fn ml_kem_1024_roundtrip_property(seed in any::<u64>()) {
            let (pk, sk) = MlKem1024::keypair();
            let (ct, ss1) = MlKem1024::encapsulate(&pk);
            let ss2 = MlKem1024::decapsulate(&ct, &sk);
            
            prop_assert_eq!(
                MlKem1024::expose_shared(&ss1), 
                MlKem1024::expose_shared(&ss2),
                "ML-KEM-1024 roundtrip failed"
            );
            
            prop_assert_eq!(
                MlKem1024::expose_shared(&ss1).len(), 
                32,
                "ML-KEM-1024 shared secret length invalid"
            );
        }

        #[test]
        fn ml_kem_512_key_independence(seed1 in any::<u64>(), seed2 in any::<u64>()) {
            prop_assume!(seed1 != seed2);
            
            let (pk1, _sk1) = MlKem512::keypair();
            let (pk2, _sk2) = MlKem512::keypair();
            
            prop_assert_ne!(
                pk1.0, pk2.0,
                "ML-KEM-512 generated identical public keys (highly improbable)"
            );
            
            let (ct1, _ss1) = MlKem512::encapsulate(&pk1);
            let (ct2, _ss2) = MlKem512::encapsulate(&pk2);
            
            prop_assert_ne!(
                ct1, ct2,
                "ML-KEM-512 generated identical ciphertexts (highly improbable)"
            );
        }
    }
}

mod ml_dsa_properties {
    use super::*;

    proptest! {
        #[test]
        fn ml_dsa_44_roundtrip_property(msg in arbitrary_crypto_message()) {
            let (pk, sk) = MlDsa44::keypair().unwrap();
            
            let signature = MlDsa44::sign(&msg, &sk).unwrap();
            
            let is_valid = MlDsa44::verify(&msg, &signature, &pk);
            prop_assert!(is_valid, "ML-DSA-44 valid signature failed verification");
            
            prop_assert_eq!(
                signature.0.len(), 
                2420,
                "ML-DSA-44 signature has incorrect size"
            );
        }

        #[test]
        fn ml_dsa_65_roundtrip_property(msg in arbitrary_crypto_message()) {
            let (pk, sk) = MlDsa65::keypair().unwrap();
            let signature = MlDsa65::sign(&msg, &sk).unwrap();
            let is_valid = MlDsa65::verify(&msg, &signature, &pk);
            
            prop_assert!(is_valid, "ML-DSA-65 valid signature failed verification");
            prop_assert_eq!(signature.0.len(), 3309, "ML-DSA-65 signature size incorrect");
        }

        #[test]
        fn ml_dsa_87_roundtrip_property(msg in arbitrary_crypto_message()) {
            let (pk, sk) = MlDsa87::keypair().unwrap();
            let signature = MlDsa87::sign(&msg, &sk).unwrap();
            let is_valid = MlDsa87::verify(&msg, &signature, &pk);
            
            prop_assert!(is_valid, "ML-DSA-87 valid signature failed verification");
            prop_assert_eq!(signature.0.len(), 4627, "ML-DSA-87 signature size incorrect");
        }

        #[test]
        fn ml_dsa_44_signature_uniqueness(
            msg1 in arbitrary_crypto_message(), 
            msg2 in arbitrary_crypto_message()
        ) {
            prop_assume!(msg1 != msg2);
            
            let (pk, sk) = MlDsa44::keypair().unwrap();
            
            let sig1 = MlDsa44::sign(&msg1, &sk).unwrap();
            let sig2 = MlDsa44::sign(&msg2, &sk).unwrap();
            
            prop_assert_ne!(
                sig1.0, sig2.0,
                "ML-DSA-44 produced identical signatures for different messages"
            );
            
            let cross_verify = MlDsa44::verify(&msg2, &sig1, &pk);
            prop_assert!(!cross_verify, "ML-DSA-44 signature verified for wrong message");
        }

        #[test]
        fn ml_dsa_44_empty_message_handling(_seed in any::<u64>()) {
            let (pk, sk) = MlDsa44::keypair().unwrap();
            let empty_msg = vec![];
            
            let signature = MlDsa44::sign(&empty_msg, &sk).unwrap();
            let is_valid = MlDsa44::verify(&empty_msg, &signature, &pk);
            
            prop_assert!(is_valid, "ML-DSA-44 failed to handle empty message");
        }
    }
}

mod hybrid_properties {
    use super::*;

    proptest! {
        #[test]
        fn hybrid_ecc_dilithium_roundtrip_property(msg in arbitrary_crypto_message()) {
            let (pk, sk) = EccDilithium::keypair().unwrap();
            
            let signature = EccDilithium::sign(&msg, &sk).unwrap();
            
            let is_valid = EccDilithium::verify(&msg, &signature, &pk);
            prop_assert!(is_valid, "Hybrid ECC+Dilithium signature failed verification");
            
            prop_assert!(!signature.classical.signature.is_empty(), "Classical signature component missing");
            prop_assert!(!signature.post_quantum.0.is_empty(), "Post-quantum signature component missing");
        }

        #[test]
        fn hybrid_signature_resilience(msg in arbitrary_crypto_message()) {
            let (pk, sk) = EccDilithium::keypair().unwrap();
            let signature = EccDilithium::sign(&msg, &sk).unwrap();
            
            use cypheron_core::hybrid::traits::VerificationPolicy;
            
            let both_required = EccDilithium::verify_with_policy(&msg, &signature, &pk, VerificationPolicy::BothRequired);
            prop_assert!(both_required, "Hybrid signature with BothRequired policy failed");
            
            let classical_only = EccDilithium::verify_with_policy(&msg, &signature, &pk, VerificationPolicy::ClassicalOnly);
            prop_assert!(classical_only, "Hybrid signature with ClassicalOnly policy failed");
            
            let pq_only = EccDilithium::verify_with_policy(&msg, &signature, &pk, VerificationPolicy::PostQuantumOnly);
            prop_assert!(pq_only, "Hybrid signature with PostQuantumOnly policy failed");
        }
    }
}

mod crypto_invariants {
    use super::*;

    proptest! {
        #[test]
        fn key_generation_size_invariants(_seed in any::<u64>()) {
            let (pk512, sk512) = MlKem512::keypair();
            prop_assert_eq!(pk512.0.len(), 800, "ML-KEM-512 public key size");
            prop_assert_eq!(sk512.0.len(), 1632, "ML-KEM-512 secret key size");
            
            let (pk768, sk768) = MlKem768::keypair();  
            prop_assert_eq!(pk768.0.len(), 1184, "ML-KEM-768 public key size");
            prop_assert_eq!(sk768.0.len(), 2400, "ML-KEM-768 secret key size");
            
            let (pk1024, sk1024) = MlKem1024::keypair();
            prop_assert_eq!(pk1024.0.len(), 1568, "ML-KEM-1024 public key size");
            prop_assert_eq!(sk1024.0.len(), 3168, "ML-KEM-1024 secret key size");
            
            let (pk_dsa44, _sk_dsa44) = MlDsa44::keypair().unwrap();
            prop_assert_eq!(pk_dsa44.0.len(), 1312, "ML-DSA-44 public key size");
            
            let (pk_dsa65, _sk_dsa65) = MlDsa65::keypair().unwrap();
            prop_assert_eq!(pk_dsa65.0.len(), 1952, "ML-DSA-65 public key size");
            
            let (pk_dsa87, _sk_dsa87) = MlDsa87::keypair().unwrap();
            prop_assert_eq!(pk_dsa87.0.len(), 2592, "ML-DSA-87 public key size");
        }

        #[test]
        fn deterministic_operations(msg in arbitrary_crypto_message()) {
            let (pk, sk) = MlKem512::keypair();
            
            let (ct, _ss) = MlKem512::encapsulate(&pk);
            let ss1 = MlKem512::decapsulate(&ct, &sk);
            let ss2 = MlKem512::decapsulate(&ct, &sk);
            
            prop_assert_eq!(
                MlKem512::expose_shared(&ss1),
                MlKem512::expose_shared(&ss2),
                "ML-KEM decapsulation is not deterministic"
            );
        }

        #[test]
        fn invalid_input_handling(_seed in any::<u64>()) {
            let (pk, sk) = MlKem512::keypair();
            
            let invalid_ct = vec![0u8; 100];
            
        }
    }
}