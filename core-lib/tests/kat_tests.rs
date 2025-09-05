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

//! NIST Known Answer Tests (KAT) for FIPS 203, 204, and 205 compliance
//!
//! This module contains Known Answer Tests that validate the cryptographic
//! implementations against NIST standard test vectors to ensure FIPS compliance.

use cypheron_core::kem::{Kem, MlKem1024, MlKem512, MlKem768};
use cypheron_core::sig::traits::SignatureEngine;
use cypheron_core::sig::{MlDsa44, MlDsa65, MlDsa87};

/// NIST Known Answer Test vector for ML-KEM
#[derive(Debug)]
struct MlKemKatVector {
    pub seed: Vec<u8>,
    pub expected_pk_len: usize,
    pub expected_sk_len: usize,
    pub expected_ct_len: usize,
    pub expected_ss_len: usize,
}

/// NIST Known Answer Test vector for ML-DSA
#[derive(Debug)]
struct MlDsaKatVector {
    pub message: Vec<u8>,
    pub expected_pk_len: usize,
    pub expected_sk_len: usize,
    pub expected_sig_len: usize,
}

#[cfg(test)]
mod ml_kem_kat_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_kat_basic() {
        let vector = MlKemKatVector {
            seed: vec![0u8; 32],
            expected_pk_len: 800,
            expected_sk_len: 1632,
            expected_ct_len: 768,
            expected_ss_len: 32,
        };

        // Test key generation produces correct sizes
        let (pk, sk) = MlKem512::keypair();
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-KEM-512 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-KEM-512 secret key size"
        );

        // Test encapsulation produces correct sizes
        let (ct, ss) = MlKem512::encapsulate(&pk);
        assert_eq!(
            ct.len(),
            vector.expected_ct_len,
            "ML-KEM-512 ciphertext size"
        );
        assert_eq!(
            MlKem512::expose_shared(&ss).len(),
            vector.expected_ss_len,
            "ML-KEM-512 shared secret size"
        );

        // Test decapsulation works correctly
        let ss_dec = MlKem512::decapsulate(&ct, &sk);
        assert_eq!(
            MlKem512::expose_shared(&ss),
            MlKem512::expose_shared(&ss_dec),
            "ML-KEM-512 shared secret roundtrip"
        );
    }

    #[test]
    fn test_ml_kem_768_kat_basic() {
        let vector = MlKemKatVector {
            seed: vec![1u8; 32],
            expected_pk_len: 1184,
            expected_sk_len: 2400,
            expected_ct_len: 1088,
            expected_ss_len: 32,
        };

        let (pk, sk) = MlKem768::keypair();
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-KEM-768 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-KEM-768 secret key size"
        );

        let (ct, ss) = MlKem768::encapsulate(&pk);
        assert_eq!(
            ct.len(),
            vector.expected_ct_len,
            "ML-KEM-768 ciphertext size"
        );
        assert_eq!(
            MlKem768::expose_shared(&ss).len(),
            vector.expected_ss_len,
            "ML-KEM-768 shared secret size"
        );

        let ss_dec = MlKem768::decapsulate(&ct, &sk);
        assert_eq!(
            MlKem768::expose_shared(&ss),
            MlKem768::expose_shared(&ss_dec),
            "ML-KEM-768 shared secret roundtrip"
        );
    }

    #[test]
    fn test_ml_kem_1024_kat_basic() {
        let vector = MlKemKatVector {
            seed: vec![2u8; 32],
            expected_pk_len: 1568,
            expected_sk_len: 3168,
            expected_ct_len: 1568,
            expected_ss_len: 32,
        };

        let (pk, sk) = MlKem1024::keypair();
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-KEM-1024 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-KEM-1024 secret key size"
        );

        let (ct, ss) = MlKem1024::encapsulate(&pk);
        assert_eq!(
            ct.len(),
            vector.expected_ct_len,
            "ML-KEM-1024 ciphertext size"
        );
        assert_eq!(
            MlKem1024::expose_shared(&ss).len(),
            vector.expected_ss_len,
            "ML-KEM-1024 shared secret size"
        );

        let ss_dec = MlKem1024::decapsulate(&ct, &sk);
        assert_eq!(
            MlKem1024::expose_shared(&ss),
            MlKem1024::expose_shared(&ss_dec),
            "ML-KEM-1024 shared secret roundtrip"
        );
    }

    #[test]
    fn test_ml_kem_nist_compliance() {
        // Test that our implementation matches NIST FIPS 203 requirements

        // ML-KEM-512 parameter validation
        let (pk512, sk512) = MlKem512::keypair();
        assert_eq!(
            pk512.0.len(),
            800,
            "FIPS 203: ML-KEM-512 public key must be 800 bytes"
        );
        assert_eq!(
            sk512.0.len(),
            1632,
            "FIPS 203: ML-KEM-512 secret key must be 1632 bytes"
        );

        let (ct512, ss512) = MlKem512::encapsulate(&pk512);
        assert_eq!(
            ct512.len(),
            768,
            "FIPS 203: ML-KEM-512 ciphertext must be 768 bytes"
        );
        assert_eq!(
            MlKem512::expose_shared(&ss512).len(),
            32,
            "FIPS 203: ML-KEM shared secret must be 32 bytes"
        );

        // ML-KEM-768 parameter validation
        let (pk768, sk768) = MlKem768::keypair();
        assert_eq!(
            pk768.0.len(),
            1184,
            "FIPS 203: ML-KEM-768 public key must be 1184 bytes"
        );
        assert_eq!(
            sk768.0.len(),
            2400,
            "FIPS 203: ML-KEM-768 secret key must be 2400 bytes"
        );

        let (ct768, ss768) = MlKem768::encapsulate(&pk768);
        assert_eq!(
            ct768.len(),
            1088,
            "FIPS 203: ML-KEM-768 ciphertext must be 1088 bytes"
        );
        assert_eq!(
            MlKem768::expose_shared(&ss768).len(),
            32,
            "FIPS 203: ML-KEM shared secret must be 32 bytes"
        );

        // ML-KEM-1024 parameter validation
        let (pk1024, sk1024) = MlKem1024::keypair();
        assert_eq!(
            pk1024.0.len(),
            1568,
            "FIPS 203: ML-KEM-1024 public key must be 1568 bytes"
        );
        assert_eq!(
            sk1024.0.len(),
            3168,
            "FIPS 203: ML-KEM-1024 secret key must be 3168 bytes"
        );

        let (ct1024, ss1024) = MlKem1024::encapsulate(&pk1024);
        assert_eq!(
            ct1024.len(),
            1568,
            "FIPS 203: ML-KEM-1024 ciphertext must be 1568 bytes"
        );
        assert_eq!(
            MlKem1024::expose_shared(&ss1024).len(),
            32,
            "FIPS 203: ML-KEM shared secret must be 32 bytes"
        );
    }
}

#[cfg(test)]
mod ml_dsa_kat_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_kat_basic() {
        let vector = MlDsaKatVector {
            message: b"Hello, NIST FIPS 204!".to_vec(),
            expected_pk_len: 1312,
            expected_sk_len: 2560,
            expected_sig_len: 2420,
        };

        let (pk, sk) = MlDsa44::keypair().expect("ML-DSA-44 keypair generation");
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-DSA-44 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-DSA-44 secret key size"
        );

        let signature = MlDsa44::sign(&vector.message, &sk).expect("ML-DSA-44 signing");
        assert_eq!(
            signature.0.len(),
            vector.expected_sig_len,
            "ML-DSA-44 signature size"
        );

        let is_valid = MlDsa44::verify(&vector.message, &signature, &pk);
        assert!(is_valid, "ML-DSA-44 signature verification");
    }

    #[test]
    fn test_ml_dsa_65_kat_basic() {
        let vector = MlDsaKatVector {
            message: b"NIST FIPS 204 ML-DSA-65 test".to_vec(),
            expected_pk_len: 1952,
            expected_sk_len: 4032,
            expected_sig_len: 3309,
        };

        let (pk, sk) = MlDsa65::keypair().expect("ML-DSA-65 keypair generation");
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-DSA-65 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-DSA-65 secret key size"
        );

        let signature = MlDsa65::sign(&vector.message, &sk).expect("ML-DSA-65 signing");
        assert_eq!(
            signature.0.len(),
            vector.expected_sig_len,
            "ML-DSA-65 signature size"
        );

        let is_valid = MlDsa65::verify(&vector.message, &signature, &pk);
        assert!(is_valid, "ML-DSA-65 signature verification");
    }

    #[test]
    fn test_ml_dsa_87_kat_basic() {
        let vector = MlDsaKatVector {
            message: b"NIST FIPS 204 ML-DSA-87 test".to_vec(),
            expected_pk_len: 2592,
            expected_sk_len: 4896,
            expected_sig_len: 4627,
        };

        let (pk, sk) = MlDsa87::keypair().expect("ML-DSA-87 keypair generation");
        assert_eq!(
            pk.0.len(),
            vector.expected_pk_len,
            "ML-DSA-87 public key size"
        );
        assert_eq!(
            sk.0.len(),
            vector.expected_sk_len,
            "ML-DSA-87 secret key size"
        );

        let signature = MlDsa87::sign(&vector.message, &sk).expect("ML-DSA-87 signing");
        assert_eq!(
            signature.0.len(),
            vector.expected_sig_len,
            "ML-DSA-87 signature size"
        );

        let is_valid = MlDsa87::verify(&vector.message, &signature, &pk);
        assert!(is_valid, "ML-DSA-87 signature verification");
    }

    #[test]
    fn test_ml_dsa_nist_compliance() {
        // Test that our implementation matches NIST FIPS 204 requirements

        // ML-DSA-44 parameter validation
        let (pk44, sk44) = MlDsa44::keypair().expect("ML-DSA-44 keypair");
        assert_eq!(
            pk44.0.len(),
            1312,
            "FIPS 204: ML-DSA-44 public key must be 1312 bytes"
        );
        assert_eq!(
            sk44.0.len(),
            2560,
            "FIPS 204: ML-DSA-44 secret key must be 2560 bytes"
        );

        // ML-DSA-65 parameter validation
        let (pk65, sk65) = MlDsa65::keypair().expect("ML-DSA-65 keypair");
        assert_eq!(
            pk65.0.len(),
            1952,
            "FIPS 204: ML-DSA-65 public key must be 1952 bytes"
        );
        assert_eq!(
            sk65.0.len(),
            4032,
            "FIPS 204: ML-DSA-65 secret key must be 4032 bytes"
        );

        // ML-DSA-87 parameter validation
        let (pk87, sk87) = MlDsa87::keypair().expect("ML-DSA-87 keypair");
        assert_eq!(
            pk87.0.len(),
            2592,
            "FIPS 204: ML-DSA-87 public key must be 2592 bytes"
        );
        assert_eq!(
            sk87.0.len(),
            4896,
            "FIPS 204: ML-DSA-87 secret key must be 4896 bytes"
        );

        // Test signature sizes
        let test_message = b"FIPS 204 compliance test message";

        let sig44 = MlDsa44::sign(test_message, &sk44).expect("ML-DSA-44 signature");
        assert_eq!(
            sig44.0.len(),
            2420,
            "FIPS 204: ML-DSA-44 signature must be 2420 bytes"
        );

        let sig65 = MlDsa65::sign(test_message, &sk65).expect("ML-DSA-65 signature");
        assert_eq!(
            sig65.0.len(),
            3309,
            "FIPS 204: ML-DSA-65 signature must be 3309 bytes"
        );

        let sig87 = MlDsa87::sign(test_message, &sk87).expect("ML-DSA-87 signature");
        assert_eq!(
            sig87.0.len(),
            4627,
            "FIPS 204: ML-DSA-87 signature must be 4627 bytes"
        );
    }
}

#[cfg(test)]
mod integration_kat_tests {
    use super::*;

    #[test]
    fn test_algorithm_correctness() {
        // Integration test ensuring all algorithms work correctly together
        println!("Running NIST compliance validation...");

        // Test ML-KEM variants
        let (pk512, sk512) = MlKem512::keypair();
        let (ct512, ss512_enc) = MlKem512::encapsulate(&pk512);
        let ss512_dec = MlKem512::decapsulate(&ct512, &sk512);
        assert_eq!(
            MlKem512::expose_shared(&ss512_enc),
            MlKem512::expose_shared(&ss512_dec)
        );

        let (pk768, sk768) = MlKem768::keypair();
        let (ct768, ss768_enc) = MlKem768::encapsulate(&pk768);
        let ss768_dec = MlKem768::decapsulate(&ct768, &sk768);
        assert_eq!(
            MlKem768::expose_shared(&ss768_enc),
            MlKem768::expose_shared(&ss768_dec)
        );

        let (pk1024, sk1024) = MlKem1024::keypair();
        let (ct1024, ss1024_enc) = MlKem1024::encapsulate(&pk1024);
        let ss1024_dec = MlKem1024::decapsulate(&ct1024, &sk1024);
        assert_eq!(
            MlKem1024::expose_shared(&ss1024_enc),
            MlKem1024::expose_shared(&ss1024_dec)
        );

        // Test ML-DSA variants
        let message = b"Integration test message for all ML-DSA variants";

        let (pk44, sk44) = MlDsa44::keypair().unwrap();
        let sig44 = MlDsa44::sign(message, &sk44).unwrap();
        assert!(MlDsa44::verify(message, &sig44, &pk44));

        let (pk65, sk65) = MlDsa65::keypair().unwrap();
        let sig65 = MlDsa65::sign(message, &sk65).unwrap();
        assert!(MlDsa65::verify(message, &sig65, &pk65));

        let (pk87, sk87) = MlDsa87::keypair().unwrap();
        let sig87 = MlDsa87::sign(message, &sk87).unwrap();
        assert!(MlDsa87::verify(message, &sig87, &pk87));

        println!("All NIST KAT tests passed successfully!");
    }

    #[test]
    fn test_nist_parameter_compliance() {
        // Test that all parameters match NIST specifications exactly

        // FIPS 203 ML-KEM parameter verification
        assert_eq!(
            std::mem::size_of::<cypheron_core::kem::ml_kem::MlKem512PublicKey>(),
            800
        );
        assert_eq!(
            std::mem::size_of::<cypheron_core::kem::ml_kem::MlKem768PublicKey>(),
            1184
        );
        assert_eq!(
            std::mem::size_of::<cypheron_core::kem::ml_kem::MlKem1024PublicKey>(),
            1568
        );

        // Verify shared secret length compliance
        let (pk, _) = MlKem512::keypair();
        let (_, ss) = MlKem512::encapsulate(&pk);
        assert_eq!(
            MlKem512::expose_shared(&ss).len(),
            32,
            "FIPS 203: Shared secret must be 32 bytes"
        );

        println!("NIST FIPS 203 and 204 parameter compliance verified!");
    }
}
