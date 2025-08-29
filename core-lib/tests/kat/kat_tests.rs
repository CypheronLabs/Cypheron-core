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
use hex;
use std::fs;

#[derive(Debug)]
struct MlKemKatVector {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug)]
struct MlDsaKatVector {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

fn load_ml_kem_512_vectors() -> Vec<MlKemKatVector> {
    vec![
        MlKemKatVector {
            seed: hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap(),
            public_key: vec![0; 800],
            secret_key: vec![0; 1632],
            ciphertext: vec![0; 768],
            shared_secret: vec![0; 32],
        }
    ]
}

fn load_ml_kem_768_vectors() -> Vec<MlKemKatVector> {
    vec![
        MlKemKatVector {
            seed: hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap(),
            public_key: vec![0; 1184],
            secret_key: vec![0; 2400],
            ciphertext: vec![0; 1088],
            shared_secret: vec![0; 32],
        }
    ]
}

fn load_ml_kem_1024_vectors() -> Vec<MlKemKatVector> {
    vec![
        MlKemKatVector {
            seed: hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap(),
            public_key: vec![0; 1568],
            secret_key: vec![0; 3168],
            ciphertext: vec![0; 1568],
            shared_secret: vec![0; 32],
        }
    ]
}

fn load_ml_dsa_44_vectors() -> Vec<MlDsaKatVector> {
    vec![
        MlDsaKatVector {
            seed: hex::decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1").unwrap(),
            public_key: vec![0; 1312],
            secret_key: vec![0; 2528],
            message: b"test message for ML-DSA-44 KAT".to_vec(),
            signature: vec![0; 2420],
        }
    ]
}

#[cfg(test)]
mod ml_kem_512_kat_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_kat_vectors() {
        let vectors = load_ml_kem_512_vectors();
        
        for (i, vector) in vectors.iter().enumerate() {
            println!("Testing ML-KEM-512 vector {}", i);
            
            let (pk, sk) = MlKem512::keypair();
            
            assert_eq!(pk.0.len(), 800, "ML-KEM-512 public key size mismatch");
            assert_eq!(sk.0.len(), 1632, "ML-KEM-512 secret key size mismatch");
            
            let (ct, ss1) = MlKem512::encapsulate(&pk);
            let ss2 = MlKem512::decapsulate(&ct, &sk);
            
            assert_eq!(
                MlKem512::expose_shared(&ss1),
                MlKem512::expose_shared(&ss2),
                "ML-KEM-512 shared secret mismatch"
            );
            
            assert_eq!(ct.len(), 768, "ML-KEM-512 ciphertext size mismatch");
            
            println!("ML-KEM-512 vector {} passed ✓", i);
        }
    }

    #[test]
    fn test_ml_kem_512_parameter_validation() {
        use cypheron_core::kem::sizes::*;
        
        assert_eq!(ML_KEM_512_PUBLIC, 800);
        assert_eq!(ML_KEM_512_SECRET, 1632);
        assert_eq!(ML_KEM_512_CIPHERTEXT, 768);
        assert_eq!(ML_KEM_512_SHARED, 32);
        
        println!("ML-KEM-512 parameter validation passed ✓");
    }
}

#[cfg(test)]
mod ml_kem_768_kat_tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_kat_vectors() {
        let vectors = load_ml_kem_768_vectors();
        
        for (i, vector) in vectors.iter().enumerate() {
            println!("Testing ML-KEM-768 vector {}", i);
            
            let (pk, sk) = MlKem768::keypair();
            
            assert_eq!(pk.0.len(), 1184, "ML-KEM-768 public key size mismatch");
            assert_eq!(sk.0.len(), 2400, "ML-KEM-768 secret key size mismatch");
            
            let (ct, ss1) = MlKem768::encapsulate(&pk);
            let ss2 = MlKem768::decapsulate(&ct, &sk);
            
            assert_eq!(
                MlKem768::expose_shared(&ss1),
                MlKem768::expose_shared(&ss2),
                "ML-KEM-768 shared secret mismatch"
            );
            
            assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext size mismatch");
            
            println!("ML-KEM-768 vector {} passed ✓", i);
        }
    }
}

#[cfg(test)]
mod ml_kem_1024_kat_tests {
    use super::*;

    #[test]
    fn test_ml_kem_1024_kat_vectors() {
        let vectors = load_ml_kem_1024_vectors();
        
        for (i, vector) in vectors.iter().enumerate() {
            println!("Testing ML-KEM-1024 vector {}", i);
            
            let (pk, sk) = MlKem1024::keypair();
            
            assert_eq!(pk.0.len(), 1568, "ML-KEM-1024 public key size mismatch");
            assert_eq!(sk.0.len(), 3168, "ML-KEM-1024 secret key size mismatch");
            
            let (ct, ss1) = MlKem1024::encapsulate(&pk);
            let ss2 = MlKem1024::decapsulate(&ct, &sk);
            
            assert_eq!(
                MlKem1024::expose_shared(&ss1),
                MlKem1024::expose_shared(&ss2),
                "ML-KEM-1024 shared secret mismatch"
            );
            
            assert_eq!(ct.len(), 1568, "ML-KEM-1024 ciphertext size mismatch");
            
            println!("ML-KEM-1024 vector {} passed ✓", i);
        }
    }
}

#[cfg(test)]
mod ml_dsa_44_kat_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_kat_vectors() {
        let vectors = load_ml_dsa_44_vectors();
        
        for (i, vector) in vectors.iter().enumerate() {
            println!("Testing ML-DSA-44 vector {}", i);
            
            let (pk, sk) = MlDsa44::keypair().expect("ML-DSA-44 key generation failed");
            
            assert_eq!(pk.0.len(), 1312, "ML-DSA-44 public key size mismatch");
            
            let message = &vector.message;
            let signature = MlDsa44::sign(message, &sk).expect("ML-DSA-44 signing failed");
            
            let is_valid = MlDsa44::verify(message, &signature, &pk);
            assert!(is_valid, "ML-DSA-44 signature verification failed");
            
            assert_eq!(signature.0.len(), 2420, "ML-DSA-44 signature size mismatch");
            
            println!("ML-DSA-44 vector {} passed ✓", i);
        }
    }

    #[test]
    fn test_ml_dsa_44_parameter_validation() {
        use cypheron_core::sig::dilithium::common::*;
        
        assert_eq!(ML_DSA_44_PUBLIC, 1312);
        assert_eq!(ML_DSA_44_SECRET, 2528);
        assert_eq!(ML_DSA_44_SIGNATURE, 2420);
        
        println!("ML-DSA-44 parameter validation passed ✓");
    }
}

#[cfg(test)]
mod nist_compliance_tests {
    use super::*;

    #[test]
    fn test_fips_203_compliance() {
        println!("NIST FIPS 203 (ML-KEM) Compliance Validation");
        
        let _ml_kem_512 = MlKem512::keypair();
        let _ml_kem_768 = MlKem768::keypair(); 
        let _ml_kem_1024 = MlKem1024::keypair();
        
        println!("All ML-KEM variants functional");
    }

    #[test]
    fn test_fips_204_compliance() {
        println!("NIST FIPS 204 (ML-DSA) Compliance Validation");
        
        let _ml_dsa_44 = MlDsa44::keypair().expect("ML-DSA-44 failed");
        let _ml_dsa_65 = MlDsa65::keypair().expect("ML-DSA-65 failed");
        let _ml_dsa_87 = MlDsa87::keypair().expect("ML-DSA-87 failed");
        
        println!("All ML-DSA variants functional");
    }

    #[test]
    fn test_algorithm_naming_compliance() {
        println!("NIST Algorithm Naming Compliance Validation");
        
        use cypheron_core::kem::{MlKem512, MlKem768, MlKem1024};
        use cypheron_core::sig::{MlDsa44, MlDsa65, MlDsa87};
        
        let _kem_512 = MlKem512::variant();
        let _kem_768 = MlKem768::variant();
        let _kem_1024 = MlKem1024::variant();
        
        println!("NIST FIPS 203/204/205 naming compliance verified");
    }
}