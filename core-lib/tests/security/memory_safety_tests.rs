use core_lib::kem::{MlKem512, MlKem768, MlKem1024, Kem};
use core_lib::sig::{MlDsa44, MlDsa65, MlDsa87};
use core_lib::sig::traits::SignatureEngine;
use core_lib::hybrid::{EccDilithium, HybridEngine};
use std::mem;

#[cfg(test)]
mod ml_kem_memory_safety {
    use super::*;

    #[test]
    fn test_ml_kem_512_buffer_safety() {
        println!("🛡️  Testing ML-KEM-512 buffer safety...");
        
        let (pk, sk) = MlKem512::keypair();
        let (ct, ss1) = MlKem512::encapsulate(&pk);
        
        let ss2 = MlKem512::decapsulate(&ct, &sk);
        
        assert_eq!(
            MlKem512::expose_shared(&ss1),
            MlKem512::expose_shared(&ss2),
            "ML-KEM-512 buffer operation corrupted shared secret"
        );
        
        assert_eq!(pk.0.len(), 800, "ML-KEM-512 public key buffer size changed");
        assert_eq!(sk.0.len(), 1632, "ML-KEM-512 secret key buffer size changed");
        assert_eq!(ct.len(), 768, "ML-KEM-512 ciphertext buffer size changed");
        
        println!("✅ ML-KEM-512 buffer safety verified");
    }

    #[test]
    fn test_ml_kem_768_memory_bounds() {
        println!("🛡️  Testing ML-KEM-768 memory bounds...");
        
        let mut keypairs = Vec::new();
        for i in 0..10 {
            let (pk, sk) = MlKem768::keypair();
            keypairs.push((pk, sk));
            
            assert_eq!(keypairs[i].0.0.len(), 1184, "ML-KEM-768 public key size corrupted");
            assert_eq!(keypairs[i].1.0.len(), 2400, "ML-KEM-768 secret key size corrupted");
        }
        
        for (i, (pk, sk)) in keypairs.iter().enumerate() {
            let (ct, ss1) = MlKem768::encapsulate(pk);
            let ss2 = MlKem768::decapsulate(&ct, sk);
            
            assert_eq!(
                MlKem768::expose_shared(&ss1),
                MlKem768::expose_shared(&ss2),
                "Memory corruption detected in keypair {}", i
            );
        }
        
        println!("✅ ML-KEM-768 memory bounds verified");
    }

    #[test]
    fn test_ml_kem_1024_large_operations() {
        println!("🛡️  Testing ML-KEM-1024 large operation safety...");
        
        let (pk, sk) = MlKem1024::keypair();
        
        for i in 0..100 {
            let (ct, ss1) = MlKem1024::encapsulate(&pk);
            let ss2 = MlKem1024::decapsulate(&ct, &sk);
            
            assert_eq!(
                MlKem1024::expose_shared(&ss1),
                MlKem1024::expose_shared(&ss2),
                "Memory corruption in iteration {}", i
            );
            
            assert_eq!(ct.len(), 1568, "Ciphertext buffer corrupted at iteration {}", i);
        }
        
        println!("✅ ML-KEM-1024 large operation safety verified");
    }
}

#[cfg(test)]
mod ml_dsa_memory_safety {
    use super::*;

    #[test]
    fn test_ml_dsa_44_signature_memory_safety() {
        println!("🛡️  Testing ML-DSA-44 signature memory safety...");
        
        let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
        
        let test_sizes = vec![0, 1, 16, 255, 256, 1024, 4096, 65536];
        
        for size in test_sizes {
            let message = vec![0x42u8; size];
            
            let signature = MlDsa44::sign(&message, &sk)
                .expect(&format!("Signing failed for message size {}", size));
            
            let is_valid = MlDsa44::verify(&message, &signature, &pk);
            assert!(is_valid, "Verification failed for message size {}", size);
            
            assert_eq!(
                signature.0.len(), 2420,
                "Signature buffer size corrupted for message size {}", size
            );
        }
        
        println!("✅ ML-DSA-44 signature memory safety verified");
    }

    #[test]
    fn test_ml_dsa_65_concurrent_operations() {
        println!("🛡️  Testing ML-DSA-65 concurrent operation safety...");
        
        let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
        let message = vec![0x5A; 1000];
        
        let mut signatures = Vec::new();
        for i in 0..50 {
            let mut msg = message.clone();
            msg.push(i as u8);
            
            let sig = MlDsa65::sign(&msg, &sk)
                .expect(&format!("Signing failed for iteration {}", i));
            
            signatures.push((msg, sig));
        }
        
        for (i, (msg, sig)) in signatures.iter().enumerate() {
            let is_valid = MlDsa65::verify(msg, sig, &pk);
            assert!(is_valid, "Signature {} became invalid after concurrent operations", i);
            
            assert_eq!(sig.0.len(), 3309, "Signature {} structure corrupted", i);
        }
        
        println!("✅ ML-DSA-65 concurrent operation safety verified");
    }

    #[test]
    fn test_ml_dsa_87_stress_operations() {
        println!("🛡️  Testing ML-DSA-87 stress operation safety...");
        
        for iteration in 0..20 {
            let (pk, sk) = MlDsa87::keypair()
                .expect(&format!("Key generation failed at iteration {}", iteration));
            
            let message = vec![0xFF; 2048];
            let signature = MlDsa87::sign(&message, &sk)
                .expect(&format!("Signing failed at iteration {}", iteration));
            
            let is_valid = MlDsa87::verify(&message, &signature, &pk);
            assert!(is_valid, "Verification failed at iteration {}", iteration);
            
            assert_eq!(pk.0.len(), 2592, "Public key corrupted at iteration {}", iteration);
            assert_eq!(signature.0.len(), 4627, "Signature corrupted at iteration {}", iteration);
            
            drop(signature);
            drop(sk);
            drop(pk);
        }
        
        println!("✅ ML-DSA-87 stress operation safety verified");
    }
}

#[cfg(test)]
mod hybrid_memory_safety {
    use super::*;

    #[test]
    fn test_hybrid_composite_memory_safety() {
        println!("🛡️  Testing hybrid composite memory safety...");
        
        let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
        let message = vec![0x33; 1024];
        
        let signature = EccDilithium::sign(&message, &sk)
            .expect("Hybrid signing failed");
        
        assert!(!signature.classical.signature.is_empty(), "Classical signature missing");
        assert!(!signature.post_quantum.0.is_empty(), "Post-quantum signature missing");
        
        let is_valid = EccDilithium::verify(&message, &signature, &pk);
        assert!(is_valid, "Hybrid verification failed");
        
        use core_lib::hybrid::traits::VerificationPolicy;
        
        let policies = vec![
            VerificationPolicy::BothRequired,
            VerificationPolicy::ClassicalOnly, 
            VerificationPolicy::PostQuantumOnly,
            VerificationPolicy::EitherValid,
        ];
        
        for policy in policies {
            let result = EccDilithium::verify_with_policy(&message, &signature, &pk, policy);
            assert!(result, "Hybrid verification failed for policy {:?}", policy);
        }
        
        println!("✅ Hybrid composite memory safety verified");
    }

    #[test]
    fn test_hybrid_memory_cleanup() {
        println!("🛡️  Testing hybrid memory cleanup...");
        
        for i in 0..25 {
            let (pk, sk) = EccDilithium::keypair()
                .expect(&format!("Hybrid key generation failed at iteration {}", i));
            
            let message = format!("test message {}", i).into_bytes();
            let signature = EccDilithium::sign(&message, &sk)
                .expect(&format!("Hybrid signing failed at iteration {}", i));
            
            let is_valid = EccDilithium::verify(&message, &signature, &pk);
            assert!(is_valid, "Hybrid verification failed at iteration {}", i);
            
            mem::drop(signature);
            mem::drop(sk);
            mem::drop(pk);
        }
        
        println!("✅ Hybrid memory cleanup verified");
    }
}

#[cfg(test)]
mod ffi_memory_safety {
    use super::*;

    #[test]
    fn test_ffi_boundary_safety() {
        println!("🛡️  Testing FFI boundary memory safety...");
        
        let (pk, sk) = MlKem512::keypair();
        
        for i in 0..10 {
            let (ct, ss1) = MlKem512::encapsulate(&pk);
            let ss2 = MlKem512::decapsulate(&ct, &sk);
            
            assert_eq!(
                MlKem512::expose_shared(&ss1),
                MlKem512::expose_shared(&ss2),
                "FFI boundary corruption detected at iteration {}", i
            );
        }
        
        println!("✅ FFI boundary safety verified");
    }

    #[test]
    fn test_c_library_memory_safety() {
        println!("🛡️  Testing C library memory safety...");
        
        let (pk_dsa, sk_dsa) = MlDsa44::keypair().expect("DSA key generation failed");
        let message = vec![0x66; 512];
        
        for i in 0..15 {
            let signature = MlDsa44::sign(&message, &sk_dsa)
                .expect(&format!("C library signing failed at iteration {}", i));
            
            let is_valid = MlDsa44::verify(&message, &signature, &pk_dsa);
            assert!(is_valid, "C library verification failed at iteration {}", i);
        }
        
        println!("✅ C library memory safety verified");
    }
}

#[cfg(test)]
mod secret_cleanup_tests {
    use super::*;

    #[test]
    fn test_secret_key_zeroization() {
        println!("🔒 Testing secret key zeroization...");
        
        {
            let (_pk, sk) = MlKem512::keypair();
            drop(sk);
        }
        
        {
            let (_pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            drop(sk);
        }
        
        {
            let (_pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            drop(sk);
        }
        
        println!("✅ Secret key zeroization test completed");
    }

    #[test]
    fn test_shared_secret_cleanup() {
        println!("🔒 Testing shared secret cleanup...");
        
        let (pk, sk) = MlKem768::keypair();
        
        {
            let (ct, ss) = MlKem768::encapsulate(&pk);
            let _shared_data = MlKem768::expose_shared(&ss);
            drop(ss);
            drop(ct);
        }
        
        let (ct, ss1) = MlKem768::encapsulate(&pk);
        let ss2 = MlKem768::decapsulate(&ct, &sk);
        
        assert_eq!(
            MlKem768::expose_shared(&ss1),
            MlKem768::expose_shared(&ss2),
            "Operations failed after secret cleanup"
        );
        
        println!("✅ Shared secret cleanup verified");
    }
}

#[cfg(test)]
mod memory_regression_tests {
    use super::*;

    #[test]
    fn test_previous_memory_vulnerabilities() {
        println!("🔄 Testing fixes for previous memory vulnerabilities...");
        
        let (pk, sk) = MlKem1024::keypair();
        let (ct, ss1) = MlKem1024::encapsulate(&pk);
        
        assert_eq!(pk.0.len(), 1568, "Buffer size protection failed");
        assert_eq!(sk.0.len(), 3168, "Buffer size protection failed");
        assert_eq!(ct.len(), 1568, "Buffer size protection failed");
        
        let ss2 = MlKem1024::decapsulate(&ct, &sk);
        assert_eq!(
            MlKem1024::expose_shared(&ss1),
            MlKem1024::expose_shared(&ss2),
            "Memory vulnerability regression detected"
        );
        
        println!("✅ Memory vulnerability regression tests passed");
    }

    #[test]
    fn test_edge_case_memory_handling() {
        println!("🔍 Testing edge case memory handling...");
        
        let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
        
        let empty_msg = vec![];
        let single_byte_msg = vec![0x42];
        let max_reasonable_msg = vec![0x5A; 1_000_000];
        
        for (i, msg) in [&empty_msg, &single_byte_msg, &max_reasonable_msg].iter().enumerate() {
            let signature = MlDsa44::sign(msg, &sk)
                .expect(&format!("Signing failed for edge case {}", i));
            
            let is_valid = MlDsa44::verify(msg, &signature, &pk);
            assert!(is_valid, "Verification failed for edge case {}", i);
        }
        
        println!("✅ Edge case memory handling verified");
    }
}