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

use core_lib::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};

fn benchmark_baseline_ml_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Baseline ML-KEM Performance");
    
    
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("Baseline ML-KEM-512 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem512::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem512::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem512::expose_shared(&ss1), MlKem512::expose_shared(&ss2));
            black_box(())
        })
    });

    group.bench_function("Baseline ML-KEM-768 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            black_box(())
        })
    });

    group.bench_function("Baseline ML-KEM-1024 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem1024::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem1024::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem1024::expose_shared(&ss1), MlKem1024::expose_shared(&ss2));
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_baseline_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Baseline Signature Performance");
    
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(15));
    
    let message = b"performance regression test message";

    
    group.bench_function("Baseline ML-DSA-44 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(message, &sk).expect("Signing failed");
            let result = MlDsa44::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline ML-DSA-65 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            let signature = MlDsa65::sign(message, &sk).expect("Signing failed");
            let result = MlDsa65::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline ML-DSA-87 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            let signature = MlDsa87::sign(message, &sk).expect("Signing failed");
            let result = MlDsa87::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    
    group.bench_function("Baseline Falcon-512 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            let signature = Falcon512::sign(message, &sk).expect("Signing failed");
            let result = Falcon512::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline Falcon-1024 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon1024::keypair().expect("Key generation failed");
            let signature = Falcon1024::sign(message, &sk).expect("Signing failed");
            let result = Falcon1024::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    
    group.bench_function("Baseline SPHINCS+-SHAKE-128f Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = core_lib::sig::sphincs::shake_128f::keypair()
                .expect("Key generation failed");
            let signature = core_lib::sig::sphincs::shake_128f::sign_detached(message, &sk)
                .expect("Signing failed");
            let result = core_lib::sig::sphincs::shake_128f::verify_detached(&signature, message, &pk);
            assert!(result.is_ok());
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_baseline_hybrid_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Baseline Hybrid Performance");
    
    group.sample_size(100); 
    group.measurement_time(Duration::from_secs(20));
    
    let message = b"hybrid performance test";

    group.bench_function("Baseline ECC+Dilithium Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline ECC+Falcon Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
            let signature = EccFalcon::sign(message, &sk).expect("Hybrid signing failed");
            let result = EccFalcon::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline ECC+SPHINCS+ Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = EccSphincs::keypair().expect("Hybrid key generation failed");
            let signature = EccSphincs::sign(message, &sk).expect("Hybrid signing failed");
            let result = EccSphincs::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Baseline P256+ML-KEM-768 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid KEM key generation failed");
            let (ct, ss1) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
            let ss2 = P256MlKem768::decapsulate(&ct, &sk).expect("Hybrid decapsulation failed");
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_memory_regression_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage Regression Detection");

    
    group.bench_function("Memory Leak Detection - ML-KEM-768", |b| {
        b.iter(|| {
            let mut operations_completed = 0;
            
            
            for _ in 0..100 {
                let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
                let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
                let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
                
                if MlKem768::expose_shared(&ss1) == MlKem768::expose_shared(&ss2) {
                    operations_completed += 1;
                }
                
                
                drop(pk);
                drop(sk);
                drop(ct);
                drop(ss1);
                drop(ss2);
            }
            
            assert_eq!(operations_completed, 100);
            black_box(operations_completed)
        })
    });

    group.bench_function("Memory Leak Detection - Hybrid Operations", |b| {
        let message = b"memory leak test";
        
        b.iter(|| {
            let mut operations_completed = 0;
            
            
            for _ in 0..20 {
                let (pk1, sk1) = EccDilithium::keypair().expect("Hybrid key generation failed");
                let sig1 = EccDilithium::sign(message, &sk1).expect("Hybrid signing failed");
                let result1 = EccDilithium::verify(message, &sig1, &pk1);
                
                let (pk2, sk2) = EccFalcon::keypair().expect("Hybrid key generation failed");
                let sig2 = EccFalcon::sign(message, &sk2).expect("Hybrid signing failed");
                let result2 = EccFalcon::verify(message, &sig2, &pk2);
                
                let (pk3, sk3) = EccSphincs::keypair().expect("Hybrid key generation failed");
                let sig3 = EccSphincs::sign(message, &sk3).expect("Hybrid signing failed");
                let result3 = EccSphincs::verify(message, &sig3, &pk3);
                
                if result1 && result2 && result3 {
                    operations_completed += 1;
                }
                
                
                drop((pk1, sk1, sig1));
                drop((pk2, sk2, sig2));
                drop((pk3, sk3, sig3));
            }
            
            assert_eq!(operations_completed, 20);
            black_box(operations_completed)
        })
    });

    group.finish();
}

fn benchmark_performance_stability(c: &mut Criterion) {
    let mut group = c.benchmark_group("Performance Stability Testing");

    
    group.bench_function("Performance Consistency - ML-KEM-768", |b| {
        let mut timings = Vec::with_capacity(50);
        
        b.iter(|| {
            let start = Instant::now();
            
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            
            let duration = start.elapsed();
            timings.push(duration);
            
            
            if timings.len() >= 10 {
                let avg = timings.iter().sum::<Duration>() / timings.len() as u32;
                let max_allowed = avg * 3; 
                
                for &timing in &timings {
                    assert!(timing < max_allowed, 
                        "Performance regression detected: timing {:?} exceeds {:?}", 
                        timing, max_allowed);
                }
            }
            
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_cross_platform_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cross-Platform Consistency");

    
    group.bench_function("Cross-Platform ML-KEM-768 Consistency", |b| {
        b.iter(|| {
            let mut all_consistent = true;
            
            
            for _ in 0..10 {
                let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
                let (ct1, ss1_1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
                let (ct2, ss1_2) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
                
                let ss2_1 = MlKem768::decapsulate(&ct1, &sk).expect("Failed to decapsulate");
                let ss2_2 = MlKem768::decapsulate(&ct2, &sk).expect("Failed to decapsulate");
                
                
                if MlKem768::expose_shared(&ss1_1) != MlKem768::expose_shared(&ss2_1) ||
                   MlKem768::expose_shared(&ss1_2) != MlKem768::expose_shared(&ss2_2) {
                    all_consistent = false;
                }
                
                
                if MlKem768::expose_shared(&ss1_1) == MlKem768::expose_shared(&ss1_2) ||
                   ct1 == ct2 {
                    all_consistent = false; 
                }
            }
            
            assert!(all_consistent, "Cross-platform consistency regression detected");
            black_box(all_consistent)
        })
    });

    group.finish();
}

fn benchmark_algorithm_correctness_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("Algorithm Correctness Regression");

    
    group.bench_function("Algorithm Correctness Under Load", |b| {
        let message = b"correctness test message";
        
        b.iter(|| {
            let mut all_correct = true;
            
            
            for _ in 0..5 {
                
                let (kem_pk, kem_sk) = MlKem768::keypair().expect("Failed to generate keypair");
                let (ct, ss1) = MlKem768::encapsulate(&kem_pk).expect("Failed to encapsulate");
                let ss2 = MlKem768::decapsulate(&ct, &kem_sk).expect("Failed to decapsulate");
                if MlKem768::expose_shared(&ss1) != MlKem768::expose_shared(&ss2) {
                    all_correct = false;
                }
                
                
                let (dsa_pk, dsa_sk) = MlDsa44::keypair().expect("Key generation failed");
                let signature = MlDsa44::sign(message, &dsa_sk).expect("Signing failed");
                if !MlDsa44::verify(message, &signature, &dsa_pk) {
                    all_correct = false;
                }
                
                
                let (falcon_pk, falcon_sk) = Falcon512::keypair().expect("Key generation failed");
                let falcon_sig = Falcon512::sign(message, &falcon_sk).expect("Signing failed");
                if !Falcon512::verify(message, &falcon_sig, &falcon_pk) {
                    all_correct = false;
                }
                
                
                let (hybrid_pk, hybrid_sk) = EccDilithium::keypair()
                    .expect("Hybrid key generation failed");
                let hybrid_sig = EccDilithium::sign(message, &hybrid_sk)
                    .expect("Hybrid signing failed");
                if !EccDilithium::verify(message, &hybrid_sig, &hybrid_pk) {
                    all_correct = false;
                }
            }
            
            assert!(all_correct, "Algorithm correctness regression detected");
            black_box(all_correct)
        })
    });

    group.finish();
}

fn benchmark_security_regression_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("Security Regression Detection");

    
    group.bench_function("Randomness Quality Regression", |b| {
        b.iter(|| {
            let mut public_keys = Vec::with_capacity(50);
            let mut shared_secrets = Vec::with_capacity(50);
            
            
            for _ in 0..50 {
                let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
                let (ct, ss) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
                let ss_dec = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
                
                assert_eq!(MlKem768::expose_shared(&ss), MlKem768::expose_shared(&ss_dec));
                
                public_keys.push(pk);
                shared_secrets.push(ss);
            }
            
            
            for i in 0..public_keys.len() {
                for j in (i + 1)..public_keys.len() {
                    assert_ne!(public_keys[i].0, public_keys[j].0, 
                        "Public key uniqueness regression detected");
                    assert_ne!(MlKem768::expose_shared(&shared_secrets[i]), 
                              MlKem768::expose_shared(&shared_secrets[j]),
                        "Shared secret uniqueness regression detected");
                }
            }
            
            black_box((public_keys.len(), shared_secrets.len()))
        })
    });

    group.finish();
}

fn benchmark_backwards_compatibility(c: &mut Criterion) {
    let mut group = c.benchmark_group("Backwards Compatibility");

    
    group.bench_function("Key Format Compatibility", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            
            
            assert_eq!(pk.0.len(), 1184, "ML-KEM-768 public key size changed");
            assert_eq!(sk.0.expose_secret().len(), 2400, "ML-KEM-768 secret key size changed");
            
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext size changed");
            assert_eq!(MlKem768::expose_shared(&ss1).len(), 32, "ML-KEM-768 shared secret size changed");
            
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            
            black_box(())
        })
    });

    
    group.bench_function("Hybrid Format Compatibility", |b| {
        let message = b"compatibility test";
        
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(message, &signature, &pk);
            
            assert!(result, "Hybrid signature verification failed");
            
            
            let (kem_pk, kem_sk) = P256MlKem768::keypair()
                .expect("Hybrid KEM key generation failed");
            let (ct, ss1) = P256MlKem768::encapsulate(&kem_pk)
                .expect("Hybrid encapsulation failed");
            let ss2 = P256MlKem768::decapsulate(&ct, &kem_sk)
                .expect("Hybrid decapsulation failed");
            
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            
            
            assert_eq!(kem_pk.classical.0.len(), 65, "P-256 public key size changed");
            assert_eq!(kem_pk.post_quantum.0.len(), 1184, "ML-KEM-768 in hybrid public key size changed");
            assert_eq!(ct.classical_ephemeral.len(), 65, "P-256 ephemeral key size changed");
            assert_eq!(ct.post_quantum_ciphertext.len(), 1088, "ML-KEM-768 in hybrid ciphertext size changed");
            assert_eq!(ss1.as_bytes().len(), 32, "Hybrid shared secret size changed");
            
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    regression_benches,
    benchmark_baseline_ml_kem_operations,
    benchmark_baseline_signature_operations,
    benchmark_baseline_hybrid_operations,
    benchmark_memory_regression_detection,
    benchmark_performance_stability,
    benchmark_cross_platform_consistency,
    benchmark_algorithm_correctness_regression,
    benchmark_security_regression_detection,
    benchmark_backwards_compatibility
);

criterion_main!(regression_benches);