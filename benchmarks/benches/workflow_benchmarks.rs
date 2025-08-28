use core_lib::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde::{Serialize, Deserialize};

fn benchmark_complete_kem_workflows(c: &mut Criterion) {
    let mut group = c.benchmark_group("Complete KEM Workflows");

    
    group.bench_function("ML-KEM-512 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem512::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem512::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem512::expose_shared(&ss1), MlKem512::expose_shared(&ss2));
            black_box(())
        })
    });

    
    group.bench_function("ML-KEM-768 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            black_box(())
        })
    });

    
    group.bench_function("ML-KEM-1024 Complete Workflow", |b| {
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

fn benchmark_complete_signature_workflows(c: &mut Criterion) {
    let mut group = c.benchmark_group("Complete Signature Workflows");
    let test_message = b"Benchmark test message for complete workflow evaluation";

    
    group.bench_function("ML-DSA-44 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(black_box(test_message), &sk).expect("Signing failed");
            let result = MlDsa44::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ML-DSA-65 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            let signature = MlDsa65::sign(black_box(test_message), &sk).expect("Signing failed");
            let result = MlDsa65::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ML-DSA-87 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            let signature = MlDsa87::sign(black_box(test_message), &sk).expect("Signing failed");
            let result = MlDsa87::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    
    group.bench_function("Falcon-512 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            let signature = Falcon512::sign(black_box(test_message), &sk).expect("Signing failed");
            let result = Falcon512::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Falcon-1024 Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon1024::keypair().expect("Key generation failed");
            let signature = Falcon1024::sign(black_box(test_message), &sk).expect("Signing failed");
            let result = Falcon1024::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    
    group.bench_function("SPHINCS+-SHAKE-128f Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = core_lib::sig::sphincs::shake_128f::keypair()
                .expect("Key generation failed");
            let signature = core_lib::sig::sphincs::shake_128f::sign_detached(
                black_box(test_message), &sk
            ).expect("Signing failed");
            let result = core_lib::sig::sphincs::shake_128f::verify_detached(
                &signature, black_box(test_message), &pk
            );
            assert!(result.is_ok());
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_hybrid_complete_workflows(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Complete Workflows");
    let test_message = b"Hybrid workflow test message";

    
    group.bench_function("ECC+Dilithium Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(black_box(test_message), &sk)
                .expect("Hybrid signing failed");
            let result = EccDilithium::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+Falcon Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
            let signature = EccFalcon::sign(black_box(test_message), &sk)
                .expect("Hybrid signing failed");
            let result = EccFalcon::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+SPHINCS+ Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccSphincs::keypair().expect("Hybrid key generation failed");
            let signature = EccSphincs::sign(black_box(test_message), &sk)
                .expect("Hybrid signing failed");
            let result = EccSphincs::verify(black_box(test_message), &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    
    group.bench_function("P256+ML-KEM-768 Complete Workflow", |b| {
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

fn benchmark_real_world_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("Real-World Usage Scenarios");

    
    group.bench_function("Secure Communication Setup (KEM + Signature)", |b| {
        let document = b"Important secure document that needs to be encrypted and signed";
        
        b.iter(|| {
            
            let (alice_kem_pk, alice_kem_sk) = MlKem768::keypair().expect("Failed to generate KEM keys");
            let (alice_sig_pk, alice_sig_sk) = MlDsa44::keypair().expect("Failed to generate signature keys");
            
            
            let (bob_kem_pk, bob_kem_sk) = MlKem768::keypair().expect("Failed to generate KEM keys");
            let (bob_sig_pk, _bob_sig_sk) = MlDsa44::keypair().expect("Failed to generate signature keys");
            
            
            let (ciphertext, shared_secret) = MlKem768::encapsulate(&bob_kem_pk)
                .expect("Failed to encapsulate");
            let signature = MlDsa44::sign(document, &alice_sig_sk).expect("Failed to sign");
            
            
            let decrypted_secret = MlKem768::decapsulate(&ciphertext, &bob_kem_sk)
                .expect("Failed to decapsulate");
            let is_valid = MlDsa44::verify(document, &signature, &alice_sig_pk);
            
            assert_eq!(MlKem768::expose_shared(&shared_secret), MlKem768::expose_shared(&decrypted_secret));
            assert!(is_valid);
            black_box(())
        })
    });

    
    group.bench_function("Multi-Party Key Agreement", |b| {
        b.iter(|| {
            let mut shared_secrets = Vec::new();
            
            
            let parties: Vec<_> = (0..5)
                .map(|_| MlKem768::keypair().expect("Failed to generate keypair"))
                .collect();
            
            
            for i in 0..parties.len() {
                for j in (i + 1)..parties.len() {
                    let (ct, ss) = MlKem768::encapsulate(&parties[j].0)
                        .expect("Failed to encapsulate");
                    let ss_decrypted = MlKem768::decapsulate(&ct, &parties[j].1)
                        .expect("Failed to decapsulate");
                    
                    assert_eq!(MlKem768::expose_shared(&ss), MlKem768::expose_shared(&ss_decrypted));
                    shared_secrets.push(ss);
                }
            }
            
            black_box(shared_secrets)
        })
    });

    group.finish();
}

fn benchmark_serialization_workflows(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialization Workflows");

    
    group.bench_function("ML-KEM-768 Key Serialization Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            
            
            let pk_bytes = pk.0.to_vec();
            let sk_bytes = sk.0.expose_secret().to_vec();
            
            
            let _pk_restored = core_lib::kem::ml_kem_768::MlKemPublicKey(
                pk_bytes[..pk_bytes.len()].try_into()
                    .expect("Failed to restore public key")
            );
            
            
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            black_box((pk_bytes, sk_bytes))
        })
    });

    
    group.bench_function("Hybrid Key Serialization Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            
            
            let pk_classical_bytes = pk.classical.0.to_vec();  
            let pk_pq_bytes = pk.post_quantum.0.to_vec();
            
            let test_message = b"Serialization test message";
            let signature = EccDilithium::sign(test_message, &sk)
                .expect("Hybrid signing failed");
            let result = EccDilithium::verify(test_message, &signature, &pk);
            
            assert!(result);
            black_box((pk_classical_bytes, pk_pq_bytes))
        })
    });

    group.finish();
}

fn benchmark_mixed_algorithm_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mixed Algorithm Scenarios");

    
    group.bench_function("Mixed Security Levels Workflow", |b| {
        let document = b"Multi-level security document";
        
        b.iter(|| {
            
            let (kem_pk, kem_sk) = MlKem1024::keypair().expect("Failed to generate keypair");
            
            
            let (sig_pk, sig_sk) = MlDsa44::keypair().expect("Key generation failed");
            
            
            let (temp_pk, temp_sk) = MlKem512::keypair().expect("Failed to generate keypair");
            
            
            let (main_ct, main_ss) = MlKem1024::encapsulate(&kem_pk)
                .expect("Failed to encapsulate");
            let signature = MlDsa44::sign(document, &sig_sk).expect("Signing failed");
            let (temp_ct, temp_ss) = MlKem512::encapsulate(&temp_pk)
                .expect("Failed to encapsulate");
            
            
            let main_ss_dec = MlKem1024::decapsulate(&main_ct, &kem_sk)
                .expect("Failed to decapsulate");
            let sig_valid = MlDsa44::verify(document, &signature, &sig_pk);
            let temp_ss_dec = MlKem512::decapsulate(&temp_ct, &temp_sk)
                .expect("Failed to decapsulate");
            
            assert_eq!(MlKem1024::expose_shared(&main_ss), MlKem1024::expose_shared(&main_ss_dec));
            assert!(sig_valid);
            assert_eq!(MlKem512::expose_shared(&temp_ss), MlKem512::expose_shared(&temp_ss_dec));
            
            black_box(())
        })
    });

    
    group.bench_function("Hybrid + Pure PQC Combination", |b| {
        let message = b"Combined cryptographic systems test";
        
        b.iter(|| {
            
            let (hybrid_pk, hybrid_sk) = EccDilithium::keypair()
                .expect("Hybrid key generation failed");
            
            
            let (pqc_kem_pk, pqc_kem_sk) = MlKem1024::keypair()
                .expect("Failed to generate keypair");
            
            
            let (pqc_sig_pk, pqc_sig_sk) = MlDsa87::keypair()
                .expect("Key generation failed");
            
            
            let hybrid_sig = EccDilithium::sign(message, &hybrid_sk)
                .expect("Hybrid signing failed");
            let (kem_ct, kem_ss) = MlKem1024::encapsulate(&pqc_kem_pk)
                .expect("Failed to encapsulate");
            let pqc_sig = MlDsa87::sign(message, &pqc_sig_sk)
                .expect("Signing failed");
            
            
            let hybrid_valid = EccDilithium::verify(message, &hybrid_sig, &hybrid_pk);
            let kem_ss_dec = MlKem1024::decapsulate(&kem_ct, &pqc_kem_sk)
                .expect("Failed to decapsulate");
            let pqc_sig_valid = MlDsa87::verify(message, &pqc_sig, &pqc_sig_pk);
            
            assert!(hybrid_valid);
            assert_eq!(MlKem1024::expose_shared(&kem_ss), MlKem1024::expose_shared(&kem_ss_dec));
            assert!(pqc_sig_valid);
            
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_high_throughput_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("High Throughput Scenarios");

    
    for batch_size in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("Bulk Signature Verification", batch_size),
            batch_size,
            |b, &size| {
                let message = b"Bulk verification test message";
                
                
                let test_data: Vec<_> = (0..size)
                    .map(|_| {
                        let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
                        let signature = MlDsa44::sign(message, &sk).expect("Signing failed");
                        (pk, signature)
                    })
                    .collect();
                
                b.iter(|| {
                    let mut valid_count = 0;
                    for (pk, signature) in &test_data {
                        if MlDsa44::verify(message, signature, pk) {
                            valid_count += 1;
                        }
                    }
                    assert_eq!(valid_count, size);
                    black_box(valid_count)
                })
            },
        );
    }

    
    group.bench_function("High-Frequency Key Exchange", |b| {
        b.iter(|| {
            let mut successful_exchanges = 0;
            
            
            for _ in 0..50 {
                let (pk1, sk1) = MlKem768::keypair().expect("Failed to generate keypair");
                let (pk2, sk2) = MlKem768::keypair().expect("Failed to generate keypair");
                
                let (ct1, ss1_enc) = MlKem768::encapsulate(&pk2).expect("Failed to encapsulate");
                let (ct2, ss2_enc) = MlKem768::encapsulate(&pk1).expect("Failed to encapsulate");
                
                let ss1_dec = MlKem768::decapsulate(&ct1, &sk2).expect("Failed to decapsulate");
                let ss2_dec = MlKem768::decapsulate(&ct2, &sk1).expect("Failed to decapsulate");
                
                if MlKem768::expose_shared(&ss1_enc) == MlKem768::expose_shared(&ss1_dec) &&
                   MlKem768::expose_shared(&ss2_enc) == MlKem768::expose_shared(&ss2_dec) {
                    successful_exchanges += 1;
                }
            }
            
            assert_eq!(successful_exchanges, 50);
            black_box(successful_exchanges)
        })
    });

    group.finish();
}

fn benchmark_resource_constrained_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("Resource Constrained Scenarios");

    
    group.bench_function("Minimal Memory Usage Pattern", |b| {
        let message = b"Resource constrained message";
        
        b.iter(|| {
            
            let (pk1, sk1) = MlKem512::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem512::encapsulate(&pk1).expect("Failed to encapsulate");
            let ss2 = MlKem512::decapsulate(&ct, &sk1).expect("Failed to decapsulate");
            
            
            assert_eq!(MlKem512::expose_shared(&ss1), MlKem512::expose_shared(&ss2));
            drop((pk1, sk1, ct, ss1, ss2));
            
            
            let (pk2, sk2) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(message, &sk2).expect("Signing failed");
            let result = MlDsa44::verify(message, &signature, &pk2);
            
            assert!(result);
            drop((pk2, sk2, signature));
            
            black_box(())
        })
    });

    
    group.bench_function("Time-Critical Operations", |b| {
        
        let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
        let (sig_pk, sig_sk) = MlDsa44::keypair().expect("Key generation failed");
        let message = b"Time critical message";
        
        b.iter(|| {
            
            let (ct, ss1) = MlKem512::encapsulate(black_box(&pk)).expect("Failed to encapsulate");
            let signature = MlDsa44::sign(black_box(message), black_box(&sig_sk))
                .expect("Signing failed");
            
            let ss2 = MlKem512::decapsulate(black_box(&ct), black_box(&sk))
                .expect("Failed to decapsulate");
            let valid = MlDsa44::verify(black_box(message), black_box(&signature), black_box(&sig_pk));
            
            assert_eq!(MlKem512::expose_shared(&ss1), MlKem512::expose_shared(&ss2));
            assert!(valid);
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    workflow_benches,
    benchmark_complete_kem_workflows,
    benchmark_complete_signature_workflows,
    benchmark_hybrid_complete_workflows,
    benchmark_real_world_scenarios,
    benchmark_serialization_workflows,
    benchmark_mixed_algorithm_scenarios,
    benchmark_high_throughput_scenarios,
    benchmark_resource_constrained_scenarios
);

criterion_main!(workflow_benches);