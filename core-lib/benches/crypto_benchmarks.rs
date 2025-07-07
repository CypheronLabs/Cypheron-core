/*!
 * Comprehensive Cryptographic Performance Benchmarks
 * 
 * This module provides detailed performance benchmarks for all cryptographic
 * operations to detect performance regressions and optimize implementations.
 */

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use core_lib::kem::{MlKem512, MlKem768, MlKem1024, Kem};
use core_lib::sig::{MlDsa44, MlDsa65, MlDsa87};
use core_lib::sig::traits::SignatureEngine;
use core_lib::hybrid::{EccDilithium, HybridEngine};

/// ML-KEM Performance Benchmarks
fn benchmark_ml_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Operations");
    
    // ML-KEM-512 Benchmarks
    group.bench_function("ML-KEM-512 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair();
            black_box((pk, sk))
        })
    });
    
    let (pk_512, sk_512) = MlKem512::keypair();
    group.bench_function("ML-KEM-512 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem512::encapsulate(black_box(&pk_512));
            black_box((ct, ss))
        })
    });
    
    let (ct_512, _ss_512) = MlKem512::encapsulate(&pk_512);
    group.bench_function("ML-KEM-512 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem512::decapsulate(black_box(&ct_512), black_box(&sk_512));
            black_box(ss)
        })
    });
    
    // ML-KEM-768 Benchmarks
    group.bench_function("ML-KEM-768 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair();
            black_box((pk, sk))
        })
    });
    
    let (pk_768, sk_768) = MlKem768::keypair();
    group.bench_function("ML-KEM-768 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem768::encapsulate(black_box(&pk_768));
            black_box((ct, ss))
        })
    });
    
    let (ct_768, _ss_768) = MlKem768::encapsulate(&pk_768);
    group.bench_function("ML-KEM-768 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem768::decapsulate(black_box(&ct_768), black_box(&sk_768));
            black_box(ss)
        })
    });
    
    // ML-KEM-1024 Benchmarks
    group.bench_function("ML-KEM-1024 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair();
            black_box((pk, sk))
        })
    });
    
    let (pk_1024, sk_1024) = MlKem1024::keypair();
    group.bench_function("ML-KEM-1024 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem1024::encapsulate(black_box(&pk_1024));
            black_box((ct, ss))
        })
    });
    
    let (ct_1024, _ss_1024) = MlKem1024::encapsulate(&pk_1024);
    group.bench_function("ML-KEM-1024 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem1024::decapsulate(black_box(&ct_1024), black_box(&sk_1024));
            black_box(ss)
        })
    });
    
    group.finish();
}

/// ML-DSA Performance Benchmarks
fn benchmark_ml_dsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Operations");
    
    let test_message = vec![0x42u8; 1024]; // 1KB test message
    
    // ML-DSA-44 Benchmarks
    group.bench_function("ML-DSA-44 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });
    
    let (pk_44, sk_44) = MlDsa44::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-44 Signing", |b| {
        b.iter(|| {
            let signature = MlDsa44::sign(black_box(&test_message), black_box(&sk_44))
                .expect("Signing failed");
            black_box(signature)
        })
    });
    
    let signature_44 = MlDsa44::sign(&test_message, &sk_44).expect("Signing failed");
    group.bench_function("ML-DSA-44 Verification", |b| {
        b.iter(|| {
            let result = MlDsa44::verify(
                black_box(&test_message), 
                black_box(&signature_44), 
                black_box(&pk_44)
            );
            black_box(result)
        })
    });
    
    // ML-DSA-65 Benchmarks
    group.bench_function("ML-DSA-65 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });
    
    let (pk_65, sk_65) = MlDsa65::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-65 Signing", |b| {
        b.iter(|| {
            let signature = MlDsa65::sign(black_box(&test_message), black_box(&sk_65))
                .expect("Signing failed");
            black_box(signature)
        })
    });
    
    let signature_65 = MlDsa65::sign(&test_message, &sk_65).expect("Signing failed");
    group.bench_function("ML-DSA-65 Verification", |b| {
        b.iter(|| {
            let result = MlDsa65::verify(
                black_box(&test_message), 
                black_box(&signature_65), 
                black_box(&pk_65)
            );
            black_box(result)
        })
    });
    
    // ML-DSA-87 Benchmarks
    group.bench_function("ML-DSA-87 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });
    
    let (pk_87, sk_87) = MlDsa87::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-87 Signing", |b| {
        b.iter(|| {
            let signature = MlDsa87::sign(black_box(&test_message), black_box(&sk_87))
                .expect("Signing failed");
            black_box(signature)
        })
    });
    
    let signature_87 = MlDsa87::sign(&test_message, &sk_87).expect("Signing failed");
    group.bench_function("ML-DSA-87 Verification", |b| {
        b.iter(|| {
            let result = MlDsa87::verify(
                black_box(&test_message), 
                black_box(&signature_87), 
                black_box(&pk_87)
            );
            black_box(result)
        })
    });
    
    group.finish();
}

/// Hybrid Cryptographic Scheme Benchmarks
fn benchmark_hybrid_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Operations");
    
    let test_message = vec![0x5Au8; 512]; // 512 byte test message
    
    group.bench_function("Hybrid ECC+Dilithium Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            black_box((pk, sk))
        })
    });
    
    let (pk_hybrid, sk_hybrid) = EccDilithium::keypair().expect("Hybrid key generation failed");
    group.bench_function("Hybrid ECC+Dilithium Signing", |b| {
        b.iter(|| {
            let signature = EccDilithium::sign(black_box(&test_message), black_box(&sk_hybrid))
                .expect("Hybrid signing failed");
            black_box(signature)
        })
    });
    
    let signature_hybrid = EccDilithium::sign(&test_message, &sk_hybrid)
        .expect("Hybrid signing failed");
    
    group.bench_function("Hybrid ECC+Dilithium Verification", |b| {
        b.iter(|| {
            let result = EccDilithium::verify(
                black_box(&test_message), 
                black_box(&signature_hybrid), 
                black_box(&pk_hybrid)
            );
            black_box(result)
        })
    });
    
    // Test different verification policies
    use core_lib::hybrid::traits::VerificationPolicy;
    
    group.bench_function("Hybrid Verification - BothRequired", |b| {
        b.iter(|| {
            let result = EccDilithium::verify_with_policy(
                black_box(&test_message), 
                black_box(&signature_hybrid), 
                black_box(&pk_hybrid),
                VerificationPolicy::BothRequired
            );
            black_box(result)
        })
    });
    
    group.bench_function("Hybrid Verification - ClassicalOnly", |b| {
        b.iter(|| {
            let result = EccDilithium::verify_with_policy(
                black_box(&test_message), 
                black_box(&signature_hybrid), 
                black_box(&pk_hybrid),
                VerificationPolicy::ClassicalOnly
            );
            black_box(result)
        })
    });
    
    group.bench_function("Hybrid Verification - PostQuantumOnly", |b| {
        b.iter(|| {
            let result = EccDilithium::verify_with_policy(
                black_box(&test_message), 
                black_box(&signature_hybrid), 
                black_box(&pk_hybrid),
                VerificationPolicy::PostQuantumOnly
            );
            black_box(result)
        })
    });
    
    group.finish();
}

/// Message Size Throughput Benchmarks
fn benchmark_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Message Size Throughput");
    
    let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
    
    // Test different message sizes to analyze throughput
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let message = vec![0x7Fu8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-44 Signing", size), 
            size, 
            |b, _size| {
                b.iter(|| {
                    let signature = MlDsa44::sign(black_box(&message), black_box(&sk))
                        .expect("Signing failed");
                    black_box(signature)
                })
            }
        );
        
        let signature = MlDsa44::sign(&message, &sk).expect("Signing failed");
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-44 Verification", size), 
            size, 
            |b, _size| {
                b.iter(|| {
                    let result = MlDsa44::verify(
                        black_box(&message), 
                        black_box(&signature), 
                        black_box(&pk)
                    );
                    black_box(result)
                })
            }
        );
    }
    
    group.finish();
}

/// Security Parameter Comparison Benchmarks
fn benchmark_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("Security Level Comparison");
    
    let test_message = vec![0x99u8; 1024];
    
    // Compare performance across different security levels
    
    // KEM Security Levels
    group.bench_function("ML-KEM-512 (Security Level 1)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair();
            let (ct, _ss1) = MlKem512::encapsulate(&pk);
            let _ss2 = MlKem512::decapsulate(&ct, &sk);
            black_box(())
        })
    });
    
    group.bench_function("ML-KEM-768 (Security Level 3)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair();
            let (ct, _ss1) = MlKem768::encapsulate(&pk);
            let _ss2 = MlKem768::decapsulate(&ct, &sk);
            black_box(())
        })
    });
    
    group.bench_function("ML-KEM-1024 (Security Level 5)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair();
            let (ct, _ss1) = MlKem1024::encapsulate(&pk);
            let _ss2 = MlKem1024::decapsulate(&ct, &sk);
            black_box(())
        })
    });
    
    // Signature Security Levels
    group.bench_function("ML-DSA-44 (Security Level 2)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa44::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });
    
    group.bench_function("ML-DSA-65 (Security Level 3)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            let signature = MlDsa65::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa65::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });
    
    group.bench_function("ML-DSA-87 (Security Level 5)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            let signature = MlDsa87::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa87::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });
    
    group.finish();
}

/// Regression Detection Benchmarks
fn benchmark_regression_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("Regression Detection");
    
    // Baseline performance tests that should be consistent
    group.bench_function("Baseline ML-KEM-512 Full Operation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair();
            let (ct, ss1) = MlKem512::encapsulate(&pk);
            let ss2 = MlKem512::decapsulate(&ct, &sk);
            assert_eq!(
                MlKem512::expose_shared(&ss1),
                MlKem512::expose_shared(&ss2)
            );
            black_box(())
        })
    });
    
    group.bench_function("Baseline ML-DSA-44 Full Operation", |b| {
        let message = b"performance regression test message";
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(message, &sk).expect("Signing failed");
            let result = MlDsa44::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });
    
    group.bench_function("Baseline Hybrid Full Operation", |b| {
        let message = b"hybrid performance test";
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_ml_kem_operations,
    benchmark_ml_dsa_operations,
    benchmark_hybrid_operations,
    benchmark_message_sizes,
    benchmark_security_levels,
    benchmark_regression_detection
);

criterion_main!(benches);