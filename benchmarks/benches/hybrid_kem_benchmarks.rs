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
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn benchmark_hybrid_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Hybrid KEM Operations");

    group.bench_function("P256+ML-KEM-768 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
            black_box((pk, sk))
        })
    });

    let (pk, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

    group.bench_function("P256+ML-KEM-768 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) =
                P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");
            black_box((ct, ss))
        })
    });

    let (ct, _ss1) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
    group.bench_function("P256+ML-KEM-768 Decapsulation", |b| {
        b.iter(|| {
            let ss = P256MlKem768::decapsulate(black_box(&ct), black_box(&sk))
                .expect("Hybrid decapsulation failed");
            black_box(ss)
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_complete_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Complete Workflow");

    group.bench_function("P256+ML-KEM-768 Complete Round-trip", |b| {
        b.iter(|| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
            let (ct, ss1) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
            let ss2 = P256MlKem768::decapsulate(&ct, &sk).expect("Hybrid decapsulation failed");

            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Throughput Analysis");
    group.throughput(Throughput::Elements(1));

    let (pk, _sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

    group.bench_function("P256+ML-KEM-768 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) =
                P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");
            black_box((ct, ss))
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Batch Operations");

    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("P256+ML-KEM-768 Batch Keygen", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut keypairs = Vec::with_capacity(size);
                    for _ in 0..size {
                        let keypair =
                            P256MlKem768::keypair().expect("Hybrid keypair generation failed");
                        keypairs.push(keypair);
                    }
                    black_box(keypairs)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("P256+ML-KEM-768 Batch Encapsulation", batch_size),
            batch_size,
            |b, &size| {
                let keypairs: Vec<_> = (0..size)
                    .map(|_| P256MlKem768::keypair().expect("Hybrid keypair generation failed"))
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (pk, _) in &keypairs {
                        let result =
                            P256MlKem768::encapsulate(pk).expect("Hybrid encapsulation failed");
                        results.push(result);
                    }
                    black_box(results)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("P256+ML-KEM-768 Batch Decapsulation", batch_size),
            batch_size,
            |b, &size| {
                let test_data: Vec<_> = (0..size)
                    .map(|_| {
                        let (pk, sk) =
                            P256MlKem768::keypair().expect("Hybrid keypair generation failed");
                        let (ct, _) =
                            P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
                        (ct, sk)
                    })
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (ct, sk) in &test_data {
                        let result =
                            P256MlKem768::decapsulate(ct, sk).expect("Hybrid decapsulation failed");
                        results.push(result);
                    }
                    black_box(results)
                })
            },
        );
    }

    group.finish();
}

fn benchmark_hybrid_kem_key_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Key Reuse Scenarios");

    let (pk, _sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

    group.bench_function("P256+ML-KEM-768 Multiple Encapsulations Same Key", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(10);
            for _ in 0..10 {
                let result =
                    P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");
                results.push(result);
            }
            black_box(results)
        })
    });

    let (pk_reuse, sk_reuse) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
    let ciphertexts: Vec<_> = (0..10)
        .map(|_| {
            P256MlKem768::encapsulate(&pk_reuse)
                .expect("Hybrid encapsulation failed")
                .0
        })
        .collect();

    group.bench_function("P256+ML-KEM-768 Multiple Decapsulations Same Key", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(10);
            for ct in &ciphertexts {
                let result = P256MlKem768::decapsulate(black_box(ct), black_box(&sk_reuse))
                    .expect("Hybrid decapsulation failed");
                results.push(result);
            }
            black_box(results)
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_security_properties(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Security Properties");

    group.bench_function("P256+ML-KEM-768 Different Keys Different Secrets", |b| {
        b.iter(|| {
            let (pk1, _) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
            let (pk2, _) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

            let (_, ss1) = P256MlKem768::encapsulate(&pk1).expect("Hybrid encapsulation failed");
            let (_, ss2) = P256MlKem768::encapsulate(&pk2).expect("Hybrid encapsulation failed");

            assert_ne!(ss1.as_bytes(), ss2.as_bytes());
            black_box(())
        })
    });

    group.bench_function(
        "P256+ML-KEM-768 Multiple Encapsulations Different Ciphertexts",
        |b| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

            b.iter(|| {
                let (ct1, ss1) =
                    P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");
                let (ct2, ss2) =
                    P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");

                assert_ne!(ct1.classical_ephemeral, ct2.classical_ephemeral);
                assert_ne!(ct1.post_quantum_ciphertext, ct2.post_quantum_ciphertext);

                let decrypted1 =
                    P256MlKem768::decapsulate(&ct1, &sk).expect("Hybrid decapsulation failed");
                let decrypted2 =
                    P256MlKem768::decapsulate(&ct2, &sk).expect("Hybrid decapsulation failed");

                assert_eq!(ss1.as_bytes(), decrypted1.as_bytes());
                assert_eq!(ss2.as_bytes(), decrypted2.as_bytes());

                assert_ne!(ss1.as_bytes(), ss2.as_bytes());
                black_box(())
            })
        },
    );

    group.finish();
}

fn benchmark_hybrid_kem_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Key Size Validation");

    group.bench_function("P256+ML-KEM-768 Key Size Verification", |b| {
        b.iter(|| {
            let (pk, _sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
            let (ct, _ss) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");

            assert_eq!(pk.classical.0.len(), 65);

            assert_eq!(pk.post_quantum.0.len(), 1184);

            assert_eq!(ct.classical_ephemeral.len(), 65);

            assert_eq!(ct.post_quantum_ciphertext.len(), 1088);

            black_box(())
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Consistency Tests");

    group.bench_function("P256+ML-KEM-768 Multi-round Consistency", |b| {
        let (pk, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

        b.iter(|| {
            for _ in 0..5 {
                let (ct, ss1) =
                    P256MlKem768::encapsulate(black_box(&pk)).expect("Hybrid encapsulation failed");
                let ss2 = P256MlKem768::decapsulate(black_box(&ct), black_box(&sk))
                    .expect("Hybrid decapsulation failed");

                assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            }
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Error Handling Performance");

    let (_, sk) = P256MlKem768::keypair().expect("Hybrid keypair generation failed");

    group.bench_function("P256+ML-KEM-768 Invalid Ciphertext Handling", |b| {
        let invalid_ct = HybridCiphertext {
            classical_ephemeral: vec![0u8; 32],
            post_quantum_ciphertext: vec![0u8; 500],
        };

        b.iter(|| {
            let result = P256MlKem768::decapsulate(black_box(&invalid_ct), black_box(&sk));
            assert!(result.is_err());
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_hybrid_kem_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("P256+ML-KEM-768 Memory Usage Patterns");

    group.bench_function("P256+ML-KEM-768 Memory Allocation Keygen", |b| {
        b.iter(|| {
            let mut keypairs = Vec::with_capacity(100);
            for _ in 0..100 {
                let keypair = P256MlKem768::keypair().expect("Hybrid keypair generation failed");
                keypairs.push(keypair);
            }

            drop(keypairs);
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    hybrid_kem_benches,
    benchmark_hybrid_kem_operations,
    benchmark_hybrid_kem_complete_workflow,
    benchmark_hybrid_kem_throughput,
    benchmark_hybrid_kem_batch_operations,
    benchmark_hybrid_kem_key_reuse,
    benchmark_hybrid_kem_security_properties,
    benchmark_hybrid_kem_key_sizes,
    benchmark_hybrid_kem_consistency,
    benchmark_hybrid_kem_error_handling,
    benchmark_hybrid_kem_memory_usage
);

criterion_main!(hybrid_kem_benches);
