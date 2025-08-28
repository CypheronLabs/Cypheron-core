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
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn benchmark_ecc_dilithium_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECC+Dilithium Hybrid Operations");
    let test_message = vec![0x5Au8; 512];

    group.bench_function("ECC+Dilithium Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_hybrid, sk_hybrid) = EccDilithium::keypair().expect("Hybrid key generation failed");
    group.bench_function("ECC+Dilithium Signing", |b| {
        b.iter(|| {
            let signature = EccDilithium::sign(black_box(&test_message), black_box(&sk_hybrid))
                .expect("Hybrid signing failed");
            black_box(signature)
        })
    });

    let signature_hybrid =
        EccDilithium::sign(&test_message, &sk_hybrid).expect("Hybrid signing failed");

    group.bench_function("ECC+Dilithium Verification", |b| {
        b.iter(|| {
            let result = EccDilithium::verify(
                black_box(&test_message),
                black_box(&signature_hybrid),
                black_box(&pk_hybrid),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_ecc_falcon_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECC+Falcon Hybrid Operations");
    let test_message = vec![0x6Bu8; 512];

    group.bench_function("ECC+Falcon Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_hybrid, sk_hybrid) = EccFalcon::keypair().expect("Hybrid key generation failed");
    group.bench_function("ECC+Falcon Signing", |b| {
        b.iter(|| {
            let signature = EccFalcon::sign(black_box(&test_message), black_box(&sk_hybrid))
                .expect("Hybrid signing failed");
            black_box(signature)
        })
    });

    let signature_hybrid =
        EccFalcon::sign(&test_message, &sk_hybrid).expect("Hybrid signing failed");

    group.bench_function("ECC+Falcon Verification", |b| {
        b.iter(|| {
            let result = EccFalcon::verify(
                black_box(&test_message),
                black_box(&signature_hybrid),
                black_box(&pk_hybrid),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_ecc_sphincs_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECC+SPHINCS+ Hybrid Operations");
    let test_message = vec![0x7Cu8; 512];

    group.bench_function("ECC+SPHINCS+ Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = EccSphincs::keypair().expect("Hybrid key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_hybrid, sk_hybrid) = EccSphincs::keypair().expect("Hybrid key generation failed");
    group.bench_function("ECC+SPHINCS+ Signing", |b| {
        b.iter(|| {
            let signature = EccSphincs::sign(black_box(&test_message), black_box(&sk_hybrid))
                .expect("Hybrid signing failed");
            black_box(signature)
        })
    });

    let signature_hybrid =
        EccSphincs::sign(&test_message, &sk_hybrid).expect("Hybrid signing failed");

    group.bench_function("ECC+SPHINCS+ Verification", |b| {
        b.iter(|| {
            let result = EccSphincs::verify(
                black_box(&test_message),
                black_box(&signature_hybrid),
                black_box(&pk_hybrid),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_hybrid_verification_policies(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Verification Policies");
    let test_message = vec![0x8Du8; 256];

    let (pk_hybrid, sk_hybrid) = EccDilithium::keypair().expect("Hybrid key generation failed");
    let signature_hybrid = EccDilithium::sign(&test_message, &sk_hybrid)
        .expect("Hybrid signing failed");

    group.bench_function("Hybrid Verification - BothRequired", |b| {
        b.iter(|| {
            let result = EccDilithium::verify_with_policy(
                black_box(&test_message),
                black_box(&signature_hybrid),
                black_box(&pk_hybrid),
                VerificationPolicy::BothRequired,
            );
            black_box(result)
        })
    });

    group.bench_function("Hybrid Verification - EitherValid", |b| {
        b.iter(|| {
            let result = EccDilithium::verify_with_policy(
                black_box(&test_message),
                black_box(&signature_hybrid),
                black_box(&pk_hybrid),
                VerificationPolicy::EitherValid,
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
                VerificationPolicy::ClassicalOnly,
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
                VerificationPolicy::PostQuantumOnly,
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_hybrid_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Algorithm Comparison");
    let test_message = vec![0x9Eu8; 1024];

    
    group.bench_function("ECC+Dilithium Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(&test_message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(&test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+Falcon Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
            let signature = EccFalcon::sign(&test_message, &sk).expect("Hybrid signing failed");
            let result = EccFalcon::verify(&test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+SPHINCS+ Complete Workflow", |b| {
        b.iter(|| {
            let (pk, sk) = EccSphincs::keypair().expect("Hybrid key generation failed");
            let signature = EccSphincs::sign(&test_message, &sk).expect("Hybrid signing failed");
            let result = EccSphincs::verify(&test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_hybrid_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Batch Operations");
    let test_message = vec![0xAFu8; 256];

    for batch_size in [5, 25, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("ECC+Dilithium Batch Signing", batch_size),
            batch_size,
            |b, &size| {
                let keypairs: Vec<_> = (0..size)
                    .map(|_| EccDilithium::keypair().expect("Hybrid key generation failed"))
                    .collect();

                b.iter(|| {
                    let mut signatures = Vec::with_capacity(size);
                    for (_, sk) in &keypairs {
                        let signature = EccDilithium::sign(&test_message, sk)
                            .expect("Hybrid signing failed");
                        signatures.push(signature);
                    }
                    black_box(signatures)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ECC+Falcon Batch Verification", batch_size),
            batch_size,
            |b, &size| {
                
                let test_data: Vec<_> = (0..size)
                    .map(|_| {
                        let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
                        let signature = EccFalcon::sign(&test_message, &sk)
                            .expect("Hybrid signing failed");
                        (pk, signature)
                    })
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (pk, signature) in &test_data {
                        let result = EccFalcon::verify(&test_message, signature, pk);
                        results.push(result);
                    }
                    black_box(results)
                })
            },
        );
    }

    group.finish();
}

fn benchmark_hybrid_policy_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Policy Performance Comparison");
    let test_message = vec![0xBCu8; 512];

    
    let (pk_dilithium, sk_dilithium) = EccDilithium::keypair().expect("Hybrid key generation failed");
    let sig_dilithium = EccDilithium::sign(&test_message, &sk_dilithium)
        .expect("Hybrid signing failed");

    let (pk_falcon, sk_falcon) = EccFalcon::keypair().expect("Hybrid key generation failed");
    let sig_falcon = EccFalcon::sign(&test_message, &sk_falcon)
        .expect("Hybrid signing failed");

    let (pk_sphincs, sk_sphincs) = EccSphincs::keypair().expect("Hybrid key generation failed");
    let sig_sphincs = EccSphincs::sign(&test_message, &sk_sphincs)
        .expect("Hybrid signing failed");

    
    for policy in [
        VerificationPolicy::BothRequired,
        VerificationPolicy::EitherValid,
        VerificationPolicy::ClassicalOnly,
        VerificationPolicy::PostQuantumOnly,
    ].iter() {
        let policy_name = format!("{:?}", policy);

        group.bench_function(&format!("ECC+Dilithium {}", policy_name), |b| {
            b.iter(|| {
                let result = EccDilithium::verify_with_policy(
                    black_box(&test_message),
                    black_box(&sig_dilithium),
                    black_box(&pk_dilithium),
                    *policy,
                );
                black_box(result)
            })
        });

        group.bench_function(&format!("ECC+Falcon {}", policy_name), |b| {
            b.iter(|| {
                let result = EccFalcon::verify_with_policy(
                    black_box(&test_message),
                    black_box(&sig_falcon),
                    black_box(&pk_falcon),
                    *policy,
                );
                black_box(result)
            })
        });

        group.bench_function(&format!("ECC+SPHINCS+ {}", policy_name), |b| {
            b.iter(|| {
                let result = EccSphincs::verify_with_policy(
                    black_box(&test_message),
                    black_box(&sig_sphincs),
                    black_box(&pk_sphincs),
                    *policy,
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

fn benchmark_hybrid_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Message Size Impact");

    let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");

    for size in [32, 128, 512, 2048, 8192].iter() {
        let message = vec![0xCDu8; *size];

        group.bench_with_input(
            BenchmarkId::new("ECC+Dilithium Signing", size),
            size,
            |b, _size| {
                b.iter(|| {
                    let signature = EccDilithium::sign(black_box(&message), black_box(&sk))
                        .expect("Hybrid signing failed");
                    black_box(signature)
                })
            },
        );

        let signature = EccDilithium::sign(&message, &sk).expect("Hybrid signing failed");
        group.bench_with_input(
            BenchmarkId::new("ECC+Dilithium Verification", size),
            size,
            |b, _size| {
                b.iter(|| {
                    let result = EccDilithium::verify(
                        black_box(&message),
                        black_box(&signature),
                        black_box(&pk),
                    );
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    hybrid_signature_benches,
    benchmark_ecc_dilithium_operations,
    benchmark_ecc_falcon_operations,
    benchmark_ecc_sphincs_operations,
    benchmark_hybrid_verification_policies,
    benchmark_hybrid_algorithm_comparison,
    benchmark_hybrid_batch_operations,
    benchmark_hybrid_policy_comparison,
    benchmark_hybrid_message_sizes
);

criterion_main!(hybrid_signature_benches);