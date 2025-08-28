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

fn benchmark_ml_dsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Operations");
    let test_message = vec![0x42u8; 1024];

    group.bench_function("ML-DSA-44 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_44, sk_44) = MlDsa44::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-44 Signing", |b| {
        b.iter(|| {
            let signature =
                MlDsa44::sign(black_box(&test_message), black_box(&sk_44)).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_44 = MlDsa44::sign(&test_message, &sk_44).expect("Signing failed");
    group.bench_function("ML-DSA-44 Verification", |b| {
        b.iter(|| {
            let result = MlDsa44::verify(
                black_box(&test_message),
                black_box(&signature_44),
                black_box(&pk_44),
            );
            black_box(result)
        })
    });

    group.bench_function("ML-DSA-65 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_65, sk_65) = MlDsa65::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-65 Signing", |b| {
        b.iter(|| {
            let signature =
                MlDsa65::sign(black_box(&test_message), black_box(&sk_65)).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_65 = MlDsa65::sign(&test_message, &sk_65).expect("Signing failed");
    group.bench_function("ML-DSA-65 Verification", |b| {
        b.iter(|| {
            let result = MlDsa65::verify(
                black_box(&test_message),
                black_box(&signature_65),
                black_box(&pk_65),
            );
            black_box(result)
        })
    });

    group.bench_function("ML-DSA-87 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_87, sk_87) = MlDsa87::keypair().expect("Key generation failed");
    group.bench_function("ML-DSA-87 Signing", |b| {
        b.iter(|| {
            let signature =
                MlDsa87::sign(black_box(&test_message), black_box(&sk_87)).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_87 = MlDsa87::sign(&test_message, &sk_87).expect("Signing failed");
    group.bench_function("ML-DSA-87 Verification", |b| {
        b.iter(|| {
            let result = MlDsa87::verify(
                black_box(&test_message),
                black_box(&signature_87),
                black_box(&pk_87),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_falcon_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Falcon Operations");
    let test_message = vec![0x5Au8; 1024];

    group.bench_function("Falcon-512 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_512, sk_512) = Falcon512::keypair().expect("Key generation failed");
    group.bench_function("Falcon-512 Signing", |b| {
        b.iter(|| {
            let signature = Falcon512::sign(black_box(&test_message), black_box(&sk_512))
                .expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_512 = Falcon512::sign(&test_message, &sk_512).expect("Signing failed");
    group.bench_function("Falcon-512 Verification", |b| {
        b.iter(|| {
            let result = Falcon512::verify(
                black_box(&test_message),
                black_box(&signature_512),
                black_box(&pk_512),
            );
            black_box(result)
        })
    });

    group.bench_function("Falcon-1024 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon1024::keypair().expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_1024, sk_1024) = Falcon1024::keypair().expect("Key generation failed");
    group.bench_function("Falcon-1024 Signing", |b| {
        b.iter(|| {
            let signature = Falcon1024::sign(black_box(&test_message), black_box(&sk_1024))
                .expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_1024 = Falcon1024::sign(&test_message, &sk_1024).expect("Signing failed");
    group.bench_function("Falcon-1024 Verification", |b| {
        b.iter(|| {
            let result = Falcon1024::verify(
                black_box(&test_message),
                black_box(&signature_1024),
                black_box(&pk_1024),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_sphincs_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPHINCS+ Operations");
    let test_message = vec![0x7Bu8; 1024];

    group.bench_function("SPHINCS+-SHAKE-128f Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = core_lib::sig::sphincs::shake_128f::keypair()
                .expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_shake, sk_shake) = core_lib::sig::sphincs::shake_128f::keypair()
        .expect("Key generation failed");
    group.bench_function("SPHINCS+-SHAKE-128f Signing", |b| {
        b.iter(|| {
            let signature = core_lib::sig::sphincs::shake_128f::sign_detached(
                black_box(&test_message),
                black_box(&sk_shake),
            ).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_shake = core_lib::sig::sphincs::shake_128f::sign_detached(&test_message, &sk_shake)
        .expect("Signing failed");
    group.bench_function("SPHINCS+-SHAKE-128f Verification", |b| {
        b.iter(|| {
            let result = core_lib::sig::sphincs::shake_128f::verify_detached(
                black_box(&signature_shake),
                black_box(&test_message),
                black_box(&pk_shake),
            );
            black_box(result)
        })
    });

    group.bench_function("SPHINCS+-SHA2-256s Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = core_lib::sig::sphincs::sha2_256s::keypair()
                .expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_sha2, sk_sha2) = core_lib::sig::sphincs::sha2_256s::keypair()
        .expect("Key generation failed");
    group.bench_function("SPHINCS+-SHA2-256s Signing", |b| {
        b.iter(|| {
            let signature = core_lib::sig::sphincs::sha2_256s::sign_detached(
                black_box(&test_message),
                black_box(&sk_sha2),
            ).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_sha2 = core_lib::sig::sphincs::sha2_256s::sign_detached(&test_message, &sk_sha2)
        .expect("Signing failed");
    group.bench_function("SPHINCS+-SHA2-256s Verification", |b| {
        b.iter(|| {
            let result = core_lib::sig::sphincs::sha2_256s::verify_detached(
                black_box(&signature_sha2),
                black_box(&test_message),
                black_box(&pk_sha2),
            );
            black_box(result)
        })
    });

    group.bench_function("SPHINCS+-HARAKA-192f Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = core_lib::sig::sphincs::haraka_192f::keypair()
                .expect("Key generation failed");
            black_box((pk, sk))
        })
    });

    let (pk_haraka, sk_haraka) = core_lib::sig::sphincs::haraka_192f::keypair()
        .expect("Key generation failed");
    group.bench_function("SPHINCS+-HARAKA-192f Signing", |b| {
        b.iter(|| {
            let signature = core_lib::sig::sphincs::haraka_192f::sign_detached(
                black_box(&test_message),
                black_box(&sk_haraka),
            ).expect("Signing failed");
            black_box(signature)
        })
    });

    let signature_haraka = core_lib::sig::sphincs::haraka_192f::sign_detached(&test_message, &sk_haraka)
        .expect("Signing failed");
    group.bench_function("SPHINCS+-HARAKA-192f Verification", |b| {
        b.iter(|| {
            let result = core_lib::sig::sphincs::haraka_192f::verify_detached(
                black_box(&signature_haraka),
                black_box(&test_message),
                black_box(&pk_haraka),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn benchmark_signature_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature Message Size Throughput");

    let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");

    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let message = vec![0x7Fu8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("ML-DSA-44 Signing", size), size, |b, _size| {
            b.iter(|| {
                let signature =
                    MlDsa44::sign(black_box(&message), black_box(&sk)).expect("Signing failed");
                black_box(signature)
            })
        });

        let signature = MlDsa44::sign(&message, &sk).expect("Signing failed");
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-44 Verification", size),
            size,
            |b, _size| {
                b.iter(|| {
                    let result =
                        MlDsa44::verify(black_box(&message), black_box(&signature), black_box(&pk));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

fn benchmark_signature_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature Security Level Comparison");
    let test_message = vec![0x99u8; 1024];

    group.bench_function("ML-DSA-44 (Security Level 2) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa44::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });

    group.bench_function("ML-DSA-65 (Security Level 3) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            let signature = MlDsa65::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa65::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });

    group.bench_function("ML-DSA-87 (Security Level 5) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            let signature = MlDsa87::sign(&test_message, &sk).expect("Signing failed");
            let _result = MlDsa87::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });

    group.bench_function("Falcon-512 (Security Level 1) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            let signature = Falcon512::sign(&test_message, &sk).expect("Signing failed");
            let _result = Falcon512::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });

    group.bench_function("Falcon-1024 (Security Level 5) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon1024::keypair().expect("Key generation failed");
            let signature = Falcon1024::sign(&test_message, &sk).expect("Signing failed");
            let _result = Falcon1024::verify(&test_message, &signature, &pk);
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_signature_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature Batch Operations");
    let test_message = vec![0xAAu8; 512];

    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-44 Batch Verification", batch_size),
            batch_size,
            |b, &size| {
                let signatures: Vec<_> = (0..size)
                    .map(|_| {
                        let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
                        let signature = MlDsa44::sign(&test_message, &sk).expect("Signing failed");
                        (pk, signature)
                    })
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (pk, signature) in &signatures {
                        let result = MlDsa44::verify(&test_message, signature, pk);
                        results.push(result);
                    }
                    black_box(results)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Falcon-512 Batch Signing", batch_size),
            batch_size,
            |b, &size| {
                let keypairs: Vec<_> = (0..size)
                    .map(|_| Falcon512::keypair().expect("Key generation failed"))
                    .collect();

                b.iter(|| {
                    let mut signatures = Vec::with_capacity(size);
                    for (_, sk) in &keypairs {
                        let signature = Falcon512::sign(&test_message, sk).expect("Signing failed");
                        signatures.push(signature);
                    }
                    black_box(signatures)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    signature_benches,
    benchmark_ml_dsa_operations,
    benchmark_falcon_operations,
    benchmark_sphincs_operations,
    benchmark_signature_message_sizes,
    benchmark_signature_security_levels,
    benchmark_signature_batch_operations
);

criterion_main!(signature_benches);