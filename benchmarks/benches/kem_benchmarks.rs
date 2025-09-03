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

fn safe_crypto_op<T, E>(result: Result<T, E>, operation: &str) -> T
where 
    E: std::fmt::Display,
{
    match result {
        Ok(value) => value,
        Err(e) => {
            panic!("Critical benchmark failure in {}: {}. This indicates a fundamental crypto library issue that requires immediate attention.", operation, e);
        }
    }
}

fn benchmark_ml_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Operations");

    group.bench_function("ML-KEM-512 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem512::keypair(), "ML-KEM-512 keypair generation");
            black_box((pk, sk))
        })
    });

    let (pk_512, sk_512) = safe_crypto_op(MlKem512::keypair(), "ML-KEM-512 benchmark setup");
    group.bench_function("ML-KEM-512 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem512::encapsulate(black_box(&pk_512)), "ML-KEM-512 encapsulation");
            black_box((ct, ss))
        })
    });

    let (ct_512, _ss_512) = safe_crypto_op(MlKem512::encapsulate(&pk_512), "ML-KEM-512 encapsulation setup");
    group.bench_function("ML-KEM-512 Decapsulation", |b| {
        b.iter(|| {
            let ss = safe_crypto_op(MlKem512::decapsulate(black_box(&ct_512), black_box(&sk_512)), "ML-KEM-512 decapsulation");
            black_box(ss)
        })
    });

    group.bench_function("ML-KEM-768 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 keypair generation");
            black_box((pk, sk))
        })
    });

    let (pk_768, sk_768) = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 benchmark setup");
    group.bench_function("ML-KEM-768 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem768::encapsulate(black_box(&pk_768)), "ML-KEM-768 encapsulation");
            black_box((ct, ss))
        })
    });

    let (ct_768, _ss_768) = safe_crypto_op(MlKem768::encapsulate(&pk_768), "ML-KEM-768 encapsulation setup");
    group.bench_function("ML-KEM-768 Decapsulation", |b| {
        b.iter(|| {
            let ss = safe_crypto_op(MlKem768::decapsulate(black_box(&ct_768), black_box(&sk_768)), "ML-KEM-768 decapsulation");
            black_box(ss)
        })
    });

    group.bench_function("ML-KEM-1024 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem1024::keypair(), "ML-KEM-1024 keypair generation");
            black_box((pk, sk))
        })
    });

    let (pk_1024, sk_1024) = safe_crypto_op(MlKem1024::keypair(), "ML-KEM-1024 benchmark setup");
    group.bench_function("ML-KEM-1024 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem1024::encapsulate(black_box(&pk_1024)), "ML-KEM-1024 encapsulation");
            black_box((ct, ss))
        })
    });

    let (ct_1024, _ss_1024) = safe_crypto_op(MlKem1024::encapsulate(&pk_1024), "ML-KEM-1024 encapsulation setup");
    group.bench_function("ML-KEM-1024 Decapsulation", |b| {
        b.iter(|| {
            let ss = safe_crypto_op(MlKem1024::decapsulate(black_box(&ct_1024), black_box(&sk_1024)), "ML-KEM-1024 decapsulation");
            black_box(ss)
        })
    });

    group.finish();
}

fn benchmark_kem_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Security Level Comparison");

    group.bench_function("ML-KEM-512 (Security Level 1) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem512::keypair(), "ML-KEM-512 complete workflow keypair");
            let (ct, _ss1) = safe_crypto_op(MlKem512::encapsulate(&pk), "ML-KEM-512 complete workflow encapsulate");
            let _ss2 = safe_crypto_op(MlKem512::decapsulate(&ct, &sk), "ML-KEM-512 complete workflow decapsulate");
            black_box(())
        })
    });

    group.bench_function("ML-KEM-768 (Security Level 3) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 complete workflow keypair");
            let (ct, _ss1) = safe_crypto_op(MlKem768::encapsulate(&pk), "ML-KEM-768 complete workflow encapsulate");
            let _ss2 = safe_crypto_op(MlKem768::decapsulate(&ct, &sk), "ML-KEM-768 complete workflow decapsulate");
            black_box(())
        })
    });

    group.bench_function("ML-KEM-1024 (Security Level 5) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = safe_crypto_op(MlKem1024::keypair(), "ML-KEM-1024 complete workflow keypair");
            let (ct, _ss1) = safe_crypto_op(MlKem1024::encapsulate(&pk), "ML-KEM-1024 complete workflow encapsulate");
            let _ss2 = safe_crypto_op(MlKem1024::decapsulate(&ct, &sk), "ML-KEM-1024 complete workflow decapsulate");
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_kem_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Throughput Analysis");
    
    let (pk_512, sk_512) = safe_crypto_op(MlKem512::keypair(), "ML-KEM-512 throughput setup");
    let (pk_768, sk_768) = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 throughput setup");
    let (pk_1024, sk_1024) = safe_crypto_op(MlKem1024::keypair(), "ML-KEM-1024 throughput setup");

    group.throughput(Throughput::Elements(1));
    
    group.bench_function("ML-KEM-512 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem512::encapsulate(black_box(&pk_512)), "ML-KEM-512 throughput encapsulation");
            black_box((ct, ss))
        })
    });

    group.bench_function("ML-KEM-768 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem768::encapsulate(black_box(&pk_768)), "ML-KEM-768 throughput encapsulation");
            black_box((ct, ss))
        })
    });

    group.bench_function("ML-KEM-1024 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = safe_crypto_op(MlKem1024::encapsulate(black_box(&pk_1024)), "ML-KEM-1024 throughput encapsulation");
            black_box((ct, ss))
        })
    });

    group.finish();
}

fn benchmark_kem_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Batch Operations");

    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("ML-KEM-768 Batch Keygen", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut keypairs = Vec::with_capacity(size);
                    for _ in 0..size {
                        let keypair = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 batch keypair generation");
                        keypairs.push(keypair);
                    }
                    black_box(keypairs)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ML-KEM-768 Batch Encapsulation", batch_size),
            batch_size,
            |b, &size| {
                let keypairs: Vec<_> = (0..size)
                    .map(|_| safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 batch encapsulation setup"))
                    .collect();
                
                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (pk, _) in &keypairs {
                        let result = safe_crypto_op(MlKem768::encapsulate(pk), "ML-KEM-768 batch encapsulation");
                        results.push(result);
                    }
                    black_box(results)
                })
            },
        );
    }

    group.finish();
}

fn benchmark_kem_key_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Key Reuse Scenarios");

    let (pk_768, _sk_768) = safe_crypto_op(MlKem768::keypair(), "ML-KEM-768 key reuse setup");

    group.bench_function("ML-KEM-768 Multiple Encapsulations Same Key", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(10);
            for _ in 0..10 {
                let result = safe_crypto_op(MlKem768::encapsulate(black_box(&pk_768)), "ML-KEM-768 key reuse encapsulation");
                results.push(result);
            }
            black_box(results)
        })
    });

    group.finish();
}

criterion_group!(
    kem_benches,
    benchmark_ml_kem_operations,
    benchmark_kem_security_levels,
    benchmark_kem_throughput,
    benchmark_kem_batch_operations,
    benchmark_kem_key_reuse
);

criterion_main!(kem_benches);