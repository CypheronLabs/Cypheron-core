use core_lib::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn benchmark_ml_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Operations");

    group.bench_function("ML-KEM-512 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
            black_box((pk, sk))
        })
    });

    let (pk_512, sk_512) = MlKem512::keypair().expect("Failed to generate keypair");
    group.bench_function("ML-KEM-512 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) =
                MlKem512::encapsulate(black_box(&pk_512)).expect("Failed to encapsulate");
            black_box((ct, ss))
        })
    });

    let (ct_512, _ss_512) = MlKem512::encapsulate(&pk_512).expect("Failed to encapsulate");
    group.bench_function("ML-KEM-512 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem512::decapsulate(black_box(&ct_512), black_box(&sk_512))
                .expect("Failed to decapsulate");
            black_box(ss)
        })
    });

    group.bench_function("ML-KEM-768 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            black_box((pk, sk))
        })
    });

    let (pk_768, sk_768) = MlKem768::keypair().expect("Failed to generate keypair");
    group.bench_function("ML-KEM-768 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) =
                MlKem768::encapsulate(black_box(&pk_768)).expect("Failed to encapsulate");
            black_box((ct, ss))
        })
    });

    let (ct_768, _ss_768) = MlKem768::encapsulate(&pk_768).expect("Failed to encapsulate");
    group.bench_function("ML-KEM-768 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem768::decapsulate(black_box(&ct_768), black_box(&sk_768))
                .expect("Failed to decapsulate");
            black_box(ss)
        })
    });

    group.bench_function("ML-KEM-1024 Keypair Generation", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair().expect("Failed to generate keypair");
            black_box((pk, sk))
        })
    });

    let (pk_1024, sk_1024) = MlKem1024::keypair().expect("Failed to generate keypair");
    group.bench_function("ML-KEM-1024 Encapsulation", |b| {
        b.iter(|| {
            let (ct, ss) =
                MlKem1024::encapsulate(black_box(&pk_1024)).expect("Failed to encapsulate");
            black_box((ct, ss))
        })
    });

    let (ct_1024, _ss_1024) = MlKem1024::encapsulate(&pk_1024).expect("Failed to encapsulate");
    group.bench_function("ML-KEM-1024 Decapsulation", |b| {
        b.iter(|| {
            let ss = MlKem1024::decapsulate(black_box(&ct_1024), black_box(&sk_1024))
                .expect("Failed to decapsulate");
            black_box(ss)
        })
    });

    group.finish();
}

fn benchmark_kem_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Security Level Comparison");

    group.bench_function("ML-KEM-512 (Security Level 1) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
            let (ct, _ss1) = MlKem512::encapsulate(&pk).expect("Failed to encapsulate");
            let _ss2 = MlKem512::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            black_box(())
        })
    });

    group.bench_function("ML-KEM-768 (Security Level 3) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, _ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let _ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            black_box(())
        })
    });

    group.bench_function("ML-KEM-1024 (Security Level 5) - Complete", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair().expect("Failed to generate keypair");
            let (ct, _ss1) = MlKem1024::encapsulate(&pk).expect("Failed to encapsulate");
            let _ss2 = MlKem1024::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            black_box(())
        })
    });

    group.finish();
}

fn benchmark_kem_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Throughput Analysis");
    
    let (pk_512, sk_512) = MlKem512::keypair().expect("Failed to generate keypair");
    let (pk_768, sk_768) = MlKem768::keypair().expect("Failed to generate keypair");
    let (pk_1024, sk_1024) = MlKem1024::keypair().expect("Failed to generate keypair");

    group.throughput(Throughput::Elements(1));
    
    group.bench_function("ML-KEM-512 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem512::encapsulate(black_box(&pk_512))
                .expect("Failed to encapsulate");
            black_box((ct, ss))
        })
    });

    group.bench_function("ML-KEM-768 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem768::encapsulate(black_box(&pk_768))
                .expect("Failed to encapsulate");
            black_box((ct, ss))
        })
    });

    group.bench_function("ML-KEM-1024 Encapsulation Throughput", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem1024::encapsulate(black_box(&pk_1024))
                .expect("Failed to encapsulate");
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
                        let keypair = MlKem768::keypair().expect("Failed to generate keypair");
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
                    .map(|_| MlKem768::keypair().expect("Failed to generate keypair"))
                    .collect();
                
                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (pk, _) in &keypairs {
                        let result = MlKem768::encapsulate(pk).expect("Failed to encapsulate");
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

    let (pk_768, _sk_768) = MlKem768::keypair().expect("Failed to generate keypair");

    group.bench_function("ML-KEM-768 Multiple Encapsulations Same Key", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(10);
            for _ in 0..10 {
                let result = MlKem768::encapsulate(black_box(&pk_768))
                    .expect("Failed to encapsulate");
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