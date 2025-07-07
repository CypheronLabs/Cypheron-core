use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use core_lib::kem::{Kyber512, Kyber768, Kyber1024, Kem};
use std::time::Duration;

fn benchmark_kem_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Key Generation");
    
    // Set measurement time for statistical significance
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    // ML-KEM-512
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let _ = black_box(Kyber512::keypair());
        })
    });
    
    // ML-KEM-768
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let _ = black_box(Kyber768::keypair());
        })
    });
    
    // ML-KEM-1024
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let _ = black_box(Kyber1024::keypair());
        })
    });
    
    group.finish();
}

fn benchmark_kem_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Encapsulation");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    // Pre-generate keys for encapsulation benchmarks
    let (pk_512, _) = Kyber512::keypair();
    let (pk_768, _) = Kyber768::keypair();
    let (pk_1024, _) = Kyber1024::keypair();
    
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let _ = black_box(Kyber512::encapsulate(&pk_512));
        })
    });
    
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let _ = black_box(Kyber768::encapsulate(&pk_768));
        })
    });
    
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let _ = black_box(Kyber1024::encapsulate(&pk_1024));
        })
    });
    
    group.finish();
}

fn benchmark_kem_decapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Decapsulation");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    // Pre-generate keys and ciphertexts for decapsulation benchmarks
    let (pk_512, sk_512) = Kyber512::keypair();
    let (ct_512, _) = Kyber512::encapsulate(&pk_512);
    
    let (pk_768, sk_768) = Kyber768::keypair();
    let (ct_768, _) = Kyber768::encapsulate(&pk_768);
    
    let (pk_1024, sk_1024) = Kyber1024::keypair();
    let (ct_1024, _) = Kyber1024::encapsulate(&pk_1024);
    
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let _ = black_box(Kyber512::decapsulate(&ct_512, &sk_512));
        })
    });
    
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let _ = black_box(Kyber768::decapsulate(&ct_768, &sk_768));
        })
    });
    
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let _ = black_box(Kyber1024::decapsulate(&ct_1024, &sk_1024));
        })
    });
    
    group.finish();
}

fn benchmark_kem_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM Throughput");
    
    // Set throughput elements for ops/sec calculation
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(30));
    
    let (pk_768, sk_768) = Kyber768::keypair();
    let (ct_768, _) = Kyber768::encapsulate(&pk_768);
    
    group.bench_function("ML-KEM-768_complete_cycle", |b| {
        b.iter(|| {
            let (pk, sk) = black_box(Kyber768::keypair());
            let (ct, ss1) = black_box(Kyber768::encapsulate(&pk));
            let ss2 = black_box(Kyber768::decapsulate(&ct, &sk));
            // Note: comparison would need to be implemented for the SharedSecret type
            black_box((ss1, ss2));
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_kem_keygen,
    benchmark_kem_encapsulation,
    benchmark_kem_decapsulation,
    benchmark_kem_throughput
);
criterion_main!(benches);