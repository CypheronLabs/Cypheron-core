use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use cypheron_core::kem::{kyber512, kyber768, kyber1024};
use cypheron_core::sig::dilithium::{dilithium2, dilithium3, dilithium5};
use std::time::Duration;
use std::collections::HashMap;

const TEST_MESSAGE: &[u8] = b"Comparative benchmark test message for performance analysis against reference implementations.";

// Simulated reference implementation performance baselines
// These would be replaced with actual liboqs/pq-crystals benchmark results
struct ReferenceBaselines {
    kem_keygen: HashMap<&'static str, f64>,
    kem_encap: HashMap<&'static str, f64>,
    kem_decap: HashMap<&'static str, f64>,
    sig_keygen: HashMap<&'static str, f64>,
    sig_sign: HashMap<&'static str, f64>,
    sig_verify: HashMap<&'static str, f64>,
}

impl ReferenceBaselines {
    fn new() -> Self {
        let mut baselines = ReferenceBaselines {
            kem_keygen: HashMap::new(),
            kem_encap: HashMap::new(),
            kem_decap: HashMap::new(),
            sig_keygen: HashMap::new(),
            sig_sign: HashMap::new(),
            sig_verify: HashMap::new(),
        };
        
        // KEM baselines (operations per second) - placeholder values
        baselines.kem_keygen.insert("kyber512", 50000.0);
        baselines.kem_keygen.insert("kyber768", 35000.0);
        baselines.kem_keygen.insert("kyber1024", 25000.0);
        
        baselines.kem_encap.insert("kyber512", 75000.0);
        baselines.kem_encap.insert("kyber768", 55000.0);
        baselines.kem_encap.insert("kyber1024", 40000.0);
        
        baselines.kem_decap.insert("kyber512", 70000.0);
        baselines.kem_decap.insert("kyber768", 50000.0);
        baselines.kem_decap.insert("kyber1024", 35000.0);
        
        // Signature baselines (operations per second) - placeholder values
        baselines.sig_keygen.insert("dilithium2", 8000.0);
        baselines.sig_keygen.insert("dilithium3", 6000.0);
        baselines.sig_keygen.insert("dilithium5", 4000.0);
        
        baselines.sig_sign.insert("dilithium2", 12000.0);
        baselines.sig_sign.insert("dilithium3", 9000.0);
        baselines.sig_sign.insert("dilithium5", 6000.0);
        
        baselines.sig_verify.insert("dilithium2", 30000.0);
        baselines.sig_verify.insert("dilithium3", 25000.0);
        baselines.sig_verify.insert("dilithium5", 20000.0);
        
        baselines
    }
}

fn benchmark_kem_vs_reference(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM vs Reference Implementations");
    
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(1000);
    
    // Benchmark ML-KEM-512
    group.bench_function("Cypheron_ML-KEM-512_keygen", |b| {
        b.iter(|| {
            let _ = black_box(kyber512::keygen());
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-768_keygen", |b| {
        b.iter(|| {
            let _ = black_box(kyber768::keygen());
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-1024_keygen", |b| {
        b.iter(|| {
            let _ = black_box(kyber1024::keygen());
        })
    });
    
    // Encapsulation benchmarks
    let (pk_512, _) = kyber512::keygen();
    let (pk_768, _) = kyber768::keygen();
    let (pk_1024, _) = kyber1024::keygen();
    
    group.bench_function("Cypheron_ML-KEM-512_encap", |b| {
        b.iter(|| {
            let _ = black_box(kyber512::encapsulate(&pk_512));
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-768_encap", |b| {
        b.iter(|| {
            let _ = black_box(kyber768::encapsulate(&pk_768));
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-1024_encap", |b| {
        b.iter(|| {
            let _ = black_box(kyber1024::encapsulate(&pk_1024));
        })
    });
    
    // Decapsulation benchmarks
    let (ct_512, _) = kyber512::encapsulate(&pk_512);
    let (ct_768, _) = kyber768::encapsulate(&pk_768);
    let (ct_1024, _) = kyber1024::encapsulate(&pk_1024);
    
    let (_, sk_512) = kyber512::keygen();
    let (_, sk_768) = kyber768::keygen();
    let (_, sk_1024) = kyber1024::keygen();
    
    group.bench_function("Cypheron_ML-KEM-512_decap", |b| {
        b.iter(|| {
            let _ = black_box(kyber512::decapsulate(&ct_512, &sk_512));
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-768_decap", |b| {
        b.iter(|| {
            let _ = black_box(kyber768::decapsulate(&ct_768, &sk_768));
        })
    });
    
    group.bench_function("Cypheron_ML-KEM-1024_decap", |b| {
        b.iter(|| {
            let _ = black_box(kyber1024::decapsulate(&ct_1024, &sk_1024));
        })
    });
    
    group.finish();
}

fn benchmark_sig_vs_reference(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature vs Reference Implementations");
    
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(500);
    
    // Key generation benchmarks
    group.bench_function("Cypheron_ML-DSA-44_keygen", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::keygen());
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-65_keygen", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::keygen());
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-87_keygen", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::keygen());
        })
    });
    
    // Signing benchmarks
    let (_, sk_d2) = dilithium2::keygen();
    let (_, sk_d3) = dilithium3::keygen();
    let (_, sk_d5) = dilithium5::keygen();
    
    group.bench_function("Cypheron_ML-DSA-44_sign", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::sign(TEST_MESSAGE, &sk_d2));
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-65_sign", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::sign(TEST_MESSAGE, &sk_d3));
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-87_sign", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::sign(TEST_MESSAGE, &sk_d5));
        })
    });
    
    // Verification benchmarks
    let (pk_d2, _) = dilithium2::keygen();
    let (pk_d3, _) = dilithium3::keygen();
    let (pk_d5, _) = dilithium5::keygen();
    
    let sig_d2 = dilithium2::sign(TEST_MESSAGE, &sk_d2);
    let sig_d3 = dilithium3::sign(TEST_MESSAGE, &sk_d3);
    let sig_d5 = dilithium5::sign(TEST_MESSAGE, &sk_d5);
    
    group.bench_function("Cypheron_ML-DSA-44_verify", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::verify(TEST_MESSAGE, &sig_d2, &pk_d2));
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-65_verify", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::verify(TEST_MESSAGE, &sig_d3, &pk_d3));
        })
    });
    
    group.bench_function("Cypheron_ML-DSA-87_verify", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::verify(TEST_MESSAGE, &sig_d5, &pk_d5));
        })
    });
    
    group.finish();
}

fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage Analysis");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // Memory usage for key generation
    group.bench_function("ML-KEM-768_memory_profile", |b| {
        b.iter(|| {
            // Generate multiple keys to test memory allocation patterns
            let mut keys = Vec::new();
            for _ in 0..100 {
                let (pk, sk) = black_box(kyber768::keygen());
                keys.push((pk, sk));
            }
            // Ensure keys are not optimized away
            black_box(keys);
        })
    });
    
    group.bench_function("ML-DSA-65_memory_profile", |b| {
        b.iter(|| {
            // Generate multiple keys to test memory allocation patterns
            let mut keys = Vec::new();
            for _ in 0..50 {
                let (pk, sk) = black_box(dilithium3::keygen());
                keys.push((pk, sk));
            }
            // Ensure keys are not optimized away
            black_box(keys);
        })
    });
    
    group.finish();
}

fn benchmark_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("Scalability Testing");
    
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);
    
    // Test performance scaling with workload size
    for size in [1, 10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("ML-KEM-768_batch_operations", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut operations = Vec::new();
                    for _ in 0..size {
                        let (pk, sk) = black_box(kyber768::keygen());
                        let (ct, ss1) = black_box(kyber768::encapsulate(&pk));
                        let ss2 = black_box(kyber768::decapsulate(&ct, &sk));
                        operations.push((ss1, ss2));
                    }
                    black_box(operations);
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_kem_vs_reference,
    benchmark_sig_vs_reference,
    benchmark_memory_usage,
    benchmark_scalability
);
criterion_main!(benches);