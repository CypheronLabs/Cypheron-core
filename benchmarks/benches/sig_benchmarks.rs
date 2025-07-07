use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use cypheron_core::sig::{
    dilithium::{dilithium2, dilithium3, dilithium5},
    falcon::{falcon512, falcon1024},
    sphincs::{haraka_192f, sha2_256s, shake_128f}
};
use std::time::Duration;

const TEST_MESSAGE: &[u8] = b"This is a test message for digital signature benchmarking. It contains enough data to be representative of real-world usage patterns.";

fn benchmark_sig_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Digital Signature Key Generation");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);
    
    // ML-DSA (Dilithium) variants
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::keygen());
        })
    });
    
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::keygen());
        })
    });
    
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::keygen());
        })
    });
    
    // Falcon variants
    group.bench_function("Falcon-512", |b| {
        b.iter(|| {
            let _ = black_box(falcon512::keygen());
        })
    });
    
    group.bench_function("Falcon-1024", |b| {
        b.iter(|| {
            let _ = black_box(falcon1024::keygen());
        })
    });
    
    // SPHINCS+ variants
    group.bench_function("SPHINCS+-Haraka-192f", |b| {
        b.iter(|| {
            let _ = black_box(haraka_192f::keygen());
        })
    });
    
    group.bench_function("SPHINCS+-SHA2-256s", |b| {
        b.iter(|| {
            let _ = black_box(sha2_256s::keygen());
        })
    });
    
    group.bench_function("SPHINCS+-SHAKE-128f", |b| {
        b.iter(|| {
            let _ = black_box(shake_128f::keygen());
        })
    });
    
    group.finish();
}

fn benchmark_sig_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Digital Signature Signing");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);
    
    // Pre-generate keys for signing benchmarks
    let (_, sk_d2) = dilithium2::keygen();
    let (_, sk_d3) = dilithium3::keygen();
    let (_, sk_d5) = dilithium5::keygen();
    let (_, sk_f512) = falcon512::keygen();
    let (_, sk_f1024) = falcon1024::keygen();
    let (_, sk_h192f) = haraka_192f::keygen();
    let (_, sk_s256s) = sha2_256s::keygen();
    let (_, sk_sh128f) = shake_128f::keygen();
    
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::sign(TEST_MESSAGE, &sk_d2));
        })
    });
    
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::sign(TEST_MESSAGE, &sk_d3));
        })
    });
    
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::sign(TEST_MESSAGE, &sk_d5));
        })
    });
    
    group.bench_function("Falcon-512", |b| {
        b.iter(|| {
            let _ = black_box(falcon512::sign(TEST_MESSAGE, &sk_f512));
        })
    });
    
    group.bench_function("Falcon-1024", |b| {
        b.iter(|| {
            let _ = black_box(falcon1024::sign(TEST_MESSAGE, &sk_f1024));
        })
    });
    
    group.bench_function("SPHINCS+-Haraka-192f", |b| {
        b.iter(|| {
            let _ = black_box(haraka_192f::sign(TEST_MESSAGE, &sk_h192f));
        })
    });
    
    group.bench_function("SPHINCS+-SHA2-256s", |b| {
        b.iter(|| {
            let _ = black_box(sha2_256s::sign(TEST_MESSAGE, &sk_s256s));
        })
    });
    
    group.bench_function("SPHINCS+-SHAKE-128f", |b| {
        b.iter(|| {
            let _ = black_box(shake_128f::sign(TEST_MESSAGE, &sk_sh128f));
        })
    });
    
    group.finish();
}

fn benchmark_sig_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Digital Signature Verification");
    
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    // Pre-generate keys and signatures for verification benchmarks
    let (pk_d2, sk_d2) = dilithium2::keygen();
    let sig_d2 = dilithium2::sign(TEST_MESSAGE, &sk_d2);
    
    let (pk_d3, sk_d3) = dilithium3::keygen();
    let sig_d3 = dilithium3::sign(TEST_MESSAGE, &sk_d3);
    
    let (pk_d5, sk_d5) = dilithium5::keygen();
    let sig_d5 = dilithium5::sign(TEST_MESSAGE, &sk_d5);
    
    let (pk_f512, sk_f512) = falcon512::keygen();
    let sig_f512 = falcon512::sign(TEST_MESSAGE, &sk_f512);
    
    let (pk_f1024, sk_f1024) = falcon1024::keygen();
    let sig_f1024 = falcon1024::sign(TEST_MESSAGE, &sk_f1024);
    
    let (pk_h192f, sk_h192f) = haraka_192f::keygen();
    let sig_h192f = haraka_192f::sign(TEST_MESSAGE, &sk_h192f);
    
    let (pk_s256s, sk_s256s) = sha2_256s::keygen();
    let sig_s256s = sha2_256s::sign(TEST_MESSAGE, &sk_s256s);
    
    let (pk_sh128f, sk_sh128f) = shake_128f::keygen();
    let sig_sh128f = shake_128f::sign(TEST_MESSAGE, &sk_sh128f);
    
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            let _ = black_box(dilithium2::verify(TEST_MESSAGE, &sig_d2, &pk_d2));
        })
    });
    
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let _ = black_box(dilithium3::verify(TEST_MESSAGE, &sig_d3, &pk_d3));
        })
    });
    
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let _ = black_box(dilithium5::verify(TEST_MESSAGE, &sig_d5, &pk_d5));
        })
    });
    
    group.bench_function("Falcon-512", |b| {
        b.iter(|| {
            let _ = black_box(falcon512::verify(TEST_MESSAGE, &sig_f512, &pk_f512));
        })
    });
    
    group.bench_function("Falcon-1024", |b| {
        b.iter(|| {
            let _ = black_box(falcon1024::verify(TEST_MESSAGE, &sig_f1024, &pk_f1024));
        })
    });
    
    group.bench_function("SPHINCS+-Haraka-192f", |b| {
        b.iter(|| {
            let _ = black_box(haraka_192f::verify(TEST_MESSAGE, &sig_h192f, &pk_h192f));
        })
    });
    
    group.bench_function("SPHINCS+-SHA2-256s", |b| {
        b.iter(|| {
            let _ = black_box(sha2_256s::verify(TEST_MESSAGE, &sig_s256s, &pk_s256s));
        })
    });
    
    group.bench_function("SPHINCS+-SHAKE-128f", |b| {
        b.iter(|| {
            let _ = black_box(shake_128f::verify(TEST_MESSAGE, &sig_sh128f, &pk_sh128f));
        })
    });
    
    group.finish();
}

fn benchmark_sig_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Digital Signature Throughput");
    
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(30));
    
    let (pk_d3, sk_d3) = dilithium3::keygen();
    
    group.bench_function("ML-DSA-65_complete_cycle", |b| {
        b.iter(|| {
            let (pk, sk) = black_box(dilithium3::keygen());
            let sig = black_box(dilithium3::sign(TEST_MESSAGE, &sk));
            let valid = black_box(dilithium3::verify(TEST_MESSAGE, &sig, &pk));
            assert!(valid);
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_sig_keygen,
    benchmark_sig_signing,
    benchmark_sig_verification,
    benchmark_sig_throughput
);
criterion_main!(benches);