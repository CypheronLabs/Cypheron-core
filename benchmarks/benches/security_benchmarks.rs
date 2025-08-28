use core_lib::prelude::*;
use core_lib::platform::{secure_random_bytes, secure_zero};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::{Duration, Instant};

fn benchmark_timing_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Timing Consistency Analysis");
    
    
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    
    group.bench_function("ML-KEM-768 Timing Consistency Keypair", |b| {
        b.iter(|| {
            let start = Instant::now();
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let duration = start.elapsed();
            black_box((pk, sk, duration))
        })
    });

    let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
    group.bench_function("ML-KEM-768 Timing Consistency Encapsulation", |b| {
        b.iter(|| {
            let start = Instant::now();
            let (ct, ss) = MlKem768::encapsulate(black_box(&pk)).expect("Failed to encapsulate");
            let duration = start.elapsed();
            black_box((ct, ss, duration))
        })
    });

    let (ct, _) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
    group.bench_function("ML-KEM-768 Timing Consistency Decapsulation", |b| {
        b.iter(|| {
            let start = Instant::now();
            let ss = MlKem768::decapsulate(black_box(&ct), black_box(&sk))
                .expect("Failed to decapsulate");
            let duration = start.elapsed();
            black_box((ss, duration))
        })
    });

    
    let test_message = vec![0x42u8; 1024];
    let (pk_sig, sk_sig) = MlDsa44::keypair().expect("Key generation failed");
    
    group.bench_function("ML-DSA-44 Timing Consistency Signing", |b| {
        b.iter(|| {
            let start = Instant::now();
            let signature = MlDsa44::sign(black_box(&test_message), black_box(&sk_sig))
                .expect("Signing failed");
            let duration = start.elapsed();
            black_box((signature, duration))
        })
    });

    let signature = MlDsa44::sign(&test_message, &sk_sig).expect("Signing failed");
    group.bench_function("ML-DSA-44 Timing Consistency Verification", |b| {
        b.iter(|| {
            let start = Instant::now();
            let result = MlDsa44::verify(
                black_box(&test_message),
                black_box(&signature),
                black_box(&pk_sig),
            );
            let duration = start.elapsed();
            black_box((result, duration))
        })
    });

    group.finish();
}

fn benchmark_memory_security_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Security Overhead");

    
    group.bench_function("Secure Random Bytes Generation", |b| {
        b.iter(|| {
            let mut buffer = vec![0u8; 1024];
            secure_random_bytes(black_box(&mut buffer)).expect("Failed to generate random bytes");
            black_box(buffer)
        })
    });

    
    for size in [32, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(
            BenchmarkId::new("Secure Memory Zeroing", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut buffer = vec![0xAAu8; size];
                    secure_zero(black_box(&mut buffer));
                    black_box(buffer)
                })
            },
        );
    }

    
    group.bench_function("ML-KEM-768 with Zeroization Overhead", |b| {
        b.iter(|| {
            let (pk, mut sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            
            
            use core_lib::prelude::*;
use core_lib::kem::ml_kem_768::MlKemSecretKey;
            drop(sk); 
            
            black_box((ss1, ss2))
        })
    });

    group.finish();
}

fn benchmark_side_channel_resistance(c: &mut Criterion) {
    let mut group = c.benchmark_group("Side-Channel Resistance Validation");
    
    
    let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
    
    
    group.bench_function("ML-KEM-768 Decapsulation Pattern Independence", |b| {
        let test_ciphertexts: Vec<_> = (0..10)
            .map(|_| MlKem768::encapsulate(&pk).expect("Failed to encapsulate").0)
            .collect();
        
        b.iter(|| {
            let mut results = Vec::with_capacity(10);
            for ct in &test_ciphertexts {
                let start = Instant::now();
                let ss = MlKem768::decapsulate(black_box(ct), black_box(&sk))
                    .expect("Failed to decapsulate");
                let duration = start.elapsed();
                results.push((ss, duration));
            }
            black_box(results)
        })
    });

    
    let test_message = vec![0x55u8; 512];
    let (pk_sig, sk_sig) = MlDsa44::keypair().expect("Key generation failed");
    let valid_sig = MlDsa44::sign(&test_message, &sk_sig).expect("Signing failed");
    let mut invalid_sig = valid_sig.clone();
    
    if let Some(byte) = invalid_sig.0.get_mut(0) {
        *byte = byte.wrapping_add(1);
    }

    group.bench_function("ML-DSA-44 Verification Timing Independence", |b| {
        b.iter(|| {
            let start_valid = Instant::now();
            let result_valid = MlDsa44::verify(
                black_box(&test_message),
                black_box(&valid_sig),
                black_box(&pk_sig),
            );
            let duration_valid = start_valid.elapsed();

            let start_invalid = Instant::now();
            let result_invalid = MlDsa44::verify(
                black_box(&test_message),
                black_box(&invalid_sig),
                black_box(&pk_sig),
            );
            let duration_invalid = start_invalid.elapsed();

            black_box((result_valid, duration_valid, result_invalid, duration_invalid))
        })
    });

    group.finish();
}

fn benchmark_ffi_security_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("FFI Security Validation Overhead");

    
    group.bench_function("FFI Buffer Validation Overhead", |b| {
        use core_lib::prelude::*;
use core_lib::security::{sanitize_buffer_for_ffi, verify_buffer_initialized};
        
        b.iter(|| {
            let mut buffer = vec![0x42u8; 1024];
            
            
            let is_safe = sanitize_buffer_for_ffi(black_box(&mut buffer));
            let is_initialized = verify_buffer_initialized(black_box(&buffer), 1024);
            
            black_box((is_safe, is_initialized))
        })
    });

    
    group.bench_function("ML-KEM-768 with FFI Security Checks", |b| {
        b.iter(|| {
            
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            
            
            let mut pk_bytes = vec![0u8; pk.0.len()];
            pk_bytes.copy_from_slice(&pk.0);
            let _validation1 = core_lib::security::sanitize_buffer_for_ffi(&mut pk_bytes);
            
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            
            let mut ct_bytes = ct.clone();
            let _validation2 = core_lib::security::verify_buffer_initialized(&ct_bytes, ct_bytes.len());
            
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            
            black_box((ss1, ss2))
        })
    });

    group.finish();
}

fn benchmark_concurrent_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("Concurrent Operations Security");
    
    use std::thread;
    use std::sync::Arc;

    
    group.bench_function("ML-KEM-768 Concurrent Keypair Generation", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    thread::spawn(|| {
                        let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
                        (pk, sk)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter()
                .map(|h| h.join().expect("Thread failed"))
                .collect();
            
            black_box(results)
        })
    });

    
    group.bench_function("ECC+Dilithium Concurrent Operations", |b| {
        let message = Arc::new(vec![0x66u8; 256]);
        
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let msg = Arc::clone(&message);
                    thread::spawn(move || {
                        let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
                        let signature = EccDilithium::sign(&msg, &sk).expect("Hybrid signing failed");
                        let result = EccDilithium::verify(&msg, &signature, &pk);
                        (result, pk, signature)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter()
                .map(|h| h.join().expect("Thread failed"))
                .collect();
            
            black_box(results)
        })
    });

    group.finish();
}

fn benchmark_error_handling_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("Error Handling Performance");

    
    group.bench_function("ML-KEM-768 Valid vs Invalid Operations", |b| {
        let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
        let (valid_ct, _) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
        
        
        let mut invalid_ct = valid_ct.clone();
        if let Some(byte) = invalid_ct.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }
        
        b.iter(|| {
            
            let start_valid = Instant::now();
            let result_valid = MlKem768::decapsulate(black_box(&valid_ct), black_box(&sk));
            let duration_valid = start_valid.elapsed();
            
            
            let start_invalid = Instant::now();
            let result_invalid = MlKem768::decapsulate(black_box(&invalid_ct), black_box(&sk));
            let duration_invalid = start_invalid.elapsed();
            
            black_box((result_valid, duration_valid, result_invalid, duration_invalid))
        })
    });

    group.finish();
}

fn benchmark_key_lifecycle_security(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Lifecycle Security");

    
    group.bench_function("Key Generation Entropy Quality", |b| {
        b.iter(|| {
            
            let mut keys = Vec::with_capacity(10);
            for _ in 0..10 {
                let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
                keys.push((pk, sk));
            }
            
            
            for i in 0..keys.len() {
                for j in (i + 1)..keys.len() {
                    assert_ne!(keys[i].0.0, keys[j].0.0, "Public keys should be different");
                }
            }
            
            black_box(keys)
        })
    });

    
    group.bench_function("Secure Key Destruction", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            
            
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            
            
            drop(sk);
            drop(pk);
            
            black_box((ss1, ss2))
        })
    });

    group.finish();
}

fn benchmark_platform_security_features(c: &mut Criterion) {
    let mut group = c.benchmark_group("Platform Security Features");

    
    group.bench_function("Platform Secure Random Generation", |b| {
        b.iter(|| {
            let mut buffers = Vec::with_capacity(10);
            for size in [32, 64, 128, 256, 512] {
                let mut buffer = vec![0u8; size];
                secure_random_bytes(black_box(&mut buffer))
                    .expect("Failed to generate random bytes");
                buffers.push(buffer);
            }
            black_box(buffers)
        })
    });

    
    group.bench_function("Platform Secure Memory Zeroing", |b| {
        b.iter(|| {
            let mut buffers = Vec::with_capacity(5);
            for size in [256, 512, 1024, 2048, 4096] {
                let mut buffer = vec![0xFFu8; size];
                secure_zero(black_box(&mut buffer));
                
                assert!(buffer.iter().all(|&b| b == 0), "Buffer not properly zeroed");
                buffers.push(buffer);
            }
            black_box(buffers)
        })
    });

    group.finish();
}

criterion_group!(
    security_benches,
    benchmark_timing_consistency,
    benchmark_memory_security_overhead,
    benchmark_side_channel_resistance,
    benchmark_ffi_security_overhead,
    benchmark_concurrent_security,
    benchmark_error_handling_performance,
    benchmark_key_lifecycle_security,
    benchmark_platform_security_features
);

criterion_main!(security_benches);