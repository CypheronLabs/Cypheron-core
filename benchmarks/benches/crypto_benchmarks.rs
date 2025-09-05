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

//! Comprehensive Cypheron Core Library Benchmark Suite

use core_lib::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Quick smoke test for all major algorithm families
fn benchmark_quick_smoke_test(c: &mut Criterion) {
    let mut group = c.benchmark_group("Quick Smoke Test");

    let test_message = b"Quick smoke test message";

    group.bench_function("ML-KEM-768 Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            black_box(())
        })
    });

    group.bench_function("ML-DSA-44 Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(test_message, &sk).expect("Signing failed");
            let result = MlDsa44::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Falcon-512 Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            let signature = Falcon512::sign(test_message, &sk).expect("Signing failed");
            let result = Falcon512::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("SPHINCS+-SHAKE-128f Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) =
                core_lib::sig::sphincs::shake_128f::keypair().expect("Key generation failed");
            let signature = core_lib::sig::sphincs::shake_128f::sign_detached(test_message, &sk)
                .expect("Signing failed");
            let result =
                core_lib::sig::sphincs::shake_128f::verify_detached(&signature, test_message, &pk);
            assert!(result.is_ok());
            black_box(())
        })
    });

    group.bench_function("ECC+Dilithium Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(test_message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("P256+ML-KEM-768 Quick Test", |b| {
        b.iter(|| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid KEM key generation failed");
            let (ct, ss1) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
            let ss2 = P256MlKem768::decapsulate(&ct, &sk).expect("Hybrid decapsulation failed");
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            black_box(())
        })
    });

    group.finish();
}

/// High-level performance overview across security levels
fn benchmark_security_level_overview(c: &mut Criterion) {
    let mut group = c.benchmark_group("Security Level Overview");
    let test_message = b"Security level comparison message";

    group.bench_function("KEM Security Level 1 (ML-KEM-512)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem512::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem512::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem512::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem512::expose_shared(&ss1), MlKem512::expose_shared(&ss2));
            black_box(())
        })
    });

    group.bench_function("KEM Security Level 3 (ML-KEM-768)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem768::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(MlKem768::expose_shared(&ss1), MlKem768::expose_shared(&ss2));
            black_box(())
        })
    });

    group.bench_function("KEM Security Level 5 (ML-KEM-1024)", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem1024::keypair().expect("Failed to generate keypair");
            let (ct, ss1) = MlKem1024::encapsulate(&pk).expect("Failed to encapsulate");
            let ss2 = MlKem1024::decapsulate(&ct, &sk).expect("Failed to decapsulate");
            assert_eq!(
                MlKem1024::expose_shared(&ss1),
                MlKem1024::expose_shared(&ss2)
            );
            black_box(())
        })
    });

    group.bench_function("Signature Security Level 1 (Falcon-512)", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon512::keypair().expect("Key generation failed");
            let signature = Falcon512::sign(test_message, &sk).expect("Signing failed");
            let result = Falcon512::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Signature Security Level 2 (ML-DSA-44)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
            let signature = MlDsa44::sign(test_message, &sk).expect("Signing failed");
            let result = MlDsa44::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Signature Security Level 3 (ML-DSA-65)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
            let signature = MlDsa65::sign(test_message, &sk).expect("Signing failed");
            let result = MlDsa65::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Signature Security Level 5 (ML-DSA-87)", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair().expect("Key generation failed");
            let signature = MlDsa87::sign(test_message, &sk).expect("Signing failed");
            let result = MlDsa87::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("Signature Security Level 5 (Falcon-1024)", |b| {
        b.iter(|| {
            let (pk, sk) = Falcon1024::keypair().expect("Key generation failed");
            let signature = Falcon1024::sign(test_message, &sk).expect("Signing failed");
            let result = Falcon1024::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.finish();
}

/// Test hybrid algorithm performance overview
fn benchmark_hybrid_overview(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Algorithms Overview");
    let test_message = b"Hybrid algorithm test message";

    group.bench_function("ECC+Dilithium (Classical + ML-DSA-44)", |b| {
        b.iter(|| {
            let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
            let signature = EccDilithium::sign(test_message, &sk).expect("Hybrid signing failed");
            let result = EccDilithium::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+Falcon (Classical + Falcon-512)", |b| {
        b.iter(|| {
            let (pk, sk) = EccFalcon::keypair().expect("Hybrid key generation failed");
            let signature = EccFalcon::sign(test_message, &sk).expect("Hybrid signing failed");
            let result = EccFalcon::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("ECC+SPHINCS+ (Classical + SPHINCS+-SHAKE-128f)", |b| {
        b.iter(|| {
            let (pk, sk) = EccSphincs::keypair().expect("Hybrid key generation failed");
            let signature = EccSphincs::sign(test_message, &sk).expect("Hybrid signing failed");
            let result = EccSphincs::verify(test_message, &signature, &pk);
            assert!(result);
            black_box(())
        })
    });

    group.bench_function("P256+ML-KEM-768 (Hybrid KEM)", |b| {
        b.iter(|| {
            let (pk, sk) = P256MlKem768::keypair().expect("Hybrid KEM key generation failed");
            let (ct, ss1) = P256MlKem768::encapsulate(&pk).expect("Hybrid encapsulation failed");
            let ss2 = P256MlKem768::decapsulate(&ct, &sk).expect("Hybrid decapsulation failed");
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(
    master_benches,
    benchmark_quick_smoke_test,
    benchmark_security_level_overview,
    benchmark_hybrid_overview
);

criterion_main!(master_benches);
