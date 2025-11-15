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

#[cfg(feature = "optimized-variants")]
use cypheron_core::optimization::{
    global_cpu_capabilities, AlgorithmFactory, ConservativeStrategy, CpuCapabilities,
    OptimizationLevel, OptimizationStrategy, PerformanceStrategy,
};
use cypheron_core::prelude::*;
use std::time::Instant;

#[cfg(feature = "optimized-variants")]
fn demonstrate_cpu_detection() {
    println!("CPU Capability Detection");
    println!("========================");
    
    let capabilities = global_cpu_capabilities();
    println!("AVX2 support: {}", capabilities.has_avx2());
    println!("AES-NI support: {}", capabilities.has_aes_ni());
    println!("SSE2 support: {}", capabilities.has_sse2());
    println!("NEON support: {}", capabilities.has_neon());
    println!("X86 optimized: {}", capabilities.is_x86_optimized());
    println!("ARM optimized: {}", capabilities.is_arm_optimized());
    println!();
}

#[cfg(feature = "optimized-variants")]
fn demonstrate_optimization_strategies() {
    println!("Optimization Strategy Selection");
    println!("===============================");
    
    let capabilities = global_cpu_capabilities();
    let conservative = ConservativeStrategy;
    let performance = PerformanceStrategy;
    
    for level in [OptimizationLevel::Reference, OptimizationLevel::Optimized, OptimizationLevel::Aggressive] {
        println!("Level: {:?}", level);
        println!("  Conservative: {:?}", conservative.select_variant(level, capabilities));
        println!("  Performance:  {:?}", performance.select_variant(level, capabilities));
    }
    println!();
}

fn benchmark_algorithm<F: Fn() -> R, R>(name: &str, operation: F) -> R {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    println!("{}: {:.2?}", name, duration);
    result
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Cypheron Core Optimization Demonstration");
    println!("========================================");
    println!();

    #[cfg(feature = "optimized-variants")]
    {
        demonstrate_cpu_detection();
        demonstrate_optimization_strategies();
    }

    println!("Performance Benchmarks");
    println!("======================");

    println!("ML-KEM-768 Operations:");
    let (pk, sk) = benchmark_algorithm("Keypair Generation", || {
        MlKem768::keypair().expect("Keypair generation failed")
    });

    let (ciphertext, _shared_secret1) = benchmark_algorithm("Encapsulation", || {
        MlKem768::encapsulate(&pk).expect("Encapsulation failed")
    });

    let _shared_secret2 = benchmark_algorithm("Decapsulation", || {
        MlKem768::decapsulate(&ciphertext, &sk).expect("Decapsulation failed")
    });

    println!();
    println!("ML-DSA-44 Operations:");
    let (sig_pk, sig_sk) = benchmark_algorithm("Signature Keypair Generation", || {
        MlDsa44::keypair().expect("Signature keypair generation failed")
    });

    let message = b"Hello, post-quantum world!";
    let signature = benchmark_algorithm("Message Signing", || {
        MlDsa44::sign(message, &sig_sk).expect("Signing failed")
    });

    let is_valid = benchmark_algorithm("Signature Verification", || {
        MlDsa44::verify(message, &signature, &sig_pk)
    });

    println!("Signature valid: {}", is_valid);

    #[cfg(feature = "optimized-variants")]
    println!("\nNote: To see optimized performance, rebuild with --features optimized-variants");

    #[cfg(not(feature = "optimized-variants"))]
    println!("\nNote: Using reference implementations. Enable optimized-variants feature for better performance.");

    Ok(())
}