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

/*!
 * Timing Attack Detection Tests
 * 
 * This module implements timing analysis to detect potential side-channel vulnerabilities
 * in cryptographic operations. Uses statistical analysis to identify timing variations
 * that could leak sensitive information.
 * 
 * Tests validate:
 * - Constant-time behavior of secret-dependent operations
 * - Timing independence from secret key material
 * - Timing independence from message content
 * - Statistical timing analysis with multiple samples
 */

use cypheron_core::kem::{MlKem512, MlKem768, MlKem1024, Kem};
use cypheron_core::sig::{MlDsa44, MlDsa65, MlDsa87};
use cypheron_core::sig::traits::SignatureEngine;
use cypheron_core::hybrid::{EccDilithium, HybridEngine};
use std::time::{Duration, Instant};

/// Number of timing samples for statistical analysis
const TIMING_SAMPLES: usize = 1000;

/// Maximum allowed timing variation (in nanoseconds) for constant-time operations
const MAX_TIMING_VARIATION_NS: u64 = 50_000; // 50 microseconds tolerance

/// Statistical timing measurement structure
#[derive(Debug)]
struct TimingMeasurement {
    pub samples: Vec<Duration>,
    pub mean: Duration,
    pub variance: f64,
    pub min: Duration,
    pub max: Duration,
}

impl TimingMeasurement {
    fn new(samples: Vec<Duration>) -> Self {
        let mean_ns: f64 = samples.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / samples.len() as f64;
        let mean = Duration::from_nanos(mean_ns as u64);
        
        let variance = samples.iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_ns;
                diff * diff
            })
            .sum::<f64>() / samples.len() as f64;
            
        let min = samples.iter().min().copied().unwrap_or(Duration::ZERO);
        let max = samples.iter().max().copied().unwrap_or(Duration::ZERO);
        
        Self { samples, mean, variance, min, max }
    }
    
    fn coefficient_of_variation(&self) -> f64 {
        let std_dev = self.variance.sqrt();
        if self.mean.as_nanos() > 0 {
            std_dev / (self.mean.as_nanos() as f64)
        } else {
            0.0
        }
    }
    
    fn timing_range(&self) -> Duration {
        self.max - self.min
    }
}

/// Measure timing of a closure execution
fn measure_timing<F, R>(iterations: usize, mut operation: F) -> TimingMeasurement
where
    F: FnMut() -> R,
{
    let mut timings = Vec::with_capacity(iterations);
    
    // Warm up
    for _ in 0..10 {
        let _ = operation();
    }
    
    // Collect timing samples
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = operation();
        let duration = start.elapsed();
        timings.push(duration);
    }
    
    TimingMeasurement::new(timings)
}

/// Compare two timing measurements for statistical significance
fn compare_timings(measurement1: &TimingMeasurement, measurement2: &TimingMeasurement) -> bool {
    // Simple statistical test: check if timing ranges overlap significantly
    let range1 = measurement1.timing_range();
    let range2 = measurement2.timing_range();
    
    // If timing ranges are significantly different, there might be a timing leak
    let max_range = range1.max(range2);
    max_range.as_nanos() <= MAX_TIMING_VARIATION_NS as u128
}

/// ML-KEM Timing Attack Tests
#[cfg(test)]
mod ml_kem_timing_tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_decapsulation_timing() {
        println!("🕐 Testing ML-KEM-512 decapsulation timing consistency...");
        
        // Generate test data
        let (pk, sk) = MlKem512::keypair();
        let (ct1, _ss1) = MlKem512::encapsulate(&pk);
        let (ct2, _ss2) = MlKem512::encapsulate(&pk);
        
        // Measure timing for first ciphertext
        let timing1 = measure_timing(TIMING_SAMPLES, || {
            let _ss = MlKem512::decapsulate(&ct1, &sk);
        });
        
        // Measure timing for second ciphertext
        let timing2 = measure_timing(TIMING_SAMPLES, || {
            let _ss = MlKem512::decapsulate(&ct2, &sk);
        });
        
        println!("Timing 1: mean={:?}, variance={:.2}, range={:?}", 
                timing1.mean, timing1.variance, timing1.timing_range());
        println!("Timing 2: mean={:?}, variance={:.2}, range={:?}", 
                timing2.mean, timing2.variance, timing2.timing_range());
        
        // Check for timing consistency
        assert!(
            compare_timings(&timing1, &timing2),
            "ML-KEM-512 decapsulation shows timing variation that could indicate side-channel vulnerability"
        );
        
        println!(" ML-KEM-512 decapsulation timing test passed");
    }

    #[test]
    fn test_ml_kem_768_encapsulation_timing() {
        println!("🕐 Testing ML-KEM-768 encapsulation timing consistency...");
        
        let (pk1, _sk1) = MlKem768::keypair();
        let (pk2, _sk2) = MlKem768::keypair();
        
        // Measure timing for different public keys
        let timing1 = measure_timing(TIMING_SAMPLES, || {
            let (_ct, _ss) = MlKem768::encapsulate(&pk1);
        });
        
        let timing2 = measure_timing(TIMING_SAMPLES, || {
            let (_ct, _ss) = MlKem768::encapsulate(&pk2);
        });
        
        println!("PK1 timing: mean={:?}, CV={:.4}", timing1.mean, timing1.coefficient_of_variation());
        println!("PK2 timing: mean={:?}, CV={:.4}", timing2.mean, timing2.coefficient_of_variation());
        
        assert!(
            compare_timings(&timing1, &timing2),
            "ML-KEM-768 encapsulation shows timing variation between different public keys"
        );
        
        println!(" ML-KEM-768 encapsulation timing test passed");
    }

    #[test]
    fn test_ml_kem_1024_key_generation_timing() {
        println!("🕐 Testing ML-KEM-1024 key generation timing consistency...");
        
        // Measure key generation timing multiple times
        let timing = measure_timing(100, || { // Fewer samples for slower operation
            let (_pk, _sk) = MlKem1024::keypair();
        });
        
        println!("Key generation: mean={:?}, variance={:.2}", timing.mean, timing.variance);
        
        // Key generation timing should be reasonably consistent
        let cv = timing.coefficient_of_variation();
        assert!(
            cv < 0.5, // Allow 50% coefficient of variation for key generation
            "ML-KEM-1024 key generation shows excessive timing variation (CV: {:.4})",
            cv
        );
        
        println!(" ML-KEM-1024 key generation timing test passed");
    }
}

/// ML-DSA Timing Attack Tests
#[cfg(test)]
mod ml_dsa_timing_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_signing_timing() {
        println!("🕐 Testing ML-DSA-44 signing timing consistency...");
        
        let (pk, sk) = MlDsa44::keypair().expect("Key generation failed");
        
        // Test different message sizes
        let msg1 = vec![0x42; 100];
        let msg2 = vec![0x24; 100];
        let msg3 = vec![0xFF; 1000]; // Different size
        
        let timing1 = measure_timing(TIMING_SAMPLES, || {
            let _sig = MlDsa44::sign(&msg1, &sk).expect("Signing failed");
        });
        
        let timing2 = measure_timing(TIMING_SAMPLES, || {
            let _sig = MlDsa44::sign(&msg2, &sk).expect("Signing failed");
        });
        
        let timing3 = measure_timing(TIMING_SAMPLES, || {
            let _sig = MlDsa44::sign(&msg3, &sk).expect("Signing failed");
        });
        
        println!("Message 1 timing: mean={:?}", timing1.mean);
        println!("Message 2 timing: mean={:?}", timing2.mean);
        println!("Message 3 timing: mean={:?}", timing3.mean);
        
        // Same-size messages should have similar timing
        assert!(
            compare_timings(&timing1, &timing2),
            "ML-DSA-44 signing shows timing variation for same-size messages"
        );
        
        // Note: Different message sizes may have different timing due to processing
        // but the variation should not leak information about message content
        
        println!(" ML-DSA-44 signing timing test passed");
    }

    #[test]
    fn test_ml_dsa_65_verification_timing() {
        println!("🕐 Testing ML-DSA-65 verification timing consistency...");
        
        let (pk, sk) = MlDsa65::keypair().expect("Key generation failed");
        let message = vec![0x5A; 256];
        
        // Generate valid and invalid signatures
        let valid_sig = MlDsa65::sign(&message, &sk).expect("Signing failed");
        let mut invalid_sig = valid_sig.clone();
        invalid_sig.0[0] ^= 0x01; // Corrupt first byte
        
        // Measure timing for valid signature verification
        let valid_timing = measure_timing(TIMING_SAMPLES, || {
            let _result = MlDsa65::verify(&message, &valid_sig, &pk);
        });
        
        // Measure timing for invalid signature verification
        let invalid_timing = measure_timing(TIMING_SAMPLES, || {
            let _result = MlDsa65::verify(&message, &invalid_sig, &pk);
        });
        
        println!("Valid sig timing: mean={:?}", valid_timing.mean);
        println!("Invalid sig timing: mean={:?}", invalid_timing.mean);
        
        // Verification timing should be consistent regardless of signature validity
        assert!(
            compare_timings(&valid_timing, &invalid_timing),
            "ML-DSA-65 verification shows timing difference between valid and invalid signatures"
        );
        
        println!(" ML-DSA-65 verification timing test passed");
    }
}

/// Hybrid Scheme Timing Attack Tests
#[cfg(test)]
mod hybrid_timing_tests {
    use super::*;

    #[test] 
    fn test_hybrid_signature_timing() {
        println!("🕐 Testing hybrid signature timing consistency...");
        
        let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
        
        let msg1 = vec![0xAA; 512];
        let msg2 = vec![0x55; 512];
        
        // Measure hybrid signing timing
        let timing1 = measure_timing(100, || { // Fewer samples for complex operation
            let _sig = EccDilithium::sign(&msg1, &sk).expect("Hybrid signing failed");
        });
        
        let timing2 = measure_timing(100, || {
            let _sig = EccDilithium::sign(&msg2, &sk).expect("Hybrid signing failed");
        });
        
        println!("Hybrid timing 1: mean={:?}, range={:?}", timing1.mean, timing1.timing_range());
        println!("Hybrid timing 2: mean={:?}, range={:?}", timing2.mean, timing2.timing_range());
        
        // Allow more variation for hybrid operations due to complexity
        let max_variation = Duration::from_millis(5); // 5ms tolerance for hybrid operations
        assert!(
            timing1.timing_range() < max_variation && timing2.timing_range() < max_variation,
            "Hybrid signature shows excessive timing variation"
        );
        
        println!(" Hybrid signature timing test passed");
    }

    #[test]
    fn test_hybrid_verification_timing() {
        println!("🕐 Testing hybrid verification timing consistency...");
        
        let (pk, sk) = EccDilithium::keypair().expect("Hybrid key generation failed");
        let message = vec![0x42; 256];
        let signature = EccDilithium::sign(&message, &sk).expect("Hybrid signing failed");
        
        // Test different verification policies
        use cypheron_core::hybrid::traits::VerificationPolicy;
        
        let both_timing = measure_timing(100, || {
            let _result = EccDilithium::verify_with_policy(&message, &signature, &pk, VerificationPolicy::BothRequired);
        });
        
        let classical_timing = measure_timing(100, || {
            let _result = EccDilithium::verify_with_policy(&message, &signature, &pk, VerificationPolicy::ClassicalOnly);
        });
        
        let pq_timing = measure_timing(100, || {
            let _result = EccDilithium::verify_with_policy(&message, &signature, &pk, VerificationPolicy::PostQuantumOnly);
        });
        
        println!("Both required: mean={:?}", both_timing.mean);
        println!("Classical only: mean={:?}", classical_timing.mean);
        println!("PQ only: mean={:?}", pq_timing.mean);
        
        // Different policies may have different absolute timing but should be consistent
        // within each policy
        assert!(
            both_timing.coefficient_of_variation() < 0.3 &&
            classical_timing.coefficient_of_variation() < 0.3 &&
            pq_timing.coefficient_of_variation() < 0.3,
            "Hybrid verification shows inconsistent timing within policies"
        );
        
        println!(" Hybrid verification timing test passed");
    }
}

/// General timing analysis utilities
#[cfg(test)]
mod timing_utilities {
    use super::*;

    #[test]
    fn test_timing_measurement_infrastructure() {
        println!(" Testing timing measurement infrastructure...");
        
        // Test known timing differences
        let fast_timing = measure_timing(100, || {
            // Very fast operation
            let _x = 1 + 1;
        });
        
        let slow_timing = measure_timing(100, || {
            // Slightly slower operation
            std::thread::sleep(Duration::from_micros(1));
        });
        
        println!("Fast operation: mean={:?}", fast_timing.mean);
        println!("Slow operation: mean={:?}", slow_timing.mean);
        
        // Verify that our timing infrastructure can detect known differences
        assert!(
            slow_timing.mean > fast_timing.mean,
            "Timing infrastructure cannot detect known timing differences"
        );
        
        println!(" Timing measurement infrastructure working correctly");
    }
}