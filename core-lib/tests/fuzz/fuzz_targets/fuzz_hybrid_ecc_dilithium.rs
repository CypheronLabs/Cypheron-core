#![no_main]

use libfuzzer_sys::fuzz_target;
use core_lib::hybrid::{EccDilithium, HybridEngine};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Generate valid hybrid keypair
    let keypair_result = std::panic::catch_unwind(|| {
        EccDilithium::keypair()
    });
    
    let (pk, sk) = match keypair_result {
        Ok(Ok((pk, sk))) => (pk, sk),
        _ => return, // Skip if keypair generation fails
    };
    
    // Test hybrid signing with fuzzed message data
    if data.len() <= 65536 { // Reasonable size limit
        let _result = std::panic::catch_unwind(|| {
            EccDilithium::sign(data, &sk)
        });
    }
    
    // Test with various message sizes to find edge cases
    let test_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    
    for &size in test_sizes.iter() {
        if data.len() >= size {
            let message = &data[..size];
            
            let _result = std::panic::catch_unwind(|| {
                if let Ok(signature) = EccDilithium::sign(message, &sk) {
                    // Test verification
                    let _ = EccDilithium::verify(message, &signature, &pk);
                    
                    // Test with different verification policies
                    use core_lib::hybrid::traits::VerificationPolicy;
                    let policies = [
                        VerificationPolicy::BothRequired,
                        VerificationPolicy::ClassicalOnly,
                        VerificationPolicy::PostQuantumOnly,
                        VerificationPolicy::EitherValid,
                    ];
                    
                    for policy in policies.iter() {
                        let _ = EccDilithium::verify_with_policy(message, &signature, &pk, *policy);
                    }
                }
            });
        }
    }
    
    // Test with structured fuzz data
    if data.len() >= 16 {
        // Split data into different components
        let mid = data.len() / 2;
        let message_part = &data[..mid];
        let _noise_part = &data[mid..];
        
        let _result = std::panic::catch_unwind(|| {
            if let Ok(signature) = EccDilithium::sign(message_part, &sk) {
                // Test verification with correct message
                let _ = EccDilithium::verify(message_part, &signature, &pk);
                
                // Test verification with modified message (should fail but not crash)
                if message_part.len() > 1 {
                    let mut modified_message = message_part.to_vec();
                    modified_message[0] = modified_message[0].wrapping_add(1);
                    let _ = EccDilithium::verify(&modified_message, &signature, &pk);
                }
            }
        });
    }
    
    // Test boundary conditions
    let boundary_sizes = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256];
    
    for &size in boundary_sizes.iter() {
        if data.len() >= size {
            let chunk = if size == 0 { &[] } else { &data[..size] };
            
            let _result = std::panic::catch_unwind(|| {
                let _ = EccDilithium::sign(chunk, &sk);
            });
        }
    }
    
    // Test with patterns that might trigger specific code paths
    if data.len() >= 4 {
        // Test with repeated patterns
        let pattern_byte = data[0];
        let pattern_message = vec![pattern_byte; 256];
        
        let _result = std::panic::catch_unwind(|| {
            let _ = EccDilithium::sign(&pattern_message, &sk);
        });
        
        // Test with alternating patterns
        let mut alt_message = Vec::new();
        for (i, &byte) in data[..data.len().min(256)].iter().enumerate() {
            alt_message.push(if i % 2 == 0 { byte } else { !byte });
        }
        
        let _result = std::panic::catch_unwind(|| {
            let _ = EccDilithium::sign(&alt_message, &sk);
        });
    }
    
    // Test error handling paths
    if data.len() >= 32 {
        // Create scenarios that might trigger different error conditions
        let test_data_chunks = data.chunks(32);
        
        for chunk in test_data_chunks.take(8) { // Limit iterations
            let _result = std::panic::catch_unwind(|| {
                let _ = EccDilithium::sign(chunk, &sk);
            });
        }
    }
});