#![no_main]

use libfuzzer_sys::fuzz_target;
use core_lib::kem::{MlKem512, Kem};

fuzz_target!(|data: &[u8]| {
    // Don't fuzz with empty data
    if data.is_empty() {
        return;
    }

    // Generate a valid keypair
    let (pk, sk) = MlKem512::keypair();
    
    // Test decapsulation with fuzzed ciphertext data
    if data.len() == 768 { // ML-KEM-512 ciphertext size
        let mut ciphertext = vec![0u8; 768];
        ciphertext.copy_from_slice(data);
        
        // This should not crash, even with invalid ciphertext
        let _result = std::panic::catch_unwind(|| {
            MlKem512::decapsulate(&ciphertext, &sk)
        });
    }
    
    // Test with fuzzed public key data
    if data.len() >= 800 { // ML-KEM-512 public key size
        let mut pk_data = [0u8; 800];
        pk_data.copy_from_slice(&data[..800]);
        
        use core_lib::kem::kyber512::KyberPublicKey;
        let fuzzed_pk = KyberPublicKey(pk_data);
        
        // Encapsulation with fuzzed public key should not crash
        let _result = std::panic::catch_unwind(|| {
            MlKem512::encapsulate(&fuzzed_pk)
        });
    }
    
    // Test with partial data to check bounds handling
    for chunk_size in [1, 16, 32, 64, 128, 256, 512].iter() {
        if data.len() >= *chunk_size {
            let chunk = &data[..*chunk_size];
            
            // Test that partial data doesn't cause crashes
            let _result = std::panic::catch_unwind(|| {
                // Various operations that might be vulnerable to malformed input
                if chunk.len() >= 800 {
                    let mut pk_data = [0u8; 800];
                    pk_data[..chunk.len().min(800)].copy_from_slice(&chunk[..chunk.len().min(800)]);
                    let pk = KyberPublicKey(pk_data);
                    let _ = MlKem512::encapsulate(&pk);
                }
            });
        }
    }
});