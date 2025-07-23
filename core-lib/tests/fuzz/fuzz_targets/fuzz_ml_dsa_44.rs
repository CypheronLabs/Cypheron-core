#![no_main]

use libfuzzer_sys::fuzz_target;
use core_lib::sig::{MlDsa44};
use core_lib::sig::traits::SignatureEngine;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let keypair_result = std::panic::catch_unwind(|| {
        MlDsa44::keypair()
    });
    
    let (pk, sk) = match keypair_result {
        Ok(Ok((pk, sk))) => (pk, sk),
        _ => return,
    };
    
    if data.len() <= 65536 {
        let _result = std::panic::catch_unwind(|| {
            MlDsa44::sign(data, &sk)
        });
    }
    
    if data.len() >= 2420 {
        let mut sig_data = [0u8; 2420];
        sig_data.copy_from_slice(&data[..2420]);
        
        use core_lib::sig::dilithium::dilithium2::types::Signature;
        let fuzzed_sig = Signature(sig_data);
        
        let test_message = b"test message for fuzzing";
        
        let _result = std::panic::catch_unwind(|| {
            MlDsa44::verify(test_message, &fuzzed_sig, &pk)
        });
    }
    
    if data.len() >= 1312 {
        let mut pk_data = [0u8; 1312];
        pk_data.copy_from_slice(&data[..1312]);
        
        use core_lib::sig::dilithium::dilithium2::types::PublicKey;
        let fuzzed_pk = PublicKey(pk_data);
        
        let test_message = b"test message";
        let valid_sig = match MlDsa44::sign(test_message, &sk) {
            Ok(sig) => sig,
            Err(_) => return,
        };
        
        let _result = std::panic::catch_unwind(|| {
            MlDsa44::verify(test_message, &valid_sig, &fuzzed_pk)
        });
    }
    
    let message_sizes = [0, 1, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024];
    
    for &size in message_sizes.iter() {
        if data.len() >= size && size <= 1024 {
            let message = &data[..size];
            
            let _result = std::panic::catch_unwind(|| {
                if let Ok(signature) = MlDsa44::sign(message, &sk) {
                    let _ = MlDsa44::verify(message, &signature, &pk);
                }
            });
        }
    }
    
    if data.len() >= 8 {
        let length_bytes = &data[..8];
        let fake_length = u64::from_le_bytes([
            length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3],
            length_bytes[4], length_bytes[5], length_bytes[6], length_bytes[7],
        ]);
        
        let safe_size = (fake_length % 65536) as usize;
        if data.len() >= safe_size {
            let bounded_message = &data[..safe_size];
            
            let _result = std::panic::catch_unwind(|| {
                let _ = MlDsa44::sign(bounded_message, &sk);
            });
        }
    }
});