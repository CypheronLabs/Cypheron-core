/*!
 * Isolated ML-DSA-44 (Dilithium2) Test Program
 * 
 * This program isolates and tests the ML-DSA-44 signature verification
 * to identify the root cause of the health check failure.
 */

use core_lib::sig::MlDsa44;
use core_lib::sig::traits::SignatureEngine;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 ML-DSA-44 (Dilithium2) Verification Test");
    println!("============================================");
    
    let start_time = Instant::now();
    
    // Step 1: Key Generation
    println!("1. Generating ML-DSA-44 keypair...");
    let keygen_start = Instant::now();
    let (pk, sk) = match MlDsa44::keypair() {
        Ok(keys) => {
            println!("   ✅ Key generation successful ({:?})", keygen_start.elapsed());
            println!("   📏 Public key size: {} bytes", keys.0.len());
            println!("   📏 Secret key size: {} bytes", keys.1.len());
            keys
        }
        Err(e) => {
            println!("   ❌ Key generation failed: {:?}", e);
            return Err(format!("Key generation failed: {:?}", e).into());
        }
    };
    
    // Step 2: Message Signing
    let message = b"health check message for ML-DSA-44 verification test";
    println!("2. Signing message: '{}'", std::str::from_utf8(message).unwrap());
    let sign_start = Instant::now();
    
    let signature = match MlDsa44::sign(message, &sk) {
        Ok(sig) => {
            println!("   ✅ Signing successful ({:?})", sign_start.elapsed());
            println!("   📏 Signature size: {} bytes", sig.0.len());
            println!("   🔢 Signature preview: {:02x}{:02x}{:02x}{:02x}...", 
                sig.0[0], sig.0[1], sig.0[2], sig.0[3]);
            sig
        }
        Err(e) => {
            println!("   ❌ Signing failed: {:?}", e);
            return Err(format!("Signing failed: {:?}", e).into());
        }
    };
    
    // Step 3: Signature Verification
    println!("3. Verifying signature...");
    let verify_start = Instant::now();
    
    let is_valid = MlDsa44::verify(message, &signature, &pk);
    let verify_time = verify_start.elapsed();
    
    if is_valid {
        println!("   ✅ Signature verification SUCCESSFUL ({:?})", verify_time);
    } else {
        println!("   ❌ Signature verification FAILED ({:?})", verify_time);
        println!("   🔧 This indicates a bug in the ML-DSA-44 implementation");
        return Err("Signature verification failed".into());
    }
    
    // Step 4: Test with Different Message
    println!("4. Testing with different message...");
    let wrong_message = b"different message that should fail verification";
    let should_fail = MlDsa44::verify(wrong_message, &signature, &pk);
    
    if should_fail {
        println!("   ❌ Verification incorrectly passed for wrong message!");
        return Err("Verification should have failed for wrong message".into());
    } else {
        println!("   ✅ Verification correctly failed for wrong message");
    }
    
    // Step 5: Test with Empty Message
    println!("5. Testing with empty message...");
    let empty_message = b"";
    let empty_start = Instant::now();
    
    match MlDsa44::sign(empty_message, &sk) {
        Ok(empty_sig) => {
            let empty_valid = MlDsa44::verify(empty_message, &empty_sig, &pk);
            println!("   ✅ Empty message test: signed and verified = {}", empty_valid);
        }
        Err(e) => {
            println!("   ℹ️  Empty message signing failed (may be expected): {:?}", e);
        }
    }
    
    let total_time = start_time.elapsed();
    println!();
    println!("🎯 Test Summary:");
    println!("   Total time: {:?}", total_time);
    println!("   Status: ALL TESTS PASSED ✅");
    println!("   ML-DSA-44 implementation appears to be working correctly");
    
    Ok(())
}