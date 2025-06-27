use secrecy::ExposeSecret;
use core_lib::sig::falcon::falcon1024::api::Falcon1024;
use core_lib::sig::falcon::falcon1024::types::Signature;
use core_lib::sig::traits::SignatureEngine;
use core_lib::sig::falcon::falcon1024::constants::{
    FALCON_PUBLIC,
    FALCON_SECRET,
    FALCON_SIGNATURE,
};

const TEST_MESSAGE_FALCON1024: &[u8] = b"This is a test message for Falcon-1024 implementation.";

#[test]
fn falcon1024_test_keypair_generation_lengths() {
    let result = Falcon1024::keypair();
    assert!(result.is_ok(), "Falcon-1024: Keypair generation failed: {:?}", result.err());
    let (pk, sk) = result.unwrap();

    println!("Falcon-1024 Public Key (len={}): {:02x?}", pk.0.len(), &pk.0[..16]);
    println!("Falcon-1024 Secret Key (len={}): {:02x?}", sk.0.expose_secret().len(), &sk.0.expose_secret()[..16]);

    assert_eq!(pk.0.len(), FALCON_PUBLIC, "Falcon-1024: Public key length mismatch");
    assert_eq!(sk.0.expose_secret().len(), FALCON_SECRET, "Falcon-1024: Secret key length mismatch");
}

#[test]
fn falcon1024_test_sign_verify_roundtrip() {
    let keypair_result = Falcon1024::keypair();
    assert!(keypair_result.is_ok(), "Falcon-1024: Keypair generation failed for roundtrip: {:?}", keypair_result.err());
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon1024::sign(TEST_MESSAGE_FALCON1024, &sk);
    assert!(sign_result.is_ok(), "Falcon-1024: Signing failed: {:?}", sign_result.err());
    let signature = sign_result.unwrap();

    println!("Falcon-1024 Message: {:?}", std::str::from_utf8(TEST_MESSAGE_FALCON1024).unwrap_or("Invalid UTF-8"));
    println!("Falcon-1024 Signature (len={}): {:02x?}", signature.0.len(), &signature.0[..32]);
    
    // Find actual signature length 
    let mut actual_sig_len = signature.0.len();
    while actual_sig_len > 0 && signature.0[actual_sig_len - 1] == 0 {
        actual_sig_len -= 1;
    }
    println!("Falcon-1024 Actual Signature Length: {}", actual_sig_len);

    assert_eq!(signature.0.len(), FALCON_SIGNATURE, "Falcon-1024: Signature length mismatch");

    let is_valid = Falcon1024::verify(TEST_MESSAGE_FALCON1024, &signature, &pk);
    assert!(is_valid, "Falcon-1024: Verification failed for a valid signature");
}

#[test]
fn falcon1024_test_verify_failure_wrong_message() {
    let keypair_result = Falcon1024::keypair();
    assert!(keypair_result.is_ok(), "Falcon-1024: Keypair generation failed for wrong message test: {:?}", keypair_result.err());
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon1024::sign(TEST_MESSAGE_FALCON1024, &sk);
    assert!(sign_result.is_ok(), "Falcon-1024: Signing failed for wrong message test: {:?}", sign_result.err());
    let signature = sign_result.unwrap();

    let wrong_message: &[u8] = b"This is definitely not the original message for Falcon-1024.";
    let is_valid = Falcon1024::verify(wrong_message, &signature, &pk);

    assert!(!is_valid, "Falcon-1024: Verification should fail for a wrong message");
}

#[test]
fn falcon1024_test_verify_failure_wrong_public_key() {
    let keypair1_result = Falcon1024::keypair();
    assert!(keypair1_result.is_ok(), "Falcon-1024: Keypair 1 generation failed: {:?}", keypair1_result.err());
    let (_pk1, sk1) = keypair1_result.unwrap();

    let keypair2_result = Falcon1024::keypair();
    assert!(keypair2_result.is_ok(), "Falcon-1024: Keypair 2 generation failed: {:?}", keypair2_result.err());
    let (pk2, _sk2) = keypair2_result.unwrap();

    let sign_result = Falcon1024::sign(TEST_MESSAGE_FALCON1024, &sk1);
    assert!(sign_result.is_ok(), "Falcon-1024: Signing with sk1 failed: {:?}", sign_result.err());
    let signature = sign_result.unwrap();

    let is_valid = Falcon1024::verify(TEST_MESSAGE_FALCON1024, &signature, &pk2);
    assert!(!is_valid, "Falcon-1024: Verification should fail for a wrong public key");
}

#[test]
fn falcon1024_test_verify_failure_corrupted_signature() {
    let keypair_result = Falcon1024::keypair(); 
    assert!(keypair_result.is_ok(), "Falcon-1024: Keypair generation failed for corrupted sig test: {:?}", keypair_result.err());
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon1024::sign(TEST_MESSAGE_FALCON1024, &sk); 
    assert!(sign_result.is_ok(), "Falcon-1024: Signing failed for corrupted sig test: {:?}", sign_result.err());

    let signature_instance = sign_result.unwrap(); 
    let mut signature_array: [u8; 1462] = signature_instance.0;

    if FALCON_SIGNATURE > 0 {
        signature_array[0] ^= 0x01;
    } else {
        panic!("Falcon-1024: FALCON_SIGNATURE constant is 0, cannot corrupt meaningfully");
    }

    let corrupted_signature: Signature<1462> = Signature(signature_array);

    let is_valid = Falcon1024::verify(TEST_MESSAGE_FALCON1024, &corrupted_signature, &pk);
    assert!(!is_valid, "Falcon-1024: Verification should fail for a corrupted signature");
}