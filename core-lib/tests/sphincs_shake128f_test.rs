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

use cypheron_core::sig::sphincs::errors::SphincsError;
use cypheron_core::sig::sphincs::shake_128f::api::*;
use cypheron_core::sig::sphincs::shake_128f::types;

const TEST_MESSAGE: &[u8] = b"This is a test message for SPHINCS+ SHAKE-192f.";

#[test]
fn shake192f_test_keypair_generation_lengths() {
    let (pk, sk) = keypair().expect("Keypair generation failed");

    assert_eq!(pk.as_bytes().len(), public_key_bytes(), "Public key length mismatch");
    assert_eq!(sk.as_bytes().len(), secret_key_bytes(), "Secret key length mismatch");

    assert_eq!(
        pk.as_bytes().len(),
        types::PublicKey::length(),
        "Public key type length() mismatch"
    );
    assert_eq!(
        sk.as_bytes().len(),
        types::SecretKey::length(),
        "Secret key type length() mismatch"
    );
}

#[test]
fn shake192f_test_keypair_from_seed_lengths_and_determinism() {
    let seed_len = seed_bytes();
    let seed_data1: Vec<u8> = (0..seed_len).map(|i| (i % 256) as u8).collect();
    let seed_data2: Vec<u8> = (0..seed_len).map(|i| ((i + 1) % 256) as u8).collect();

    let (pk1_s1, sk1_s1) = keypair_from_seed(&seed_data1).expect("Keypair from seed 1 failed");
    assert_eq!(pk1_s1.as_bytes().len(), public_key_bytes());
    assert_eq!(sk1_s1.as_bytes().len(), secret_key_bytes());

    let (pk2_s1, sk2_s1) =
        keypair_from_seed(&seed_data1).expect("Keypair from seed 1 (deterministic) failed");
    assert_eq!(
        pk1_s1.as_bytes(),
        pk2_s1.as_bytes(),
        "Public keys from same seed should be identical"
    );
    assert_eq!(
        sk1_s1.as_bytes(),
        sk2_s1.as_bytes(),
        "Secret keys from same seed should be identical"
    );

    let (pk_s2, _sk_s2) = keypair_from_seed(&seed_data2).expect("Keypair from seed 2 failed");
    assert_ne!(
        pk1_s1.as_bytes(),
        pk_s2.as_bytes(),
        "Public keys from different seeds should be different"
    );
}

#[test]
fn shake192f_test_sign_verify_detached_roundtrip() {
    let (pk, sk) = keypair().expect("Keypair generation failed");

    let signature = sign_detached(TEST_MESSAGE, &sk).expect("Signing failed");
    assert_eq!(signature.as_bytes().len(), signature_bytes());
    assert_eq!(signature.as_bytes().len(), types::Signature::length());

    let verification_result = verify_detached(&signature, TEST_MESSAGE, &pk);
    assert!(
        verification_result.is_ok(),
        "Verification failed for a valid signature: {:?}",
        verification_result.err()
    );
}

#[test]
fn shake192f_test_verify_detached_failure_wrong_message() {
    let (pk, sk) = keypair().expect("Keypair generation failed");
    let signature = sign_detached(TEST_MESSAGE, &sk).expect("Signing failed");

    let wrong_message: &[u8] = b"This is a different message.";
    let verification_result = verify_detached(&signature, wrong_message, &pk);

    assert!(verification_result.is_err(), "Verification should fail for a wrong message");
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => {}
        e => panic!("Unexpected error type for wrong message: {:?}", e),
    }
}

#[test]
fn shake192f_test_verify_detached_failure_wrong_public_key() {
    let (_pk1, sk1) = keypair().expect("Keypair 1 generation failed");
    let (pk2, _sk2) = keypair().expect("Keypair 2 generation failed");

    let signature = sign_detached(TEST_MESSAGE, &sk1).expect("Signing with sk1 failed");

    let verification_result = verify_detached(&signature, TEST_MESSAGE, &pk2);
    assert!(verification_result.is_err(), "Verification should fail for a wrong public key");
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => { /* Expected error */ }
        e => panic!("Unexpected error type for wrong public key: {:?}", e),
    }
}

#[test]
fn shake192f_test_verify_detached_failure_corrupted_signature() {
    let (pk, sk) = keypair().expect("Keypair generation failed");
    let mut signature_bytes_vec =
        sign_detached(TEST_MESSAGE, &sk).expect("Signing failed").as_bytes().to_vec();

    if !signature_bytes_vec.is_empty() {
        signature_bytes_vec[0] ^= 0x01;
    } else {
        panic!("Signature is empty, cannot corrupt");
    }
    let corrupted_signature = types::Signature::from_bytes(&signature_bytes_vec).unwrap();

    let verification_result = verify_detached(&corrupted_signature, TEST_MESSAGE, &pk);
    assert!(verification_result.is_err(), "Verification should fail for a corrupted signature");
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => { /* Expected error */ }
        e => panic!("Unexpected error type for corrupted signature: {:?}", e),
    }
}

#[test]
fn shake192f_test_sign_open_combined_roundtrip() {
    let (pk, sk) = keypair().expect("Keypair generation failed");

    let signed_message = sign_combined(TEST_MESSAGE, &sk).expect("Combined signing failed");

    assert!(signed_message.len() > TEST_MESSAGE.len());
    assert_eq!(signed_message.len(), TEST_MESSAGE.len() + signature_bytes());

    let opened_message_result = open_combined(&signed_message, &pk);
    assert!(
        opened_message_result.is_ok(),
        "Opening combined message failed: {:?}",
        opened_message_result.err()
    );

    let opened_message = opened_message_result.unwrap();
    assert_eq!(opened_message, TEST_MESSAGE, "Opened message does not match original message");
}

#[test]
fn shake192f_test_open_combined_failure_wrong_pk() {
    let (_pk1, sk1) = keypair().expect("Keypair 1 generation failed");
    let (pk2, _sk2) = keypair().expect("Keypair 2 generation failed");

    let signed_message = sign_combined(TEST_MESSAGE, &sk1).expect("Combined signing failed");

    let opened_message_result = open_combined(&signed_message, &pk2);
    assert!(opened_message_result.is_err(), "Opening combined message should fail with wrong PK");
    match opened_message_result.err().unwrap() {
        SphincsError::OpenFailed(_) => { /* Expected error */ }
        e => panic!("Unexpected error type for open_combined with wrong PK: {:?}", e),
    }
}

#[test]
fn shake192f_test_invalid_seed_length() {
    let seed_len = seed_bytes();
    let invalid_seed_data: Vec<u8> = (0..seed_len.saturating_sub(1)).map(|i| i as u8).collect();

    if seed_len > 0 {
        let result = keypair_from_seed(&invalid_seed_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            SphincsError::InvalidSeedLength { expected, actual } => {
                assert_eq!(expected, seed_len);
                assert_eq!(actual, invalid_seed_data.len());
            }
            e => panic!("Unexpected error type for invalid seed length: {:?}", e),
        }
    }
}
