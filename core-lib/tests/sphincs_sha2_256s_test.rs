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

use core_lib::sig::sphincs::errors::SphincsError;
use core_lib::sig::sphincs::sha2_256s::api::*;
use core_lib::sig::sphincs::sha2_256s::types;

const TEST_MESSAGE_SHA2_256S: &[u8] = b"This is a test message for SPHINCS+ SHA2-256s.";

#[test]
fn sha2256s_test_keypair_generation_lengths() {
    let (pk, sk) = keypair().expect("SHA2-256s: Keypair generation failed");

    assert_eq!(pk.as_bytes().len(), public_key_bytes(), "SHA2-256s: Public key length mismatch");
    assert_eq!(sk.as_bytes().len(), secret_key_bytes(), "SHA2-256s: Secret key length mismatch");

    assert_eq!(
        pk.as_bytes().len(),
        types::PublicKey::length(),
        "SHA2-256s: Public key type length() mismatch"
    );
    assert_eq!(
        sk.as_bytes().len(),
        types::SecretKey::length(),
        "SHA2-256s: Secret key type length() mismatch"
    );
}

#[test]
fn sha2256s_test_keypair_from_seed_lengths_and_determinism() {
    let seed_len = seed_bytes();
    let seed_data1: Vec<u8> = (0..seed_len).map(|i| (i % 256) as u8).collect();
    let seed_data2: Vec<u8> = (0..seed_len).map(|i| ((i + 1) % 256) as u8).collect();

    let (pk1_s1, sk1_s1) =
        keypair_from_seed(&seed_data1).expect("SHA2-256s: Keypair from seed 1 failed");
    assert_eq!(
        pk1_s1.as_bytes().len(),
        public_key_bytes(),
        "SHA2-256s: PK length from seed mismatch"
    );
    assert_eq!(
        sk1_s1.as_bytes().len(),
        secret_key_bytes(),
        "SHA2-256s: SK length from seed mismatch"
    );

    let (pk2_s1, sk2_s1) = keypair_from_seed(&seed_data1)
        .expect("SHA2-256s: Keypair from seed 1 (deterministic) failed");
    assert_eq!(
        pk1_s1.as_bytes(),
        pk2_s1.as_bytes(),
        "SHA2-256s: Public keys from same seed should be identical"
    );
    assert_eq!(
        sk1_s1.as_bytes(),
        sk2_s1.as_bytes(),
        "SHA2-256s: Secret keys from same seed should be identical"
    );

    let (pk_s2, _sk_s2) =
        keypair_from_seed(&seed_data2).expect("SHA2-256s: Keypair from seed 2 failed");
    assert_ne!(
        pk1_s1.as_bytes(),
        pk_s2.as_bytes(),
        "SHA2-256s: Public keys from different seeds should be different"
    );
}

#[test]
fn sha2256s_test_sign_verify_detached_roundtrip() {
    let (pk, sk) = keypair().expect("SHA2-256s: Keypair generation failed");

    let signature = sign_detached(TEST_MESSAGE_SHA2_256S, &sk).expect("SHA2-256s: Signing failed");
    assert_eq!(
        signature.as_bytes().len(),
        signature_bytes(),
        "SHA2-256s: Signature length mismatch"
    );
    assert_eq!(
        signature.as_bytes().len(),
        types::Signature::length(),
        "SHA2-256s: Signature type length() mismatch"
    );

    let verification_result = verify_detached(&signature, TEST_MESSAGE_SHA2_256S, &pk);
    assert!(
        verification_result.is_ok(),
        "SHA2-256s: Verification failed for a valid signature: {:?}",
        verification_result.err()
    );
}

#[test]
fn sha2256s_test_verify_detached_failure_wrong_message() {
    let (pk, sk) = keypair().expect("SHA2-256s: Keypair generation failed");
    let signature = sign_detached(TEST_MESSAGE_SHA2_256S, &sk).expect("SHA2-256s: Signing failed");

    let wrong_message: &[u8] = b"This is a different message for SHA2-256s.";
    let verification_result = verify_detached(&signature, wrong_message, &pk);

    assert!(
        verification_result.is_err(),
        "SHA2-256s: Verification should fail for a wrong message"
    );
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => { /* Expected error */ }
        e => panic!("SHA2-256s: Unexpected error type for wrong message: {:?}", e),
    }
}

#[test]
fn sha2256s_test_verify_detached_failure_wrong_public_key() {
    let (_pk1, sk1) = keypair().expect("SHA2-256s: Keypair 1 generation failed");
    let (pk2, _sk2) = keypair().expect("SHA2-256s: Keypair 2 generation failed");

    let signature =
        sign_detached(TEST_MESSAGE_SHA2_256S, &sk1).expect("SHA2-256s: Signing with sk1 failed");

    let verification_result = verify_detached(&signature, TEST_MESSAGE_SHA2_256S, &pk2);
    assert!(
        verification_result.is_err(),
        "SHA2-256s: Verification should fail for a wrong public key"
    );
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => { /* Expected error */ }
        e => panic!("SHA2-256s: Unexpected error type for wrong public key: {:?}", e),
    }
}

#[test]
fn sha2256s_test_verify_detached_failure_corrupted_signature() {
    let (pk, sk) = keypair().expect("SHA2-256s: Keypair generation failed");
    let mut signature_bytes_vec = sign_detached(TEST_MESSAGE_SHA2_256S, &sk)
        .expect("SHA2-256s: Signing failed")
        .as_bytes()
        .to_vec();

    if !signature_bytes_vec.is_empty() {
        signature_bytes_vec[0] ^= 0x01;
    } else {
        panic!("SHA2-256s: Signature is empty, cannot corrupt");
    }
    let corrupted_signature = types::Signature::from_bytes(&signature_bytes_vec).unwrap();

    let verification_result = verify_detached(&corrupted_signature, TEST_MESSAGE_SHA2_256S, &pk);
    assert!(
        verification_result.is_err(),
        "SHA2-256s: Verification should fail for a corrupted signature"
    );
    match verification_result.err().unwrap() {
        SphincsError::VerificationFailed => { /* Expected error */ }
        e => panic!("SHA2-256s: Unexpected error type for corrupted signature: {:?}", e),
    }
}

#[test]
fn sha2256s_test_sign_open_combined_roundtrip() {
    let (pk, sk) = keypair().expect("SHA2-256s: Keypair generation failed");

    let signed_message =
        sign_combined(TEST_MESSAGE_SHA2_256S, &sk).expect("SHA2-256s: Combined signing failed");

    assert!(
        signed_message.len() > TEST_MESSAGE_SHA2_256S.len(),
        "SHA2-256s: Combined message should be longer"
    );
    assert_eq!(
        signed_message.len(),
        TEST_MESSAGE_SHA2_256S.len() + signature_bytes(),
        "SHA2-256s: Combined message length incorrect"
    );

    let opened_message_result = open_combined(&signed_message, &pk);
    assert!(
        opened_message_result.is_ok(),
        "SHA2-256s: Opening combined message failed: {:?}",
        opened_message_result.err()
    );

    let opened_message = opened_message_result.unwrap();
    assert_eq!(
        opened_message, TEST_MESSAGE_SHA2_256S,
        "SHA2-256s: Opened message does not match original message"
    );
}

#[test]
fn sha2256s_test_open_combined_failure_wrong_pk() {
    let (_pk1, sk1) = keypair().expect("SHA2-256s: Keypair 1 generation failed");
    let (pk2, _sk2) = keypair().expect("SHA2-256s: Keypair 2 generation failed");

    let signed_message =
        sign_combined(TEST_MESSAGE_SHA2_256S, &sk1).expect("SHA2-256s: Combined signing failed");

    let opened_message_result = open_combined(&signed_message, &pk2);
    assert!(
        opened_message_result.is_err(),
        "SHA2-256s: Opening combined message should fail with wrong PK"
    );
    match opened_message_result.err().unwrap() {
        SphincsError::OpenFailed(_) => { /* Expected error */ }
        e => panic!("SHA2-256s: Unexpected error type for open_combined with wrong PK: {:?}", e),
    }
}

#[test]
fn sha2256s_test_invalid_seed_length() {
    let seed_len = seed_bytes();
    let invalid_seed_data: Vec<u8> = (0..seed_len.saturating_sub(1)).map(|i| i as u8).collect();

    if seed_len > 0 {
        let result = keypair_from_seed(&invalid_seed_data);
        assert!(result.is_err(), "SHA2-256s: keypair_from_seed should fail with short seed");
        match result.err().unwrap() {
            SphincsError::InvalidSeedLength { expected, actual } => {
                assert_eq!(expected, seed_len, "SHA2-256s: Expected seed length mismatch in error");
                assert_eq!(
                    actual,
                    invalid_seed_data.len(),
                    "SHA2-256s: Actual seed length mismatch in error"
                );
            }
            e => panic!("SHA2-256s: Unexpected error type for invalid seed length: {:?}", e),
        }
    } else {
        println!("SHA2-256s: Seed length is 0, skipping invalid_seed_length test logic for too short seed.");
    }
}
