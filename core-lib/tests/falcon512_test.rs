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

use core_lib::sig::falcon::falcon512::api::Falcon512;
use core_lib::sig::falcon::falcon512::constants::{FALCON_PUBLIC, FALCON_SECRET, FALCON_SIGNATURE};
use core_lib::sig::falcon::falcon512::types::{Falcon512Signature, Signature};
use core_lib::sig::traits::SignatureEngine;
use secrecy::ExposeSecret;

const TEST_MESSAGE_FALCON512: &[u8] = b"This is a test message for Falcon-512 implementation.";

#[test]
fn falcon512_test_keypair_generation_lengths() {
    let result = Falcon512::keypair();
    assert!(result.is_ok(), "Falcon-512: Keypair generation failed: {:?}", result.err());
    let (pk, sk) = result.unwrap();

    println!("Falcon-512 Public Key generated successfully (len={})", pk.0.len());
    println!("Falcon-512 Secret Key generated successfully (len={})", sk.0.expose_secret().len());

    assert_eq!(pk.0.len(), FALCON_PUBLIC, "Falcon-512: Public key length mismatch");
    assert_eq!(sk.0.expose_secret().len(), FALCON_SECRET, "Falcon-512: Secret key length mismatch");
}

#[test]
fn falcon512_test_sign_verify_roundtrip() {
    let keypair_result = Falcon512::keypair();
    assert!(
        keypair_result.is_ok(),
        "Falcon-512: Keypair generation failed for roundtrip: {:?}",
        keypair_result.err()
    );
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon512::sign(TEST_MESSAGE_FALCON512, &sk);
    assert!(sign_result.is_ok(), "Falcon-512: Signing failed: {:?}", sign_result.err());
    let signature = sign_result.unwrap();

    println!(
        "Falcon-512 Message: {:?}",
        std::str::from_utf8(TEST_MESSAGE_FALCON512).unwrap_or("Invalid UTF-8")
    );
    println!("Falcon-512 Signature (len={}): {:02x?}", signature.0.len(), &signature.0[..32]);

    let mut actual_sig_len = signature.0.len();
    while actual_sig_len > 0 && signature.0[actual_sig_len - 1] == 0 {
        actual_sig_len -= 1;
    }
    println!("Falcon-512 Actual Signature Length: {}", actual_sig_len);

    assert_eq!(signature.0.len(), FALCON_SIGNATURE, "Falcon-512: Signature length mismatch");

    let is_valid = Falcon512::verify(TEST_MESSAGE_FALCON512, &signature, &pk);
    assert!(is_valid, "Falcon-512: Verification failed for a valid signature");
}

#[test]
fn falcon512_test_verify_failure_wrong_message() {
    let keypair_result = Falcon512::keypair();
    assert!(
        keypair_result.is_ok(),
        "Falcon-512: Keypair generation failed for wrong message test: {:?}",
        keypair_result.err()
    );
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon512::sign(TEST_MESSAGE_FALCON512, &sk);
    assert!(
        sign_result.is_ok(),
        "Falcon-512: Signing failed for wrong message test: {:?}",
        sign_result.err()
    );
    let signature = sign_result.unwrap();

    let wrong_message: &[u8] = b"This is definitely not the original message for Falcon-512.";
    let is_valid = Falcon512::verify(wrong_message, &signature, &pk);

    assert!(!is_valid, "Falcon-512: Verification should fail for a wrong message");
}

#[test]
fn falcon512_test_verify_failure_wrong_public_key() {
    let keypair1_result = Falcon512::keypair();
    assert!(
        keypair1_result.is_ok(),
        "Falcon-512: Keypair 1 generation failed: {:?}",
        keypair1_result.err()
    );
    let (_pk1, sk1) = keypair1_result.unwrap();

    let keypair2_result = Falcon512::keypair();
    assert!(
        keypair2_result.is_ok(),
        "Falcon-512: Keypair 2 generation failed: {:?}",
        keypair2_result.err()
    );
    let (pk2, _sk2) = keypair2_result.unwrap();

    let sign_result = Falcon512::sign(TEST_MESSAGE_FALCON512, &sk1);
    assert!(sign_result.is_ok(), "Falcon-512: Signing with sk1 failed: {:?}", sign_result.err());
    let signature = sign_result.unwrap();

    let is_valid = Falcon512::verify(TEST_MESSAGE_FALCON512, &signature, &pk2);
    assert!(!is_valid, "Falcon-512: Verification should fail for a wrong public key");
}

#[test]
fn falcon512_test_verify_failure_corrupted_signature() {
    let keypair_result = Falcon512::keypair();
    assert!(
        keypair_result.is_ok(),
        "Falcon-512: Keypair generation failed for corrupted sig test: {:?}",
        keypair_result.err()
    );
    let (pk, sk) = keypair_result.unwrap();

    let sign_result = Falcon512::sign(TEST_MESSAGE_FALCON512, &sk);
    assert!(
        sign_result.is_ok(),
        "Falcon-512: Signing failed for corrupted sig test: {:?}",
        sign_result.err()
    );

    let signature_instance = sign_result.unwrap();
    let mut signature_array: [u8; FALCON_SIGNATURE] = signature_instance.0;

    if FALCON_SIGNATURE > 0 {
        signature_array[0] ^= 0x01;
    } else {
        panic!("Falcon-512: FALCON_SIGNATURE constant is 0, cannot corrupt meaningfully");
    }

    let corrupted_signature: Falcon512Signature = Signature(signature_array);

    let is_valid = Falcon512::verify(TEST_MESSAGE_FALCON512, &corrupted_signature, &pk);
    assert!(!is_valid, "Falcon-512: Verification should fail for a corrupted signature");
}
