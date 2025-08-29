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

use cypheron_core::kem::KemVariant;
use cypheron_core::kem::{Kem, Kyber768};
use secrecy::ExposeSecret;

#[test]
fn test_variant_and_expose() {
    assert_eq!(Kyber768::variant(), KemVariant::MlKem768);

    let (pk, sk) = Kyber768::keypair().expect("Failed to generate keypair");
    let (ct, ss1) = Kyber768::encapsulate(&pk).expect("Failed to encapsulate");
    let ss2 = Kyber768::decapsulate(&ct, &sk).expect("Failed to decapsulate");

    println!("Public Key generated successfully (len={})", pk.0.len());
    println!("Secret Key generated successfully (len={})", sk.0.expose_secret().len());
    println!("Ciphertext generated successfully (len={})", ct.len());
    println!("Shared secrets match: {}", ss1.expose_secret() == ss2.expose_secret());

    assert_eq!(ss1.expose_secret(), ss2.expose_secret());
}

#[test]
fn test_decapsulate_with_wrong_secret_key() {
    let (pk1, _sk1) = Kyber768::keypair().expect("Failed to generate first keypair");
    let (_pk2, sk2) = Kyber768::keypair().expect("Failed to generate second keypair");
    let (ct, ss1) = Kyber768::encapsulate(&pk1).expect("Failed to encapsulate");
    let ss_wrong = Kyber768::decapsulate(&ct, &sk2).expect("Failed to decapsulate");
    assert_ne!(ss1.expose_secret(), ss_wrong.expose_secret());
}

#[test]
fn test_decapsulate_with_corrupted_ciphertext() {
    let (pk, sk) = Kyber768::keypair().expect("Failed to generate keypair");
    let (mut ct, ss1) = Kyber768::encapsulate(&pk).expect("Failed to encapsulate");
    if !ct.is_empty() {
        ct[0] ^= 0xFF;
    }
    let ss_corrupt = Kyber768::decapsulate(&ct, &sk).expect("Failed to decapsulate");
    assert_ne!(ss1.expose_secret(), ss_corrupt.expose_secret());
}
