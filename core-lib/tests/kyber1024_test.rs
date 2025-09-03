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
use cypheron_core::kem::{Kem, Kyber1024};
use cypheron_core::security::{TestResult, test_assert_eq, test_assert_ne, crypto_operation};
use secrecy::ExposeSecret;

#[test]
fn test_variant_and_expose() -> TestResult<()> {
    test_assert_eq!(Kyber1024::variant(), KemVariant::MlKem1024, "KEM variant check");

    let (pk, sk) = crypto_operation!(Kyber1024::keypair(), "keypair generation");
    let (ct, ss1) = crypto_operation!(Kyber1024::encapsulate(&pk), "encapsulation");
    let ss2 = crypto_operation!(Kyber1024::decapsulate(&ct, &sk), "decapsulation");

    println!("Public Key generated successfully (len={})", pk.0.len());
    println!(
        "Secret Key generated successfully (len={})",
        sk.0.expose_secret().len()
    );
    println!("Ciphertext generated successfully (len={})", ct.len());
    println!(
        "Shared secrets match: {}",
        ss1.expose_secret() == ss2.expose_secret()
    );

    test_assert_eq!(ss1.expose_secret(), ss2.expose_secret(), "shared secret consistency");
    Ok(())
}

#[test]
fn test_decapsulate_with_wrong_secret_key() -> TestResult<()> {
    let (pk1, _sk1) = crypto_operation!(Kyber1024::keypair(), "first keypair generation");
    let (_pk2, sk2) = crypto_operation!(Kyber1024::keypair(), "second keypair generation");
    let (ct, ss1) = crypto_operation!(Kyber1024::encapsulate(&pk1), "encapsulation");
    let ss_wrong = crypto_operation!(Kyber1024::decapsulate(&ct, &sk2), "decapsulation with wrong key");
    
    test_assert_ne!(ss1.expose_secret(), ss_wrong.expose_secret(), "wrong secret key should yield different shared secret");
    Ok(())
}

#[test]
fn test_decapsulate_with_corrupted_ciphertext() -> TestResult<()> {
    let (pk, sk) = crypto_operation!(Kyber1024::keypair(), "keypair generation");
    let (mut ct, ss1) = crypto_operation!(Kyber1024::encapsulate(&pk), "encapsulation");
    if !ct.is_empty() {
        ct[0] ^= 0xFF;
    }
    let ss_corrupt = crypto_operation!(Kyber1024::decapsulate(&ct, &sk), "decapsulation with corrupted ciphertext");
    
    test_assert_ne!(ss1.expose_secret(), ss_corrupt.expose_secret(), "corrupted ciphertext should yield different shared secret");
    Ok(())
}
