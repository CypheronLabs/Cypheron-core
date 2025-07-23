use core_lib::kem::KemVariant;
use core_lib::kem::{Kem, Kyber768};
use secrecy::ExposeSecret;

#[test]
fn test_variant_and_expose() {
    assert_eq!(Kyber768::variant(), KemVariant::MlKem768);

    let (pk, sk) = Kyber768::keypair().expect("Failed to generate keypair");
    let (ct, ss1) = Kyber768::encapsulate(&pk).expect("Failed to encapsulate");
    let ss2 = Kyber768::decapsulate(&ct, &sk).expect("Failed to decapsulate");

    println!("Public Key generated successfully (len={})", pk.0.len());
    println!("Secret Key generated successfully (len={})", sk.0.len());
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
