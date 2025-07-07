use core_lib::kem::KemVariant;
use core_lib::kem::{Kem, Kyber768};
use secrecy::ExposeSecret;

#[test]
fn test_variant_and_expose() {
    assert_eq!(Kyber768::variant(), KemVariant::Kyber768);

    let (pk, sk) = Kyber768::keypair();
    let (ct, ss1) = Kyber768::encapsulate(&pk);
    let ss2 = Kyber768::decapsulate(&ct, &sk);

    // Safe debug output - no secret material exposed
    println!("Public Key generated successfully (len={})", pk.0.len());
    println!("Secret Key generated successfully (len={})", sk.0.len());
    println!("Ciphertext generated successfully (len={})", ct.len());
    println!("Shared secrets match: {}", Kyber768::expose_shared(&ss1) == Kyber768::expose_shared(&ss2));

    assert_eq!(Kyber768::expose_shared(&ss1), Kyber768::expose_shared(&ss2));
}

#[test]
fn test_decapsulate_with_wrong_secret_key() {
    let (pk1, _sk1) = Kyber768::keypair();
    let (_pk2, sk2) = Kyber768::keypair();
    let (ct, ss1) = Kyber768::encapsulate(&pk1);
    let ss_wrong = Kyber768::decapsulate(&ct, &sk2);
    assert_ne!(Kyber768::expose_shared(&ss1), Kyber768::expose_shared(&ss_wrong));
}

#[test]
fn test_decapsulate_with_corrupted_ciphertext() {
    let (pk, sk) = Kyber768::keypair();
    let (mut ct, ss1) = Kyber768::encapsulate(&pk);
    if !ct.is_empty() {
        ct[0] ^= 0xFF;
    }
    let ss_corrupt = Kyber768::decapsulate(&ct, &sk);
    assert_ne!(Kyber768::expose_shared(&ss1), Kyber768::expose_shared(&ss_corrupt));
}
