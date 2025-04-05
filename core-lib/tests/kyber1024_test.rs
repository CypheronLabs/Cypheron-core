use core_lib::kem::KemVariant;
use core_lib::kem::{Kem, Kyber1024};
use secrecy::ExposeSecret;

#[test]
fn test_variant_and_expose() {
    assert_eq!(Kyber1024::variant(), KemVariant::Kyber1024);

    let (pk, sk) = Kyber1024::keypair();
    let (ct, ss1) = Kyber1024::encapsulate(&pk);
    let ss2 = Kyber1024::decapsulate(&ct, &sk);

    println!("Public Key (len={}): {:02x?}", pk.0.len(), &pk.0[..16]);
    println!("Secret Key (len={}): {:02x?}", sk.0.len(), &sk.0[..16]);
    println!("Ciphertext (len={}): {:02x?}", ct.len(), &ct[..16]);
    println!("Shared Secret 1: {:02x?}", ss1.expose_secret());
    println!("Shared Secret 2: {:02x?}", ss2.expose_secret());

    assert_eq!(
        Kyber1024::expose_shared(&ss1),
        Kyber1024::expose_shared(&ss2)
    );
}
