use core_lib::kem::Kyber768;
use secrecy::ExposeSecret;


#[test]
fn test_kyber768_kem_roundtrip() {
    let (pk, sk) = Kyber768::keypair();
    let (ct, ss1) = Kyber768::encapsulate(&pk);
    let ss2 = Kyber768::decapsulate(&ct, &sk);

    assert_eq!(ss1.expose_secret(), ss2.expose_secret(), "Shared secrets do not match");
}
