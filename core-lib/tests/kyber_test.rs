use core_lib::kem::kyber::{Kyber, KyberVariant};

#[test]
fn test_kyber512_roundtrip() {
    let kyber = Kyber::new(KyberVariant::Kyber512);
    let (pk, sk) = kyber.keypair();
    let (ct, ss1) = kyber.encapsulate(&pk);
    let ss2 = kyber.decapsulate(&ct, &sk);
    assert_eq!(ss1, ss2);
}

#[test]
fn test_kyber768_roundtrip() {
    let kyber = Kyber::new(KyberVariant::Kyber768);
    let (pk, sk) = kyber.keypair();
    let (ct, ss1) = kyber.encapsulate(&pk);
    let ss2 = kyber.decapsulate(&ct, &sk);
    assert_eq!(ss1, ss2);
}

#[test]
fn test_kyber1024_roundtrip() {
    let kyber = Kyber::new(KyberVariant::Kyber1024);
    let (pk, sk) = kyber.keypair();
    let (ct, ss1) = kyber.encapsulate(&pk);
    let ss2 = kyber.decapsulate(&ct, &sk);
    assert_eq!(ss1, ss2);
}
