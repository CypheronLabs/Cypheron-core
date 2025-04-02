pub mod sizes {
    pub const KYBER768_PUBLIC: usize = 1184;
    pub const KYBER768_SECRET: usize = 2400;
    pub const KYBER768_CIPHERTEXT: usize = 1088;
    pub const KYBER768_SHARED: usize = 32;
}

#[link(name = "kyber_ref", kind = "static")] // the .a file you built
extern "C" {
    pub fn pqcrystals_kyber768_ref_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    pub fn pqcrystals_kyber768_ref_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    pub fn pqcrystals_kyber768_ref_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

#[derive(Debug, Clone, Copy)]
pub enum KyberVariant {
    Kyber512,
    Kyber768,
    Kyber1024,
}

pub struct Kyber768;

impl Kyber768 {
    pub fn keypair() -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; sizes::KYBER768_PUBLIC];
        let mut sk = vec![0u8; sizes::KYBER768_SECRET];
        unsafe {
            pqcrystals_kyber768_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        (pk, sk)
    }

    pub fn encapsulate(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut ct = vec![0u8; sizes::KYBER768_CIPHERTEXT];
        let mut ss = vec![0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr());
        }
        (ct, ss)
    }

    pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
        let mut ss = vec![0u8; sizes::KYBER768_SHARED];
        unsafe {
            pqcrystals_kyber768_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr());
        }
        ss
    }
}