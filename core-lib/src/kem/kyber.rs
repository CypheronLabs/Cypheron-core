pub mod sizes {
    pub const KYBER512_PUBLIC: usize = 800;
    pub const KYBER512_SECRET: usize = 1632;
    pub const KYBER512_CIPHERTEXT: usize = 768;
    pub const KYBER512_SHARED: usize = 32;

    pub const KYBER768_PUBLIC: usize = 1184;
    pub const KYBER768_SECRET: usize = 2400;
    pub const KYBER768_CIPHERTEXT: usize = 1088;
    pub const KYBER768_SHARED: usize = 32;

    pub const KYBER1024_PUBLIC: usize = 1568;
    pub const KYBER1024_SECRET: usize = 3168;
    pub const KYBER1024_CIPHERTEXT: usize = 1568;
    pub const KYBER1024_SHARED: usize = 32;
}

#[link(name = "kyber", kind = "dylib")]
extern "C" {
    // Kyber512
    fn crypto_kem_keypair_512(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_kem_enc_512(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_dec_512(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;

    // Kyber768
    fn crypto_kem_keypair_768(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_kem_enc_768(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_dec_768(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;

    // Kyber1024
    fn crypto_kem_keypair_1024(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_kem_enc_1024(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_dec_1024(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

#[derive(Debug, Clone, Copy)]
pub enum KyberVariant {
    Kyber512,
    Kyber768,
    Kyber1024,
}

pub struct Kyber {
    pub variant: KyberVariant,
}

impl Kyber {
    pub fn new(variant: KyberVariant) -> Self {
        Kyber { variant }
    }

    pub fn keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let (pk_len, sk_len, func): (usize, usize, unsafe extern "C" fn(*mut u8, *mut u8) -> i32) = match self.variant {
            KyberVariant::Kyber512 => (
                sizes::KYBER512_PUBLIC,
                sizes::KYBER512_SECRET,
                crypto_kem_keypair_512,
            ),
            KyberVariant::Kyber768 => (
                sizes::KYBER768_PUBLIC,
                sizes::KYBER768_SECRET,
                crypto_kem_keypair_768,
            ),
            KyberVariant::Kyber1024 => (
                sizes::KYBER1024_PUBLIC,
                sizes::KYBER1024_SECRET,
                crypto_kem_keypair_1024,
            ),
        };

        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];
        unsafe {
            func(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        (pk, sk)
    }

    pub fn encapsulate(&self, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (ct_len, ss_len, func): (usize, usize, unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> i32) = match self.variant {
            KyberVariant::Kyber512 => (
                sizes::KYBER512_CIPHERTEXT,
                sizes::KYBER512_SHARED,
                crypto_kem_enc_512,
            ),
            KyberVariant::Kyber768 => (
                sizes::KYBER768_CIPHERTEXT,
                sizes::KYBER768_SHARED,
                crypto_kem_enc_768,
            ),
            KyberVariant::Kyber1024 => (
                sizes::KYBER1024_CIPHERTEXT,
                sizes::KYBER1024_SHARED,
                crypto_kem_enc_1024,
            ),
        };

        let mut ct = vec![0u8; ct_len];
        let mut ss = vec![0u8; ss_len];
        unsafe {
            func(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr());
        }
        (ct, ss)
    }

    pub fn decapsulate(&self, ct: &[u8], sk: &[u8]) -> Vec<u8> {
        let ss_len = match self.variant {
            KyberVariant::Kyber512 => sizes::KYBER512_SHARED,
            KyberVariant::Kyber768 => sizes::KYBER768_SHARED,
            KyberVariant::Kyber1024 => sizes::KYBER1024_SHARED,
        };

        let mut ss = vec![0u8; ss_len];
        unsafe {
            match self.variant {
                KyberVariant::Kyber512 => crypto_kem_dec_512(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()),
                KyberVariant::Kyber768 => crypto_kem_dec_768(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()),
                KyberVariant::Kyber1024 => crypto_kem_dec_1024(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()),
            };
        }
        ss
    }
}