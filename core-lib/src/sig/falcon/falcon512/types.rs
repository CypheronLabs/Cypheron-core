use secrecy::Secret;

pub const FALCON512_PUBLIC: usize = 897;
pub const FALCON512_SECRET: usize = 1281;
pub const FALCON512_SIGNATURE: usize = 752;

#[derive(Clone)]
pub struct PublicKey<const N: usize>(pub [u8; N]);

pub struct SecretKey<const N: usize>(pub Secret<[u8; N]>);

#[derive(Clone)]
pub struct Signature<const N: usize>(pub [u8; N]);

// ---- Aliases for Falcon512 ----
pub type Falcon512PublicKey = PublicKey<FALCON512_PUBLIC>;
pub type Falcon512SecretKey = SecretKey<FALCON512_SECRET>;
pub type Falcon512Signature = Signature<FALCON512_SIGNATURE>;
