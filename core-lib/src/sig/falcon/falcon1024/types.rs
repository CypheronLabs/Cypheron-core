use secrecy::Secret;
use zeroize::Zeroize;

pub const FALCON1024_PUBLIC: usize = 897;
pub const FALCON1024_SECRET: usize = 1281;
pub const FALCON1024_SIGNATURE: usize = 752;

#[derive(Clone)]
pub struct PublicKey<const N: usize>(pub [u8; N]);

pub struct SecretKey<const N: usize>(pub Secret<[u8; N]>);

#[derive(Clone)]
pub struct Signature<const N: usize>(pub [u8; N]);

// ---- Aliases for Falcon512 ----
pub type Falcon1024PublicKey = PublicKey<FALCON1024_PUBLIC>;
pub type Falcon1024SecretKey = SecretKey<FALCON1024_SECRET>;
pub type Falcon1024Signature = Signature<FALCON1024_SIGNATURE>;
