use secrecy::{Secret, Zeroize};

pub const FALCON1024_PUBLIC: usize = 1793;
pub const FALCON1024_SECRET: usize = 2305;
pub const FALCON1024_SIGNATURE: usize = 1345;

#[derive(Clone)]
pub struct  PublicKey<const N: usize>(pub[u8; N]);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey<const N: usize>(pub Secret<[u8; N]>);

#[derive(Clone)]
pub struct Signature<const N: usize>(pub [u8; N]);

// ---- Aliases for Falcon1024 ----
pub type Falcon1024PublicKey = PublicKey<FALCON1024_PUBLIC>;
pub type Falcon1024SecretKey = SecretKey<FALCON1024_SECRET>;
pub type Falcon1024Signature = Signature<FALCON1024_SIGNATURE>;