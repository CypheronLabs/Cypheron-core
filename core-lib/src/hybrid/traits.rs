use std::error::Error as StdError;
use std::fmt::Debug;
use zeroize::Zeroize;

pub trait HybridEngine {
    type ClassicalPublicKey: Clone + Debug + Send + Sync + 'static;
    type ClassicalSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type ClassicalSignature: Clone + Debug + Send + Sync + 'static;

    type PqPublicKey: Clone + Debug + Send + Sync + 'static;
    type PqSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type PqSignature: Clone + Debug + Send + Sync + 'static;

    type CompositePublicKey: Clone + Debug + Send + Sync + 'static;
    type CompositeSecretKey: Zeroize + Debug + Send + Sync + 'static;
    type CompositeSignature: Clone + Debug + Send + Sync + 'static;

    type Error: StdError + Debug + Send + Sync + 'static;

    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error>;

    fn sign(
        msg: &[u8],
        sk: &Self::CompositeSecretKey,
    ) -> Result<Self::CompositeSignature, Self::Error>;

    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool;

    fn verify_with_policy(
        msg: &[u8],
        sig: &Self::CompositeSignature,
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy,
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationPolicy {
    BothRequired,
    EitherValid,
    ClassicalOnly,
    PostQuantumOnly,
}

pub trait HybridScheme: HybridEngine {}
