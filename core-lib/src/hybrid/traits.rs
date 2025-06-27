use zeroize::Zeroize;
use std::error::Error as StdError;
use std::fmt::Debug;

/// Core trait for hybrid cryptographic schemes that combine classical and post-quantum algorithms
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

    /// Generate a composite keypair (classical + post-quantum)
    fn keypair() -> Result<(Self::CompositePublicKey, Self::CompositeSecretKey), Self::Error>;
    
    /// Sign with both classical and post-quantum algorithms
    fn sign(msg: &[u8], sk: &Self::CompositeSecretKey) -> Result<Self::CompositeSignature, Self::Error>;
    
    /// Verify both classical and post-quantum signatures
    fn verify(msg: &[u8], sig: &Self::CompositeSignature, pk: &Self::CompositePublicKey) -> bool;
    
    /// Verify with policy: both must pass, or either can pass (configurable)
    fn verify_with_policy(
        msg: &[u8], 
        sig: &Self::CompositeSignature, 
        pk: &Self::CompositePublicKey,
        policy: VerificationPolicy
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationPolicy {
    /// Both classical and post-quantum signatures must be valid
    BothRequired,
    /// Either classical OR post-quantum signature must be valid  
    EitherValid,
    /// Only classical signature needs to be valid (transition mode)
    ClassicalOnly,
    /// Only post-quantum signature needs to be valid (future mode)
    PostQuantumOnly,
}

pub trait HybridScheme: HybridEngine {}