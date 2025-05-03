use zeroize::Zeroize; 
use std::error::Error as StdError; 
use std::fmt::Debug;
pub trait SignatureEngine {
    type PublicKey: Clone + Debug + Send + Sync + 'static;

    type SecretKey: Zeroize + Debug + Send + Sync + 'static;

    type Signature: Clone + Debug + Send + Sync + 'static;

    type Error: StdError + Debug + Send + Sync + 'static;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error>;
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool;

    // Removed the unidiomatic `error()` method.
}
pub trait SignatureScheme: SignatureEngine {}