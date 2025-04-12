pub trait SignatureEngine {
    type PublicKey: Clone;
    type SecretKey;
    type Signature: Clone;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Self::Signature;
    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool;
}

pub trait SignatureScheme: SignatureEngine {}