use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct CompositeSignature<C, P> {
    pub classical: C,
    pub post_quantum: P,
    pub timestamp: u64,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CompositePublicKey<C, P> {
    pub classical: C,
    pub post_quantum: P,
}

#[derive(Debug)]
pub struct CompositeSecretKey<C, P>
where
    C: Zeroize,
    P: Zeroize,
{
    pub classical: SecretBox<C>,
    pub post_quantum: SecretBox<P>,
}

impl<C, P> Zeroize for CompositeSecretKey<C, P>
where
    C: Zeroize,
    P: Zeroize,
{
    fn zeroize(&mut self) {}
}

impl<C, P> ZeroizeOnDrop for CompositeSecretKey<C, P>
where
    C: Zeroize,
    P: Zeroize,
{
}

/// Composite keypair helper
#[derive(Debug)]
pub struct CompositeKeypair<C, P>
where
    C: Zeroize,
    P: Zeroize,
{
    pub public: CompositePublicKey<C, P>,
    pub secret: CompositeSecretKey<C, P>,
}

impl<C, P> CompositeKeypair<C, P>
where
    C: Zeroize,
    P: Zeroize,
{
    pub fn new(classical_keypair: (C, C), pq_keypair: (P, P)) -> Self
    where
        C: Clone,
        P: Clone,
    {
        let (classical_pk, classical_sk) = classical_keypair;
        let (pq_pk, pq_sk) = pq_keypair;

        Self {
            public: CompositePublicKey { classical: classical_pk, post_quantum: pq_pk },
            secret: CompositeSecretKey {
                classical: SecretBox::new(Box::new(classical_sk)),
                post_quantum: SecretBox::new(Box::new(pq_sk)),
            },
        }
    }
}
