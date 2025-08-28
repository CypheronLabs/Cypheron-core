// Copyright 2025 Cypheron Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct CompositeSignature<C, P> {
    pub classical: C,
    pub post_quantum: P,
    pub timestamp: u64,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
