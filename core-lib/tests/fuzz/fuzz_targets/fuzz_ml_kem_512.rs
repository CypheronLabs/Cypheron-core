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

#![no_main]

use libfuzzer_sys::fuzz_target;
use cypheron_core::kem::{MlKem512, Kem};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let (pk, sk) = MlKem512::keypair();
    
    if data.len() == 768 {
        let mut ciphertext = vec![0u8; 768];
        ciphertext.copy_from_slice(data);
        
        let _result = std::panic::catch_unwind(|| {
            MlKem512::decapsulate(&ciphertext, &sk)
        });
    }
    
    if data.len() >= 800 {
        let mut pk_data = [0u8; 800];
        pk_data.copy_from_slice(&data[..800]);
        
        use cypheron_core::kem::kyber512::KyberPublicKey;
        let fuzzed_pk = KyberPublicKey(pk_data);
        
        let _result = std::panic::catch_unwind(|| {
            MlKem512::encapsulate(&fuzzed_pk)
        });
    }
    
    for chunk_size in [1, 16, 32, 64, 128, 256, 512].iter() {
        if data.len() >= *chunk_size {
            let chunk = &data[..*chunk_size];
            
            let _result = std::panic::catch_unwind(|| {
                if chunk.len() >= 800 {
                    let mut pk_data = [0u8; 800];
                    pk_data[..chunk.len().min(800)].copy_from_slice(&chunk[..chunk.len().min(800)]);
                    let pk = KyberPublicKey(pk_data);
                    let _ = MlKem512::encapsulate(&pk);
                }
            });
        }
    }
});