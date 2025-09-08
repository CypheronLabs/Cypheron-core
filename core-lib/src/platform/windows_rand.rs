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
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CryptAcquireContextW, 
    CryptGenRandom,
    CryptReleaseContext,
    CRYPT_VERIFYCONTEXT,
    PROV_RSA_FULL,
}

#[cfg(target_os = "windows")]
use windows::core::HCRYPTPROV;

#[no_mangle]
#[cfg(target_os = "windows")]
pub unsafe extern "C" fn randombytes(x: *mut u8, xlen: u64) {
    let mut hprov: HCRYPTPROV = HCRYPTPROV::default();
    let buffer = std::slice::from_raw_parts_mut(x, xlen as usize);

    if !CryptAcquireContextW(
        &mut hprov,
        None,
        None,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT,
    ).as_bool() {
        eprintln!("Failed to acquire cryptographic context");
        std::process::exit(1);
    }
    if !CryptGenRandom(hprov, xlen as u32, buffer).as_bool() {
        eprintln!("Failed to generate random bytes");
        std::process::exit(1);
    }
    let _ = CryptReleaseContext(hprov, 0);
}