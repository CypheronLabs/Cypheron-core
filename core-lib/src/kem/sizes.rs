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

pub const ML_KEM_512_PUBLIC: usize = 800;
pub const ML_KEM_512_SECRET: usize = 1632;
pub const ML_KEM_512_CIPHERTEXT: usize = 768;
pub const ML_KEM_512_SHARED: usize = 32;

pub const ML_KEM_768_PUBLIC: usize = 1184;
pub const ML_KEM_768_SECRET: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT: usize = 1088;
pub const ML_KEM_768_SHARED: usize = 32;

pub const ML_KEM_1024_PUBLIC: usize = 1568;
pub const ML_KEM_1024_SECRET: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXT: usize = 1568;
pub const ML_KEM_1024_SHARED: usize = 32;

#[deprecated(since = "0.2.0", note = "Use ML_KEM_512_* constants for NIST FIPS 203 compliance")]
pub const KYBER512_PUBLIC: usize = ML_KEM_512_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_512_* constants for NIST FIPS 203 compliance")]
pub const KYBER512_SECRET: usize = ML_KEM_512_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_512_* constants for NIST FIPS 203 compliance")]
pub const KYBER512_CIPHERTEXT: usize = ML_KEM_512_CIPHERTEXT;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_512_* constants for NIST FIPS 203 compliance")]
pub const KYBER512_SHARED: usize = ML_KEM_512_SHARED;

#[deprecated(since = "0.2.0", note = "Use ML_KEM_768_* constants for NIST FIPS 203 compliance")]
pub const KYBER768_PUBLIC: usize = ML_KEM_768_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_768_* constants for NIST FIPS 203 compliance")]
pub const KYBER768_SECRET: usize = ML_KEM_768_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_768_* constants for NIST FIPS 203 compliance")]
pub const KYBER768_CIPHERTEXT: usize = ML_KEM_768_CIPHERTEXT;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_768_* constants for NIST FIPS 203 compliance")]
pub const KYBER768_SHARED: usize = ML_KEM_768_SHARED;

#[deprecated(since = "0.2.0", note = "Use ML_KEM_1024_* constants for NIST FIPS 203 compliance")]
pub const KYBER1024_PUBLIC: usize = ML_KEM_1024_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_1024_* constants for NIST FIPS 203 compliance")]
pub const KYBER1024_SECRET: usize = ML_KEM_1024_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_1024_* constants for NIST FIPS 203 compliance")]
pub const KYBER1024_CIPHERTEXT: usize = ML_KEM_1024_CIPHERTEXT;
#[deprecated(since = "0.2.0", note = "Use ML_KEM_1024_* constants for NIST FIPS 203 compliance")]
pub const KYBER1024_SHARED: usize = ML_KEM_1024_SHARED;
