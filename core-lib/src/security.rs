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

pub trait FfiSafe {
    fn is_valid_for_ffi(&self) -> bool;
}

impl<T> FfiSafe for &[T] {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty()
    }
}

impl<T> FfiSafe for &mut [T] {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty()
    }
}

impl<T, const N: usize> FfiSafe for &[T; N] {
    fn is_valid_for_ffi(&self) -> bool {
        true
    }
}

impl<T, const N: usize> FfiSafe for &mut [T; N] {
    fn is_valid_for_ffi(&self) -> bool {
        true
    }
}

impl<T> FfiSafe for &Vec<T> {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty()
    }
}

impl<T> FfiSafe for Vec<T> {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty()
    }
}

macro_rules! validate_ffi_fixed_buffer {
    ($buffer:expr, $expected_size:expr) => {
        if $buffer.len() != $expected_size {
            return Err(
                crate::sig::falcon::errors::FalconErrors::FfiValidationError(
                    "Buffer size mismatch for FFI operation".to_string(),
                ),
            );
        }
        if !$buffer.is_valid_for_ffi() {
            return Err(
                crate::sig::falcon::errors::FalconErrors::FfiValidationError(
                    "Invalid buffer for FFI operation".to_string(),
                ),
            );
        }
    };
}

macro_rules! validate_ffi_kem_buffer {
    ($buffer:expr, $expected_size:expr) => {
        if $buffer.len() != $expected_size {
            return Err(crate::kem::ml_kem_512::MlKemError::InvalidPublicKeyLength {
                expected: $expected_size,
                actual: $buffer.len(),
            });
        }
        if !$buffer.is_empty() && !$buffer.is_valid_for_ffi() {
            return Err(crate::kem::ml_kem_512::MlKemError::CLibraryError { code: -3 });
        }
    };
}

macro_rules! validate_ffi_kem_ptr {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return Err(crate::kem::ml_kem_512::MlKemError::CLibraryError { code: -4 });
        }
    };
}

macro_rules! validate_ffi_dilithium_buffer {
    ($buffer:expr, $expected_size:expr) => {
        if $buffer.len() != $expected_size {
            return Err(crate::sig::dilithium::errors::DilithiumError::InvalidInput);
        }
        if !$buffer.is_empty() && !$buffer.is_valid_for_ffi() {
            return Err(crate::sig::dilithium::errors::DilithiumError::InvalidInput);
        }
    };
}

macro_rules! validate_ffi_dilithium_ptr {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return Err(crate::sig::dilithium::errors::DilithiumError::CLibraryError { code: -4 });
        }
    };
}

macro_rules! validate_dilithium_message_bounds {
    ($msg:expr) => {
        if $msg.len() > usize::MAX / 2 {
            return Err(crate::sig::dilithium::errors::DilithiumError::InvalidInput);
        }
        if !$msg.is_valid_for_ffi() && !$msg.is_empty() {
            return Err(crate::sig::dilithium::errors::DilithiumError::InvalidInput);
        }
    };
}

macro_rules! validate_dilithium_signature_output {
    ($buffer:expr, $actual_len:expr, $max_len:expr) => {
        if $actual_len == 0 || $actual_len > $max_len {
            return Err(crate::sig::dilithium::errors::DilithiumError::SigningInternalError);
        }
        if !crate::security::verify_buffer_initialized(&$buffer[..$actual_len], $actual_len) {
            return Err(crate::sig::dilithium::errors::DilithiumError::SigningInternalError);
        }
    };
}

macro_rules! validate_message_bounds {
    ($msg:expr) => {
        if $msg.len() > usize::MAX / 2 {
            return Err(
                crate::sig::falcon::errors::FalconErrors::FfiValidationError(
                    "Message too large for safe processing".to_string(),
                ),
            );
        }
        if !$msg.is_valid_for_ffi() && !$msg.is_empty() {
            return Err(
                crate::sig::falcon::errors::FalconErrors::FfiValidationError(
                    "Invalid message buffer".to_string(),
                ),
            );
        }
    };
}

macro_rules! safe_cast_to_c_void {
    ($ptr:expr) => {
        $ptr as *const c_void
    };
    (mut $ptr:expr) => {
        $ptr as *mut c_void
    };
}

pub(crate) use safe_cast_to_c_void;
pub(crate) use validate_dilithium_message_bounds;
pub(crate) use validate_dilithium_signature_output;
pub(crate) use validate_ffi_dilithium_buffer;
pub(crate) use validate_ffi_dilithium_ptr;
pub(crate) use validate_ffi_fixed_buffer;
pub(crate) use validate_ffi_kem_buffer;
pub(crate) use validate_ffi_kem_ptr;
pub(crate) use validate_message_bounds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    BufferSizeMismatch { expected: usize, actual: usize },
    BufferEmpty,
    BufferTooLarge { max_size: usize, actual: usize },
    InvalidRange { min: usize, max: usize, actual: usize },
    NullPointer,
    InvalidUtf8,
    InvalidFormat(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::BufferSizeMismatch { expected, actual } => 
                write!(f, "Buffer size mismatch: expected {}, got {}", expected, actual),
            ValidationError::BufferEmpty => 
                write!(f, "Buffer is empty"),
            ValidationError::BufferTooLarge { max_size, actual } => 
                write!(f, "Buffer too large: max {}, got {}", max_size, actual),
            ValidationError::InvalidRange { min, max, actual } => 
                write!(f, "Value {} outside valid range [{}, {}]", actual, min, max),
            ValidationError::NullPointer => 
                write!(f, "Null pointer encountered"),
            ValidationError::InvalidUtf8 => 
                write!(f, "Invalid UTF-8 sequence"),
            ValidationError::InvalidFormat(msg) => 
                write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_buffer_size(buffer: &[u8], expected_size: usize) -> Result<(), ValidationError> {
    if buffer.len() != expected_size {
        return Err(ValidationError::BufferSizeMismatch {
            expected: expected_size,
            actual: buffer.len(),
        });
    }
    Ok(())
}

pub fn validate_buffer_non_empty(buffer: &[u8]) -> Result<(), ValidationError> {
    if buffer.is_empty() {
        return Err(ValidationError::BufferEmpty);
    }
    Ok(())
}

pub fn validate_buffer_max_size(buffer: &[u8], max_size: usize) -> Result<(), ValidationError> {
    if buffer.len() > max_size {
        return Err(ValidationError::BufferTooLarge {
            max_size,
            actual: buffer.len(),
        });
    }
    Ok(())
}

pub fn validate_range<T>(value: T, min: T, max: T) -> Result<(), ValidationError> 
where 
    T: PartialOrd + Copy + Into<usize>
{
    if value < min || value > max {
        return Err(ValidationError::InvalidRange {
            min: min.into(),
            max: max.into(),
            actual: value.into(),
        });
    }
    Ok(())
}

pub fn validate_key_size(key: &[u8], expected_sizes: &[usize]) -> Result<(), ValidationError> {
    if !expected_sizes.contains(&key.len()) {
        return Err(ValidationError::InvalidFormat(
            format!("Invalid key size: {} (expected one of {:?})", key.len(), expected_sizes)
        ));
    }
    Ok(())
}

macro_rules! validate_crypto_input {
    ($buffer:expr, $expected_size:expr) => {{
        crate::security::validate_buffer_size($buffer, $expected_size)?;
        crate::security::validate_buffer_non_empty($buffer)?;
    }};
}

macro_rules! validate_crypto_output {
    ($buffer:expr, $max_size:expr) => {{
        crate::security::validate_buffer_max_size($buffer, $max_size)?;
    }};
}

pub(crate) use validate_crypto_input;
pub(crate) use validate_crypto_output;

pub mod test_utils {
    use super::ValidationError;
    use std::fmt::Debug;
    
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TestError {
        CryptoOperationFailed(String),
        ValidationFailed(ValidationError),
        AssertionFailed { expected: String, actual: String },
        TestSetupFailed(String),
        ResourceUnavailable(String),
    }
    
    impl From<ValidationError> for TestError {
        fn from(err: ValidationError) -> Self {
            TestError::ValidationFailed(err)
        }
    }
    
    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TestError::CryptoOperationFailed(msg) => 
                    write!(f, "Cryptographic operation failed: {}", msg),
                TestError::ValidationFailed(err) => 
                    write!(f, "Validation failed: {}", err),
                TestError::AssertionFailed { expected, actual } => 
                    write!(f, "Assertion failed: expected {}, got {}", expected, actual),
                TestError::TestSetupFailed(msg) => 
                    write!(f, "Test setup failed: {}", msg),
                TestError::ResourceUnavailable(msg) => 
                    write!(f, "Test resource unavailable: {}", msg),
            }
        }
    }
    
    impl std::error::Error for TestError {}
    
    pub type TestResult<T> = Result<T, TestError>;
    
    pub fn assert_eq_safe<T>(expected: &T, actual: &T, context: &str) -> TestResult<()> 
    where 
        T: PartialEq + Debug
    {
        if expected == actual {
            Ok(())
        } else {
            Err(TestError::AssertionFailed {
                expected: format!("{} - expected: {:?}", context, expected),
                actual: format!("{} - actual: {:?}", context, actual),
            })
        }
    }
    
    pub fn assert_ne_safe<T>(unexpected: &T, actual: &T, context: &str) -> TestResult<()> 
    where 
        T: PartialEq + Debug
    {
        if unexpected != actual {
            Ok(())
        } else {
            Err(TestError::AssertionFailed {
                expected: format!("{} - values should be different", context),
                actual: format!("{} - both values: {:?}", context, actual),
            })
        }
    }
    
    pub fn require_crypto_operation<T, E>(result: Result<T, E>, operation: &str) -> TestResult<T>
    where 
        E: std::fmt::Display
    {
        result.map_err(|e| TestError::CryptoOperationFailed(
            format!("{}: {}", operation, e)
        ))
    }
    
    pub fn skip_if_unavailable<T, E>(result: Result<T, E>, resource: &str) -> TestResult<Option<T>>
    where 
        E: std::fmt::Display
    {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(e) => {
                eprintln!("Skipping test - {}: {}", resource, e);
                Ok(None)
            }
        }
    }
    
    macro_rules! test_assert_eq {
        ($expected:expr, $actual:expr) => {
            crate::security::test_utils::assert_eq_safe(&$expected, &$actual, 
                &format!("{}:{}", file!(), line!()))?;
        };
        ($expected:expr, $actual:expr, $msg:expr) => {
            crate::security::test_utils::assert_eq_safe(&$expected, &$actual, $msg)?;
        };
    }
    
    macro_rules! test_assert_ne {
        ($unexpected:expr, $actual:expr) => {
            crate::security::test_utils::assert_ne_safe(&$unexpected, &$actual, 
                &format!("{}:{}", file!(), line!()))?;
        };
        ($unexpected:expr, $actual:expr, $msg:expr) => {
            crate::security::test_utils::assert_ne_safe(&$unexpected, &$actual, $msg)?;
        };
    }
    
    macro_rules! crypto_operation {
        ($op:expr, $desc:expr) => {
            crate::security::test_utils::require_crypto_operation($op, $desc)?
        };
    }
    
    pub(crate) use test_assert_eq;
    pub(crate) use test_assert_ne;
    pub(crate) use crypto_operation;
}

pub fn sanitize_buffer_for_ffi<T>(buffer: &mut [T]) -> bool {
    !buffer.is_empty()
}

pub fn verify_buffer_initialized<T: PartialEq + Default + Copy>(
    buffer: &[T],
    expected_init_len: usize,
) -> bool {
    if buffer.len() < expected_init_len {
        return false;
    }

    let default_val = T::default();
    let initialized_portion = &buffer[..expected_init_len];

    !initialized_portion.iter().all(|&x| x == default_val)
}

#[cfg(not(debug_assertions))]
macro_rules! secure_debug {
    ($($arg:tt)*) => {};
}

#[cfg(debug_assertions)]
macro_rules! secure_warn {
    ($($arg:tt)*) => {
        eprintln!("[WARN] {}", format_args!($($arg)*));
    };
}

#[cfg(not(debug_assertions))]
macro_rules! secure_warn {
    ($($arg:tt)*) => {};
}

pub(crate) use secure_warn;

#[cfg(test)]
pub use test_utils::{TestError, TestResult, test_assert_eq, test_assert_ne, crypto_operation};

pub mod benchmark_utils {
    use super::ValidationError;
    use std::fmt::Debug;
    
    #[derive(Debug, Clone)]
    pub enum BenchmarkError {
        SetupFailed(String),
        ValidationFailed(ValidationError),
        OperationFailed(String),
        ResourceUnavailable(String),
        PerformanceDegraded(String),
    }
    
    impl From<ValidationError> for BenchmarkError {
        fn from(err: ValidationError) -> Self {
            BenchmarkError::ValidationFailed(err)
        }
    }
    
    impl std::fmt::Display for BenchmarkError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                BenchmarkError::SetupFailed(msg) => 
                    write!(f, "Benchmark setup failed: {}", msg),
                BenchmarkError::ValidationFailed(err) => 
                    write!(f, "Validation failed: {}", err),
                BenchmarkError::OperationFailed(msg) => 
                    write!(f, "Benchmark operation failed: {}", msg),
                BenchmarkError::ResourceUnavailable(msg) => 
                    write!(f, "Benchmark resource unavailable: {}", msg),
                BenchmarkError::PerformanceDegraded(msg) => 
                    write!(f, "Performance degraded: {}", msg),
            }
        }
    }
    
    impl std::error::Error for BenchmarkError {}
    
    pub type BenchmarkResult<T> = Result<T, BenchmarkError>;
    
    pub fn safe_crypto_operation<T, E>(result: Result<T, E>, operation: &str) -> BenchmarkResult<T>
    where 
        E: std::fmt::Display
    {
        result.map_err(|e| BenchmarkError::OperationFailed(
            format!("{}: {}", operation, e)
        ))
    }
    
    pub fn validate_benchmark_input<T>(input: T, validator: impl Fn(&T) -> bool, desc: &str) -> BenchmarkResult<T> {
        if validator(&input) {
            Ok(input)
        } else {
            Err(BenchmarkError::SetupFailed(
                format!("Invalid benchmark input: {}", desc)
            ))
        }
    }
    
    pub fn skip_degraded_benchmark<T, E>(result: Result<T, E>, benchmark_name: &str) -> BenchmarkResult<Option<T>>
    where 
        E: std::fmt::Display
    {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(e) => {
                eprintln!("Skipping degraded benchmark '{}': {}", benchmark_name, e);
                Ok(None)
            }
        }
    }
    
    macro_rules! bench_crypto_op {
        ($op:expr, $desc:expr) => {
            crate::security::benchmark_utils::safe_crypto_operation($op, $desc)?
        };
    }
    
    macro_rules! bench_validate {
        ($input:expr, $validator:expr, $desc:expr) => {
            crate::security::benchmark_utils::validate_benchmark_input($input, $validator, $desc)?
        };
    }
    
    pub(crate) use bench_crypto_op;
    pub(crate) use bench_validate;
}
