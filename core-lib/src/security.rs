use std::ffi::c_void;

pub trait FfiSafe {
    fn is_valid_for_ffi(&self) -> bool;
}

impl<T> FfiSafe for &[T] {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty() && self.as_ptr() != std::ptr::null()
    }
}

impl<T> FfiSafe for &mut [T] {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty() && self.as_ptr() != std::ptr::null()
    }
}

impl<T, const N: usize> FfiSafe for &[T; N] {
    fn is_valid_for_ffi(&self) -> bool {
        self.as_ptr() != std::ptr::null()
    }
}

impl<T, const N: usize> FfiSafe for &mut [T; N] {
    fn is_valid_for_ffi(&self) -> bool {
        self.as_ptr() != std::ptr::null()
    }
}

impl<T> FfiSafe for &Vec<T> {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty() && self.as_ptr() != std::ptr::null()
    }
}

impl<T> FfiSafe for Vec<T> {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty() && self.as_ptr() != std::ptr::null()
    }
}

macro_rules! validate_ffi_buffer {
    ($buffer:expr, $expected_min_size:expr) => {{
        if $buffer.len() < $expected_min_size {
            return Err("Buffer too small for FFI operation".into());
        }
        if !$buffer.is_valid_for_ffi() {
            return Err("Invalid buffer for FFI operation".into());
        }
        Ok(())
    }};
}

macro_rules! validate_ffi_fixed_buffer {
    ($buffer:expr, $expected_size:expr) => {
        if $buffer.len() != $expected_size {
            return Err(crate::sig::falcon::errors::FalconErrors::FfiValidationError("Buffer size mismatch for FFI operation".to_string()));
        }
        if !$buffer.is_valid_for_ffi() {
            return Err(crate::sig::falcon::errors::FalconErrors::FfiValidationError("Invalid buffer for FFI operation".to_string()));
        }
    };
}

macro_rules! validate_ffi_pointer {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return Err(crate::sig::falcon::errors::FalconErrors::FfiValidationError("Null pointer passed to FFI function".to_string()));
        }
    };
}

macro_rules! validate_message_bounds {
    ($msg:expr) => {
        if $msg.len() > usize::MAX / 2 {
            return Err(crate::sig::falcon::errors::FalconErrors::FfiValidationError("Message too large for safe processing".to_string()));
        }
        if !$msg.is_valid_for_ffi() && !$msg.is_empty() {
            return Err(crate::sig::falcon::errors::FalconErrors::FfiValidationError("Invalid message buffer".to_string()));
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

pub(crate) use validate_ffi_buffer;
pub(crate) use validate_ffi_fixed_buffer;
pub(crate) use validate_ffi_pointer;
pub(crate) use validate_message_bounds;
pub(crate) use safe_cast_to_c_void;

pub fn sanitize_buffer_for_ffi<T>(buffer: &mut [T]) -> bool {
    if buffer.is_empty() || buffer.as_ptr().is_null() {
        return false;
    }
    true
}

pub fn verify_buffer_initialized<T: PartialEq + Default + Copy>(
    buffer: &[T], 
    expected_init_len: usize
) -> bool {
    if buffer.len() < expected_init_len {
        return false;
    }
    
    let default_val = T::default();
    let initialized_portion = &buffer[..expected_init_len];
    
    !initialized_portion.iter().all(|&x| x == default_val)
}

#[cfg(debug_assertions)]
macro_rules! secure_debug {
    ($($arg:tt)*) => {
        eprintln!("[DEBUG] {}", format_args!($($arg)*));
    };
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

pub(crate) use secure_debug;
pub(crate) use secure_warn;