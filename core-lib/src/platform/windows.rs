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

use std::io::{Error, ErrorKind};
use zeroize::Zeroize;

pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    let status = unsafe { BCryptGenRandom(None, buffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };

    if status.is_ok() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Other,
            format!("BCryptGenRandom failed with status: {status:?}"),
        ))
    }
}

pub fn secure_zero(buffer: &mut [u8]) {
    buffer.zeroize();
}

pub fn protect_memory(buffer: &mut [u8], protect: bool) -> Result<(), Error> {
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    let protection = if protect {
        PAGE_NOACCESS
    } else {
        PAGE_READWRITE
    };

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);

    let result = unsafe {
        VirtualProtect(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            protection,
            &mut old_protection,
        )
    };

    if result.is_ok() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "Failed to protect memory"))
    }
}

pub fn get_windows_version() -> String {
    use windows::Win32::System::SystemInformation::{GetVersion, OSVERSIONINFOW};

    unsafe {
        let mut version_info: OSVERSIONINFOW = std::mem::zeroed();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        let _ = GetVersion();
        if version_info.dwMajorVersion != 0 || version_info.dwMinorVersion != 0 {
            format!(
                "Windows {}.{}.{}",
                version_info.dwMajorVersion,
                version_info.dwMinorVersion,
                version_info.dwBuildNumber
            )
        } else {
            "Windows (version unknown)".to_string()
        }
    }
}

pub fn is_modern_windows() -> bool {
    use std::ffi::c_void;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    extern "system" {
        fn RtlGetVersion(VersionInformation: *mut OSVERSIONINFOW) -> i32;
    }

    unsafe {
        let mut version_info: OSVERSIONINFOW = std::mem::zeroed();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        RtlGetVersion(&mut version_info) == 0 && version_info.dwMajorVersion >= 10
    }
}
