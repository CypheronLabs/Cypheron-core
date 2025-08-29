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


pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    use windows::Win32::Security::Cryptography::{
        CryptAcquireContextW, CryptGenRandom, CryptReleaseContext, CRYPT_VERIFYCONTEXT, HCRYPTPROV,
        PROV_RSA_FULL,
    };

    unsafe {
        let mut hprov: HCRYPTPROV = Default::default();

        let result =
            CryptAcquireContextW(&mut hprov, None, None, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

        if !result.as_bool() {
            return Err(Error::new(ErrorKind::Other, "Failed to acquire cryptographic context"));
        }

        let gen_result = CryptGenRandom(hprov, buffer.len() as u32, buffer.as_mut_ptr());

        let _ = CryptReleaseContext(hprov, 0);

        if !gen_result.as_bool() {
            return Err(Error::new(ErrorKind::Other, "Failed to generate random bytes"));
        }

        Ok(())
    }
}


pub fn secure_zero(buffer: &mut [u8]) {
    use windows::Win32::System::Memory::RtlSecureZeroMemory;

    unsafe {
        RtlSecureZeroMemory(buffer.as_mut_ptr() as *mut std::ffi::c_void, buffer.len());
    }
}


pub fn protect_memory(buffer: &mut [u8], protect: bool) -> Result<(), Error> {
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_NOACCESS, PAGE_READWRITE};

    let protection = if protect { PAGE_NOACCESS } else { PAGE_READWRITE };

    let mut old_protection = 0u32;

    unsafe {
        let result = VirtualProtect(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            protection,
            &mut old_protection,
        );

        if !result.as_bool() {
            return Err(Error::new(ErrorKind::Other, "Failed to protect memory"));
        }
    }

    Ok(())
}


pub fn get_windows_version() -> String {
    use windows::Win32::System::SystemInformation::GetVersionExW;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    unsafe {
        let mut version_info: OSVERSIONINFOW = std::mem::zeroed();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if GetVersionExW(&mut version_info).as_bool() {
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
    use windows::Win32::System::SystemInformation::GetVersionExW;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    unsafe {
        let mut version_info: OSVERSIONINFOW = std::mem::zeroed();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if GetVersionExW(&mut version_info).as_bool() {
            version_info.dwMajorVersion >= 10
        } else {
            false
        }
    }
}
