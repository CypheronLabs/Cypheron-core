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
    use core_foundation::base::{CFType, TCFType};
    use security_framework::random::SecRandom;

    match SecRandom::system_random().copy_bytes(buffer) {
        Ok(_) => Ok(()),
        Err(e) => {
            Err(Error::new(ErrorKind::Other, format!("Failed to generate random bytes: {:?}", e)))
        }
    }
}

pub fn secure_random_bytes_dev_urandom(buffer: &mut [u8]) -> Result<(), Error> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buffer)?;
    Ok(())
}

pub fn secure_zero(buffer: &mut [u8]) {
    unsafe {
        libc::memset_s(buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0, buffer.len());
    }
}

pub fn secure_zero_bzero(buffer: &mut [u8]) {
    unsafe {
        libc::explicit_bzero(buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
    }
}

pub fn protect_memory(buffer: &mut [u8], protect: bool) -> Result<(), Error> {
    use libc::{mprotect, PROT_NONE, PROT_READ, PROT_WRITE};

    let protection = if protect { PROT_NONE } else { PROT_READ | PROT_WRITE };

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let addr = buffer.as_mut_ptr() as usize;
    let aligned_addr = addr & !(page_size - 1);
    let aligned_len = ((addr + buffer.len() + page_size - 1) & !(page_size - 1)) - aligned_addr;

    unsafe {
        if mprotect(aligned_addr as *mut libc::c_void, aligned_len, protection) != 0 {
            return Err(Error::new(ErrorKind::Other, "Failed to protect memory"));
        }
    }

    Ok(())
}

pub fn get_macos_version() -> String {
    use std::process::Command;

    if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
        if let Ok(version) = String::from_utf8(output.stdout) {
            return format!("macOS {}", version.trim());
        }
    }

    "macOS (version unknown)".to_string()
}

pub fn is_apple_silicon() -> bool {
    std::env::consts::ARCH == "aarch64"
}

pub fn get_apple_silicon_info() -> Option<AppleSiliconInfo> {
    if !is_apple_silicon() {
        return None;
    }

    use std::process::Command;

    let chip_name = if let Ok(output) =
        Command::new("sysctl").arg("-n").arg("machdep.cpu.brand_string").output()
    {
        String::from_utf8(output.stdout)
            .unwrap_or_else(|_| "Apple Silicon".to_string())
            .trim()
            .to_string()
    } else {
        "Apple Silicon".to_string()
    };

    Some(AppleSiliconInfo {
        chip_name,
        has_crypto_extensions: true,
        has_sve: false,
        performance_cores: get_performance_core_count(),
        efficiency_cores: get_efficiency_core_count(),
    })
}

#[derive(Debug, Clone)]
pub struct AppleSiliconInfo {
    pub chip_name: String,
    pub has_crypto_extensions: bool,
    pub has_sve: bool,
    pub performance_cores: Option<u32>,
    pub efficiency_cores: Option<u32>,
}

fn get_performance_core_count() -> Option<u32> {
    use std::process::Command;

    if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.perflevel0.logicalcpu").output() {
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    } else {
        None
    }
}

fn get_efficiency_core_count() -> Option<u32> {
    use std::process::Command;

    if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.perflevel1.logicalcpu").output() {
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    } else {
        None
    }
}

pub fn optimize_for_apple_silicon() -> Result<(), Error> {
    if !is_apple_silicon() {
        return Ok(());
    }

    unsafe {
        if libc::setpriority(libc::PRIO_PROCESS, 0, -5) != 0 {
            crate::security::secure_warn!("Could not set process priority");
        }
    }

    Ok(())
}

pub fn is_running_under_rosetta() -> bool {
    use std::process::Command;

    if let Ok(output) = Command::new("sysctl").arg("-n").arg("sysctl.proc_translated").output() {
        if let Ok(result) = String::from_utf8(output.stdout) {
            return result.trim() == "1";
        }
    }

    false
}
