use std::fs;
use std::io::Error;

pub mod platform {
    use super::*;

    pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
        if try_getrandom(buffer).is_ok() {
            return Ok(());
        }

        secure_random_bytes_dev_urandom(buffer)
    }

    pub fn secure_zero(buffer: &mut [u8]) {
        unsafe {
            if has_explicit_bzero() {
                libc::explicit_bzero(buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
            } else {
                secure_zero_fallback(buffer);
            }
        }
    }
}

fn try_getrandom(buffer: &mut [u8]) -> Result<(), Error> {
    unsafe {
        let result = libc::syscall(libc::SYS_getrandom, buffer.as_mut_ptr(), buffer.len(), 0);

        if result < 0 {
            return Err(Error::other("getrandom syscall failed"));
        }

        if result as usize != buffer.len() {
            return Err(Error::other("getrandom returned insufficient bytes"));
        }
    }

    Ok(())
}

fn secure_random_bytes_dev_urandom(buffer: &mut [u8]) -> Result<(), Error> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom")
        .map_err(|e| Error::other(format!("Failed to open /dev/urandom: {}", e)))?;

    file.read_exact(buffer)
        .map_err(|e| Error::other(format!("Failed to read from /dev/urandom: {}", e)))?;

    Ok(())
}

fn has_explicit_bzero() -> bool {
    true
}

fn secure_zero_fallback(buffer: &mut [u8]) {
    use zeroize::Zeroize;
    buffer.zeroize();
}

pub fn protect_memory(buffer: &mut [u8], protect: bool) -> Result<(), Error> {
    use libc::{mprotect, PROT_NONE, PROT_READ, PROT_WRITE};

    let protection = if protect {
        PROT_NONE
    } else {
        PROT_READ | PROT_WRITE
    };

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let addr = buffer.as_mut_ptr() as usize;
    let aligned_addr = addr & !(page_size - 1);
    let aligned_len = ((addr + buffer.len() + page_size - 1) & !(page_size - 1)) - aligned_addr;

    unsafe {
        if mprotect(aligned_addr as *mut libc::c_void, aligned_len, protection) != 0 {
            return Err(Error::other("Failed to protect memory"));
        }
    }

    Ok(())
}

pub fn get_linux_distro() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("PRETTY_NAME=") {
                let name = line.strip_prefix("PRETTY_NAME=").unwrap_or("");
                return name.trim_matches('"').to_string();
            }
        }
    }

    if let Ok(content) = fs::read_to_string("/etc/lsb-release") {
        for line in content.lines() {
            if line.starts_with("DISTRIB_DESCRIPTION=") {
                let name = line.strip_prefix("DISTRIB_DESCRIPTION=").unwrap_or("");
                return name.trim_matches('"').to_string();
            }
        }
    }

    "Linux (distribution unknown)".to_string()
}

pub fn get_kernel_version() -> String {
    if let Ok(version) = fs::read_to_string("/proc/version") {
        if let Some(end) = version.find(' ') {
            return version[..end].to_string();
        }
    }

    "Unknown kernel".to_string()
}

#[derive(Debug, Clone, Default)]
pub struct CpuInfo {
    pub model_name: String,
    pub cores: u32,
    pub has_aes: bool,
    pub has_avx2: bool,
    pub has_rdrand: bool,
    pub has_rdseed: bool,
}

pub fn get_cpu_info() -> CpuInfo {
    use std::collections::HashMap;

    let mut info = CpuInfo::default();

    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        let mut properties = HashMap::new();

        for line in content.lines() {
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim();
                let value = line[pos + 1..].trim();
                properties.insert(key.to_string(), value.to_string());
            }
        }

        if let Some(model) = properties.get("model name") {
            info.model_name = model.clone();
        }

        if let Some(flags) = properties.get("flags") {
            info.has_aes = flags.contains("aes");
            info.has_avx2 = flags.contains("avx2");
            info.has_rdrand = flags.contains("rdrand");
            info.has_rdseed = flags.contains("rdseed");
        }

        if let Some(cores) = properties.get("cpu cores") {
            info.cores = cores.parse().unwrap_or(1);
        }
    }

    info
}

pub fn optimize_for_crypto() -> Result<(), Error> {
    set_cpu_affinity()?;

    unsafe {
        if libc::setpriority(libc::PRIO_PROCESS, 0, -5) != 0 {
            eprintln!("Warning: Could not set process priority (requires privileges)");
        }
    }

    Ok(())
}

fn set_cpu_affinity() -> Result<(), Error> {
    let cpu_count = num_cpus::get();

    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpu_set);

        for i in 0..cpu_count {
            libc::CPU_SET(i, &mut cpu_set);
        }

        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpu_set) != 0 {
            return Err(Error::other("Failed to set CPU affinity"));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    pub has_hardware_rng: bool,
    pub has_aes_ni: bool,
    pub has_avx2: bool,
    pub has_secure_boot: bool,
    pub has_tpm: bool,
}

pub fn check_security_features() -> SecurityFeatures {
    let cpu_info = get_cpu_info();

    SecurityFeatures {
        has_hardware_rng: cpu_info.has_rdrand || cpu_info.has_rdseed,
        has_aes_ni: cpu_info.has_aes,
        has_avx2: cpu_info.has_avx2,
        has_secure_boot: check_secure_boot(),
        has_tpm: check_tpm(),
    }
}

fn check_secure_boot() -> bool {
    if let Ok(content) = fs::read_to_string(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    ) {
        content.len() > 4 && content.as_bytes()[4] == 1
    } else {
        false
    }
}

fn check_tpm() -> bool {
    fs::metadata("/dev/tpm0").is_ok() || fs::metadata("/dev/tpmrm0").is_ok()
}

#[cfg(feature = "seccomp-bpf")]
pub mod sandbox {
    use std::io::Error;

    pub fn enable_crypto_sandbox() -> Result<(), Error> {
        use libseccomp::*;

        let mut ctx = match ScmpFilterContext::new_filter(ScmpAction::KillProcess) {
            Ok(ctx) => ctx,
            Err(e) => {
                return Err(Error::other(format!(
                    "Failed to create seccomp context: {}",
                    e
                )))
            }
        };

        let allowed_syscalls = [
            "read",
            "write",
            "getrandom",
            "mmap",
            "munmap",
            "mprotect",
            "mlock",
            "munlock",
            "brk",
            "clock_gettime",
            "gettimeofday",
            "exit_group",
            "exit",
            "futex",
            "sched_yield",
            "rt_sigreturn",
            "sigaltstack",
        ];

        for syscall_name in &allowed_syscalls {
            let syscall = ScmpSyscall::from_name(syscall_name).map_err(|e| {
                Error::other(format!("Failed to resolve syscall {}: {}", syscall_name, e))
            })?;

            ctx.add_rule(ScmpAction::Allow, syscall).map_err(|e| {
                Error::other(format!(
                    "Failed to add seccomp rule for {}: {}",
                    syscall_name, e
                ))
            })?;
        }

        ctx.load()
            .map_err(|e| Error::other(format!("Failed to load seccomp filter: {}", e)))?;

        Ok(())
    }

    pub fn enable_production_hardening() -> Result<(), Error> {
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(Error::other("Failed to set NO_NEW_PRIVS"));
            }
        }

        enable_crypto_sandbox()?;

        Ok(())
    }
}

#[cfg(feature = "seccomp-bpf")]
pub use sandbox::enable_production_hardening as enable_production_security;

#[cfg(not(feature = "seccomp-bpf"))]
pub fn enable_production_security() -> Result<(), Error> {
    eprintln!("Warning: seccomp-bpf feature not enabled - sandbox not active");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_bytes() {
        let mut buffer = [0u8; 32];
        platform::secure_random_bytes(&mut buffer).expect("Failed to generate random bytes");

        assert!(buffer.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_secure_zero() {
        let mut buffer = [0xAA; 32];
        platform::secure_zero(&mut buffer);

        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_cpu_info() {
        let info = get_cpu_info();
        println!("CPU: {}, cores: {}", info.model_name, info.cores);
    }

    #[test]
    fn test_security_features() {
        let features = check_security_features();
        println!("Security features: {:?}", features);
    }

    #[cfg(feature = "seccomp-bpf")]
    #[test]
    fn test_seccomp_allows_getrandom() {
        let mut buffer = [0u8; 16];
        let result = try_getrandom(&mut buffer);
        assert!(result.is_ok());
    }
}
