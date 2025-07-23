#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

use std::io::Error;

pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    #[cfg(target_os = "windows")]
    return windows::secure_random_bytes(buffer);

    #[cfg(target_os = "macos")]
    return macos::secure_random_bytes(buffer);

    #[cfg(target_os = "linux")]
    return linux::secure_random_bytes(buffer);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buffer);
        Ok(())
    }
}

pub fn secure_zero(buffer: &mut [u8]) {
    #[cfg(target_os = "windows")]
    windows::secure_zero(buffer);

    #[cfg(target_os = "macos")]
    macos::secure_zero(buffer);

    #[cfg(target_os = "linux")]
    linux::secure_zero(buffer);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        use zeroize::Zeroize;
        buffer.zeroize();
    }
}

pub fn get_platform_info() -> PlatformInfo {
    PlatformInfo {
        os: get_os_name(),
        arch: std::env::consts::ARCH,
        cpu_features: get_cpu_features(),
        has_hardware_rng: has_hardware_rng(),
        has_aes_ni: has_aes_ni(),
        has_avx2: has_avx2(),
    }
}

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub cpu_features: Vec<String>,
    pub has_hardware_rng: bool,
    pub has_aes_ni: bool,
    pub has_avx2: bool,
}

fn get_os_name() -> &'static str {
    #[cfg(target_os = "windows")]
    return "Windows";

    #[cfg(target_os = "macos")]
    return "macOS";

    #[cfg(target_os = "linux")]
    return "Linux";

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return "Unknown";
}

fn get_cpu_features() -> Vec<String> {
    let mut features = Vec::new();

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") {
            features.push("AES-NI".to_string());
        }
        if is_x86_feature_detected!("avx2") {
            features.push("AVX2".to_string());
        }
        if is_x86_feature_detected!("rdrand") {
            features.push("RDRAND".to_string());
        }
        if is_x86_feature_detected!("rdseed") {
            features.push("RDSEED".to_string());
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        features.push("ARM64".to_string());

        #[cfg(target_os = "macos")]
        {
            features.push("Apple Silicon".to_string());
            if std::arch::is_aarch64_feature_detected!("aes") {
                features.push("ARM64-AES".to_string());
            }
            if std::arch::is_aarch64_feature_detected!("sha2") {
                features.push("ARM64-SHA2".to_string());
            }
            if std::arch::is_aarch64_feature_detected!("sha3") {
                features.push("ARM64-SHA3".to_string());
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                features.push("ARM64-AES".to_string());
            }
            if std::arch::is_aarch64_feature_detected!("sha2") {
                features.push("ARM64-SHA2".to_string());
            }
            if std::arch::is_aarch64_feature_detected!("neon") {
                features.push("ARM64-NEON".to_string());
            }
        }
    }

    features
}

fn has_hardware_rng() -> bool {
    #[cfg(target_arch = "x86_64")]
    return is_x86_feature_detected!("rdrand") || is_x86_feature_detected!("rdseed");

    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("rand");

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return false;
}

fn has_aes_ni() -> bool {
    #[cfg(target_arch = "x86_64")]
    return is_x86_feature_detected!("aes");

    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("aes");

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return false;
}

fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    return is_x86_feature_detected!("avx2");

    #[cfg(not(target_arch = "x86_64"))]
    return false;
}
