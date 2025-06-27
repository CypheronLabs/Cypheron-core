# Cross-Platform Support

PQ-Core provides full support for Windows, macOS, and Linux platforms with platform-specific optimizations and native integrations.

## Supported Platforms

### Windows
- **Versions**: Windows 10, Windows 11, Windows Server 2019/2022
- **Architectures**: x86_64, ARM64 (Windows on ARM)
- **Compilers**: MSVC (recommended), MinGW
- **Features**: 
  - Windows CryptoAPI integration
  - Windows Service support
  - MSVC optimizations
  - Windows Firewall integration

### macOS
- **Versions**: macOS 11.0+ (Big Sur and newer)
- **Architectures**: x86_64 (Intel), ARM64 (Apple Silicon)
- **Features**:
  - Security Framework integration
  - Apple Silicon optimizations
  - launchd service support
  - Native ARM64 performance

### Linux
- **Distributions**: Ubuntu 20.04+, RHEL 8+, Debian 11+, Fedora 35+
- **Architectures**: x86_64, ARM64, RISC-V (experimental)
- **Features**:
  - getrandom() syscall support
  - Hardware acceleration detection
  - systemd integration
  - Container-ready

## Installation by Platform

### Windows Installation

**Option 1: PowerShell Script (Recommended)**
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-org/pq-core/main/scripts/install-windows.ps1" -OutFile "install-pqcore.ps1"
.\install-pqcore.ps1
```

**Option 2: Manual Installation**
```powershell
# Install Rust
winget install Rustlang.Rustup

# Install Git
winget install Git.Git

# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Clone and build
git clone https://github.com/your-org/pq-core.git
cd pq-core
cargo build --release --bin rest-api
```

**Windows-Specific Configuration**:
```toml
# config/windows.toml
[platform]
os = "windows"
use_windows_crypto = true
enable_hardware_acceleration = true

[server]
# Windows tends to prefer more workers
workers = 8

[logging]
# Windows path format
file = "C:\\ProgramData\\PQCore\\logs\\pq-core.log"
```

### macOS Installation

**Option 1: Installation Script**
```bash
curl -fsSL https://raw.githubusercontent.com/your-org/pq-core/main/scripts/install-macos.sh | bash
```

**Option 2: Homebrew (when available)**
```bash
brew tap your-org/pq-core
brew install pq-core
```

**Option 3: Manual Installation**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install rust git pkg-config openssl

# For Apple Silicon, set environment variables
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
export OPENSSL_DIR="/opt/homebrew/opt/openssl"

# Clone and build
git clone https://github.com/your-org/pq-core.git
cd pq-core
cargo build --release --bin rest-api
```

**macOS-Specific Configuration**:
```toml
# config/macos.toml
[platform]
os = "macos"
use_security_framework = true
apple_silicon_optimizations = true  # if on Apple Silicon

[server]
# macOS handles threading well
workers = 6

[logging]
file = "/usr/local/var/log/pq-core/pq-core.log"
```

### Linux Installation

**Option 1: Package Manager (when available)**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install pq-core

# RHEL/CentOS
sudo dnf install pq-core

# Arch Linux
yay -S pq-core
```

**Option 2: Manual Installation**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential pkg-config libssl-dev git

# Install dependencies (RHEL/CentOS)
sudo dnf groupinstall "Development Tools"
sudo dnf install openssl-devel pkg-config git

# Clone and build
git clone https://github.com/your-org/pq-core.git
cd pq-core
cargo build --release --bin rest-api
```

## Platform-Specific Features

### Windows Features

**Windows CryptoAPI Integration**:
```rust
use pq_core::platform::windows;

// Uses CryptGenRandom for secure random generation
let mut buffer = [0u8; 32];
windows::secure_random_bytes(&mut buffer)?;

// Uses SecureZeroMemory for secure cleanup
windows::secure_zero(&mut buffer);
```

**Windows Service**:
```powershell
# Install as Windows Service
sc create PQCoreAPI binPath= "C:\Program Files\PQCore\rest-api.exe --config C:\Program Files\PQCore\config\windows.toml"
sc start PQCoreAPI
```

**Windows Firewall**:
```powershell
# Create firewall rule
New-NetFirewallRule -DisplayName "PQ-Core API" -Direction Inbound -Port 3000 -Protocol TCP -Action Allow
```

### macOS Features

**Security Framework Integration**:
```rust
use pq_core::platform::macos;

// Uses Security Framework's SecRandomCopyBytes
let mut buffer = [0u8; 32];
macos::secure_random_bytes(&mut buffer)?;

// Check if running on Apple Silicon
if macos::is_apple_silicon() {
    println!("Running on Apple Silicon with hardware crypto acceleration");
}
```

**launchd Service**:
```bash
# Install as launchd service
sudo cp com.pqcore.api.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.pqcore.api.plist
```

**Apple Silicon Optimizations**:
```rust
// Automatic detection and optimization
let platform_info = pq_core::get_platform_info();
if platform_info.arch == "aarch64" && platform_info.os == "macOS" {
    // Apple Silicon specific optimizations enabled
    // - Native ARM64 crypto instructions
    // - Efficient core scheduling
    // - Memory layout optimizations
}
```

### Linux Features

**getrandom() Syscall**:
```rust
use pq_core::platform::linux;

// Uses getrandom() syscall or falls back to /dev/urandom
let mut buffer = [0u8; 32];
linux::secure_random_bytes(&mut buffer)?;

// Check hardware security features
let features = linux::check_security_features();
if features.has_hardware_rng {
    println!("Hardware RNG available (RDRAND/RDSEED)");
}
```

**systemd Integration**:
```ini
# /etc/systemd/system/pq-core.service
[Unit]
Description=PQ-Core API Service
After=network.target

[Service]
Type=simple
User=pqcore
ExecStart=/usr/local/bin/rest-api --config /etc/pq-core/linux.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Performance Optimizations by Platform

### Windows Optimizations

- **MSVC Compiler Optimizations**: Uses `/O2` and whole program optimization
- **Windows-Specific CPU Features**: AVX2, AES-NI detection and usage
- **Memory Management**: VirtualAlloc for large memory allocations
- **Thread Pool**: Windows thread pool API integration

### macOS Optimizations

- **Apple Silicon**: Native ARM64 crypto instructions
- **Dispatch Queues**: GCD integration for concurrent operations
- **Accelerate Framework**: Vector operations when available
- **Memory Mapping**: Optimized mmap usage for large keys

### Linux Optimizations

- **CPU Affinity**: Binds crypto operations to performance cores
- **NUMA Awareness**: Optimizes memory allocation on NUMA systems
- **Kernel Features**: Uses latest kernel crypto APIs when available
- **Container Optimization**: Detects and optimizes for container environments

## Building from Source

### Cross-Compilation

**Windows → Linux**:
```bash
# Install cross-compilation target
rustup target add x86_64-unknown-linux-gnu

# Install cross-compiler
sudo apt install gcc-x86-64-linux-gnu

# Build
cargo build --target x86_64-unknown-linux-gnu --release
```

**macOS → Windows**:
```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install mingw
brew install mingw-w64

# Build
cargo build --target x86_64-pc-windows-gnu --release
```

**Linux → macOS**:
```bash
# Install target
rustup target add x86_64-apple-darwin

# Note: Requires macOS SDK and linker
# See: https://github.com/tpoechtrager/osxcross
```

### Platform-Specific Build Flags

**Windows**:
```bash
# Use MSVC
cargo build --target x86_64-pc-windows-msvc --release

# Enable Windows-specific features
cargo build --features windows-crypto --release
```

**macOS**:
```bash
# Apple Silicon
cargo build --target aarch64-apple-darwin --release

# Intel Mac
cargo build --target x86_64-apple-darwin --release

# Enable Security Framework
cargo build --features macos-security --release
```

**Linux**:
```bash
# Enable hardware acceleration
cargo build --features linux-hwaccel --release

# Enable getrandom
cargo build --features getrandom --release
```

## Configuration Examples

### Windows Production Config
```toml
[server]
host = "0.0.0.0"
port = 3000
workers = 8
max_connections = 1000

[security]
api_key_required = true
rate_limit_default = 1000
audit_logging = true
use_windows_crypto = true

[platform]
os = "windows"
enable_hardware_acceleration = true
use_processor_groups = true  # For > 64 cores

[logging]
level = "info"
file = "C:\\ProgramData\\PQCore\\logs\\pq-core.log"
rotation = "daily"
```

### macOS Production Config
```toml
[server]
host = "0.0.0.0"
port = 3000
workers = 6
max_connections = 1000

[security]
api_key_required = true
rate_limit_default = 1000
audit_logging = true
use_security_framework = true

[platform]
os = "macos"
apple_silicon_optimizations = true
use_dispatch_queues = true
enable_accelerate_framework = true

[logging]
level = "info"
file = "/var/log/pq-core/pq-core.log"
use_os_log = true  # macOS unified logging
```

### Linux Production Config
```toml
[server]
host = "0.0.0.0"
port = 3000
workers = 12
max_connections = 2000

[security]
api_key_required = true
rate_limit_default = 2000
audit_logging = true
use_getrandom = true

[platform]
os = "linux"
enable_hardware_acceleration = true
use_cpu_affinity = true
numa_aware = true

[logging]
level = "info"
file = "/var/log/pq-core/pq-core.log"
use_journald = true  # systemd journal integration
```

## Troubleshooting

### Windows Issues

**Build Errors**:
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Set environment variables
$env:VCINSTALLDIR = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC"
```

**Runtime Errors**:
```powershell
# Check Windows version
Get-ComputerInfo | Select WindowsProductName, WindowsVersion

# Check for missing DLLs
dumpbin /dependents rest-api.exe
```

### macOS Issues

**Apple Silicon Build Issues**:
```bash
# Ensure correct Xcode Command Line Tools
sudo xcode-select --install

# Check architecture
file target/aarch64-apple-darwin/release/rest-api

# Rosetta detection
sysctl -n sysctl.proc_translated
```

**Permission Issues**:
```bash
# Fix permissions
sudo chown -R $(whoami) /usr/local/bin/rest-api
sudo chmod +x /usr/local/bin/rest-api

# Check quarantine
xattr -d com.apple.quarantine /usr/local/bin/rest-api
```

### Linux Issues

**Missing Dependencies**:
```bash
# Ubuntu/Debian
sudo apt install build-essential libssl-dev pkg-config

# RHEL/CentOS
sudo dnf groupinstall "Development Tools"
sudo dnf install openssl-devel
```

**Permission Issues**:
```bash
# Check capabilities
getcap /usr/local/bin/rest-api

# Set capabilities for port binding
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/rest-api
```

## Next Steps

- **Security**: Review [Security Best Practices](../security/best-practices.md) for your platform
- **Deployment**: See [Production Deployment](../advanced/deployment.md) guides
- **Monitoring**: Set up [Monitoring & Observability](../advanced/monitoring.md)
- **API Usage**: Start with [Quick Start Guide](quickstart.md)

---

*Ready to deploy on your platform? Check the platform-specific installation scripts in the `/scripts` directory.*