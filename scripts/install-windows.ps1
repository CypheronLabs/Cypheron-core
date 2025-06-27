# PQ-Core Windows Installation Script
# PowerShell script to install PQ-Core on Windows

param(
    [string]$InstallPath = "$env:ProgramFiles\PQCore",
    [switch]$Dev = $false,
    [switch]$Force = $false
)

Write-Host "🚀 PQ-Core Windows Installation Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

# Check Windows version
$winVersion = Get-WmiObject -Class Win32_OperatingSystem
Write-Host "🖥️  Detected: $($winVersion.Caption) $($winVersion.Version)" -ForegroundColor Green

if ([int]$winVersion.BuildNumber -lt 10240) {
    Write-Warning "Windows 10 or newer is recommended for optimal security features."
}

# Install prerequisites
Write-Host "📦 Installing prerequisites..." -ForegroundColor Yellow

# Check for Rust
if (-not (Get-Command "rustc" -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Rust..." -ForegroundColor Yellow
    
    # Download and install Rust
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupPath = "$env:TEMP\rustup-init.exe"
    
    try {
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath
        Start-Process -FilePath $rustupPath -ArgumentList "--default-host", "x86_64-pc-windows-msvc", "--default-toolchain", "stable", "-y" -Wait
        
        # Refresh environment variables
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        Write-Host "✅ Rust installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Rust: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "✅ Rust already installed" -ForegroundColor Green
}

# Check for Git
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Git..." -ForegroundColor Yellow
    
    # Install Git using winget if available
    if (Get-Command "winget" -ErrorAction SilentlyContinue) {
        winget install --id Git.Git -e --source winget
    } else {
        Write-Warning "Please install Git manually from https://git-scm.com/download/win"
        Read-Host "Press Enter after installing Git to continue..."
    }
}

# Install Visual Studio Build Tools if needed
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    Write-Host "Installing Visual Studio Build Tools..." -ForegroundColor Yellow
    
    # Download and install VS Build Tools
    $vsBuildToolsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsBuildToolsPath = "$env:TEMP\vs_buildtools.exe"
    
    try {
        Invoke-WebRequest -Uri $vsBuildToolsUrl -OutFile $vsBuildToolsPath
        Start-Process -FilePath $vsBuildToolsPath -ArgumentList "--quiet", "--wait", "--add", "Microsoft.VisualStudio.Workload.VCTools", "--includeRecommended" -Wait
        Write-Host "✅ Visual Studio Build Tools installed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to install VS Build Tools automatically. Please install manually."
    }
}

# Clone and build PQ-Core
Write-Host "📥 Cloning PQ-Core repository..." -ForegroundColor Yellow

$sourceDir = "$env:TEMP\pq-core"
if (Test-Path $sourceDir) {
    if ($Force) {
        Remove-Item -Path $sourceDir -Recurse -Force
    } else {
        Write-Host "Source directory already exists. Use -Force to overwrite." -ForegroundColor Yellow
    }
}

try {
    git clone https://github.com/your-org/pq-core.git $sourceDir
    Set-Location $sourceDir
    
    Write-Host "🔨 Building PQ-Core..." -ForegroundColor Yellow
    
    if ($Dev) {
        cargo build --workspace
    } else {
        cargo build --release --workspace
    }
    
    Write-Host "✅ Build completed successfully" -ForegroundColor Green
}
catch {
    Write-Error "Build failed: $($_.Exception.Message)"
    exit 1
}

# Install to target directory
Write-Host "📁 Installing to $InstallPath..." -ForegroundColor Yellow

if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

$binaryPath = if ($Dev) { "target\debug" } else { "target\release" }

# Copy binaries
Copy-Item "$sourceDir\$binaryPath\rest-api.exe" "$InstallPath\" -Force
Copy-Item "$sourceDir\$binaryPath\cli.exe" "$InstallPath\" -Force

# Copy configuration files
$configDir = "$InstallPath\config"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

# Create Windows-specific configuration
$windowsConfig = @"
[server]
host = "127.0.0.1"
port = 3000
workers = 4

[security]
api_key_required = true
rate_limit_default = 60
audit_logging = true

[algorithms]
enabled_kems = ["kyber512", "kyber768", "kyber1024"]
enabled_signatures = ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024"]
enabled_hybrid = true

[logging]
level = "info"
format = "json"
file = "$($InstallPath -replace '\\', '\\')\logs\pq-core.log"

[platform]
os = "windows"
use_windows_crypto = true
enable_hardware_acceleration = true
"@

$windowsConfig | Out-File -FilePath "$configDir\windows.toml" -Encoding UTF8

# Create logs directory
$logsDir = "$InstallPath\logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallPath", "Machine")
    Write-Host "✅ Added PQ-Core to system PATH" -ForegroundColor Green
}

# Create Windows Service (optional)
function Install-PQCoreService {
    $serviceName = "PQCoreAPI"
    $serviceDisplayName = "PQ-Core API Service"
    $serviceDescription = "Post-Quantum Cryptography API Service"
    $servicePath = "$InstallPath\rest-api.exe"
    $serviceArgs = "--config `"$configDir\windows.toml`""
    
    # Check if service already exists
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Service $serviceName already exists. Stopping and removing..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName
    }
    
    # Create new service
    $result = sc.exe create $serviceName binPath= "`"$servicePath`" $serviceArgs" DisplayName= $serviceDisplayName start= auto
    
    if ($LASTEXITCODE -eq 0) {
        sc.exe description $serviceName $serviceDescription
        Write-Host "✅ Windows Service created: $serviceName" -ForegroundColor Green
        Write-Host "   Start with: Start-Service $serviceName" -ForegroundColor Gray
    } else {
        Write-Warning "Failed to create Windows Service"
    }
}

$installService = Read-Host "Install as Windows Service? (y/N)"
if ($installService -eq "y" -or $installService -eq "Y") {
    Install-PQCoreService
}

# Create firewall rule
$firewallRule = Read-Host "Create Windows Firewall rule for port 3000? (y/N)"
if ($firewallRule -eq "y" -or $firewallRule -eq "Y") {
    try {
        New-NetFirewallRule -DisplayName "PQ-Core API" -Direction Inbound -Port 3000 -Protocol TCP -Action Allow
        Write-Host "✅ Firewall rule created for port 3000" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to create firewall rule: $($_.Exception.Message)"
    }
}

# Cleanup
Set-Location $env:USERPROFILE
Remove-Item -Path $sourceDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "🎉 PQ-Core installation completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Installation directory: $InstallPath" -ForegroundColor White
Write-Host "Configuration file: $configDir\windows.toml" -ForegroundColor White
Write-Host ""
Write-Host "To start PQ-Core:" -ForegroundColor Yellow
Write-Host "  rest-api.exe --config `"$configDir\windows.toml`"" -ForegroundColor White
Write-Host ""
Write-Host "For help:" -ForegroundColor Yellow
Write-Host "  rest-api.exe --help" -ForegroundColor White
Write-Host "  cli.exe --help" -ForegroundColor White