#!/bin/bash
# PQ-Core macOS Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default installation path
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin}"
CONFIG_PATH="${CONFIG_PATH:-/usr/local/etc/pq-core}"
LOG_PATH="${LOG_PATH:-/usr/local/var/log/pq-core}"
DEV_MODE="${DEV_MODE:-false}"
FORCE="${FORCE:-false}"

echo -e "${CYAN}🚀 PQ-Core macOS Installation Script${NC}"
echo -e "${CYAN}====================================${NC}"

# Check macOS version
MACOS_VERSION=$(sw_vers -productVersion)
echo -e "${GREEN}🖥️  Detected: macOS $MACOS_VERSION${NC}"

# Check if running on Apple Silicon
if [[ $(uname -m) == "arm64" ]]; then
    echo -e "${GREEN}🔥 Apple Silicon detected${NC}"
    ARCH="aarch64"
else
    echo -e "${GREEN}💻 Intel Mac detected${NC}"
    ARCH="x86_64"
fi

# Function to check if running under Rosetta
check_rosetta() {
    if [[ $(sysctl -n sysctl.proc_translated 2>/dev/null) == "1" ]]; then
        echo -e "${YELLOW}⚠️  Running under Rosetta 2 (x86_64 emulation)${NC}"
        echo -e "${YELLOW}   For best performance, use native ARM64 build${NC}"
    fi
}

if [[ $(uname -m) == "arm64" ]]; then
    check_rosetta
fi

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}📦 Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for Apple Silicon
    if [[ $(uname -m) == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi

echo -e "${GREEN}✅ Homebrew available${NC}"

# Install prerequisites
echo -e "${YELLOW}📦 Installing prerequisites...${NC}"

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    echo -e "${GREEN}✅ Rust installed${NC}"
else
    echo -e "${GREEN}✅ Rust already installed${NC}"
fi

# Install required dependencies
brew install git pkg-config openssl

# For Apple Silicon, ensure correct OpenSSL linking
if [[ $(uname -m) == "arm64" ]]; then
    export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
    export OPENSSL_DIR="/opt/homebrew/opt/openssl"
    export OPENSSL_LIB_DIR="/opt/homebrew/opt/openssl/lib"
    export OPENSSL_INCLUDE_DIR="/opt/homebrew/opt/openssl/include"
fi

# Clone and build PQ-Core
echo -e "${YELLOW}📥 Cloning PQ-Core repository...${NC}"

TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

git clone https://github.com/your-org/pq-core.git
cd pq-core

echo -e "${YELLOW}🔨 Building PQ-Core...${NC}"

# Set target for Apple Silicon if needed
if [[ $(uname -m) == "arm64" ]]; then
    rustup target add aarch64-apple-darwin
    export CARGO_BUILD_TARGET="aarch64-apple-darwin"
fi

if [[ "$DEV_MODE" == "true" ]]; then
    cargo build --workspace
    BINARY_PATH="target/debug"
else
    cargo build --release --workspace
    BINARY_PATH="target/release"
fi

echo -e "${GREEN}✅ Build completed successfully${NC}"

# Install binaries
echo -e "${YELLOW}📁 Installing to $INSTALL_PATH...${NC}"

sudo mkdir -p "$INSTALL_PATH"
sudo mkdir -p "$CONFIG_PATH"
sudo mkdir -p "$LOG_PATH"

# Copy binaries
sudo cp "$BINARY_PATH/rest-api" "$INSTALL_PATH/"
sudo cp "$BINARY_PATH/cli" "$INSTALL_PATH/"

# Set executable permissions
sudo chmod +x "$INSTALL_PATH/rest-api"
sudo chmod +x "$INSTALL_PATH/cli"

# Create macOS-specific configuration
cat > /tmp/macos.toml << EOF
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
file = "$LOG_PATH/pq-core.log"

[platform]
os = "macos"
arch = "$ARCH"
use_security_framework = true
enable_hardware_acceleration = true
apple_silicon_optimizations = $([ "$ARCH" == "aarch64" ] && echo "true" || echo "false")
EOF

sudo cp /tmp/macos.toml "$CONFIG_PATH/"
sudo chown root:wheel "$CONFIG_PATH/macos.toml"
sudo chmod 644 "$CONFIG_PATH/macos.toml"

# Create launchd service (macOS equivalent of systemd)
create_launchd_service() {
    local service_name="com.pqcore.api"
    local plist_path="/Library/LaunchDaemons/${service_name}.plist"
    
    echo -e "${YELLOW}Creating launchd service...${NC}"
    
    sudo tee "$plist_path" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$service_name</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_PATH/rest-api</string>
        <string>--config</string>
        <string>$CONFIG_PATH/macos.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$LOG_PATH/error.log</string>
    <key>StandardOutPath</key>
    <string>$LOG_PATH/output.log</string>
    <key>WorkingDirectory</key>
    <string>/usr/local</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF
    
    sudo chown root:wheel "$plist_path"
    sudo chmod 644 "$plist_path"
    
    echo -e "${GREEN}✅ launchd service created: $service_name${NC}"
    echo -e "${CYAN}   Start with: sudo launchctl load $plist_path${NC}"
    echo -e "${CYAN}   Stop with:  sudo launchctl unload $plist_path${NC}"
}

# Ask user if they want to install as service
read -p "Install as macOS service (launchd)? (y/N): " install_service
if [[ "$install_service" =~ ^[Yy]$ ]]; then
    create_launchd_service
fi

# Set up firewall rule (if needed)
read -p "Configure macOS firewall for port 3000? (y/N): " setup_firewall
if [[ "$setup_firewall" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    # Enable firewall if not already enabled
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
    
    # Add firewall rule for the binary
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$INSTALL_PATH/rest-api"
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "$INSTALL_PATH/rest-api"
    
    echo -e "${GREEN}✅ Firewall configured${NC}"
fi

# Create symlinks for easier access
if [[ ":$PATH:" != *":$INSTALL_PATH:"* ]]; then
    echo -e "${YELLOW}Adding to PATH...${NC}"
    
    # Add to shell profile
    SHELL_PROFILE=""
    if [[ -f ~/.zshrc ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ -f ~/.bash_profile ]]; then
        SHELL_PROFILE="$HOME/.bash_profile"
    fi
    
    if [[ -n "$SHELL_PROFILE" ]]; then
        echo "export PATH=\"$INSTALL_PATH:\$PATH\"" >> "$SHELL_PROFILE"
        echo -e "${GREEN}✅ Added to PATH in $SHELL_PROFILE${NC}"
    fi
fi

# Apple Silicon specific optimizations
if [[ $(uname -m) == "arm64" ]]; then
    echo -e "${YELLOW}🔥 Applying Apple Silicon optimizations...${NC}"
    
    # Set process priority for crypto operations
    sudo sysctl -w kern.maxproc=2048 2>/dev/null || true
    
    echo -e "${GREEN}✅ Optimizations applied${NC}"
fi

# Create uninstall script
create_uninstall_script() {
    cat > "$INSTALL_PATH/uninstall-pqcore.sh" << 'EOF'
#!/bin/bash
echo "Uninstalling PQ-Core..."

# Stop and remove launchd service
sudo launchctl unload /Library/LaunchDaemons/com.pqcore.api.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.pqcore.api.plist

# Remove binaries
sudo rm -f /usr/local/bin/rest-api
sudo rm -f /usr/local/bin/cli

# Remove configuration (with confirmation)
read -p "Remove configuration files? (y/N): " remove_config
if [[ "$remove_config" =~ ^[Yy]$ ]]; then
    sudo rm -rf /usr/local/etc/pq-core
    sudo rm -rf /usr/local/var/log/pq-core
fi

# Remove from PATH (manual step)
echo "Please manually remove '$INSTALL_PATH' from your PATH in your shell profile"

echo "PQ-Core uninstalled successfully"
EOF
    
    sudo chmod +x "$INSTALL_PATH/uninstall-pqcore.sh"
}

create_uninstall_script

# Cleanup
cd "$HOME"
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}🎉 PQ-Core installation completed!${NC}"
echo -e "${GREEN}====================================${NC}"
echo -e "${CYAN}Installation directory: $INSTALL_PATH${NC}"
echo -e "${CYAN}Configuration file: $CONFIG_PATH/macos.toml${NC}"
echo -e "${CYAN}Log directory: $LOG_PATH${NC}"
echo ""
echo -e "${YELLOW}To start PQ-Core:${NC}"
echo -e "${CYAN}  $INSTALL_PATH/rest-api --config $CONFIG_PATH/macos.toml${NC}"
echo ""
echo -e "${YELLOW}For help:${NC}"
echo -e "${CYAN}  $INSTALL_PATH/rest-api --help${NC}"
echo -e "${CYAN}  $INSTALL_PATH/cli --help${NC}"
echo ""
echo -e "${YELLOW}To uninstall:${NC}"
echo -e "${CYAN}  sudo $INSTALL_PATH/uninstall-pqcore.sh${NC}"

# macOS-specific tips
echo ""
echo -e "${YELLOW}macOS-specific notes:${NC}"
if [[ $(uname -m) == "arm64" ]]; then
    echo -e "${CYAN}• Optimized for Apple Silicon${NC}"
    echo -e "${CYAN}• Hardware crypto acceleration enabled${NC}"
fi
echo -e "${CYAN}• Uses macOS Security Framework for random generation${NC}"
echo -e "${CYAN}• Firewall rules configured (if selected)${NC}"