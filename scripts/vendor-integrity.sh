#!/bin/bash
set -eu

# Vendor Integrity Verification Script for Cloud Run Deployment
# Minimal version focused on Cloud Run builds

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$PROJECT_ROOT/core-lib/vendor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if vendor directory exists
check_vendor_directory() {
    if [[ ! -d "$VENDOR_DIR" ]]; then
        log_error "Vendor directory not found: $VENDOR_DIR"
        return 1
    fi
    
    # Check for essential crypto algorithm directories
    local required_dirs=("kyber" "dilithium" "falcon")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$VENDOR_DIR/$dir" ]]; then
            log_error "Required crypto directory missing: $VENDOR_DIR/$dir"
            return 1
        fi
    done
    
    log_success "Vendor directory structure verified"
    return 0
}

# Basic file existence check for critical crypto files
verify_crypto_files() {
    log_info "Verifying critical crypto implementation files..."
    
    # Check Kyber files
    local kyber_files=("ref/kem.c" "ref/indcpa.c" "ref/api.h")
    for file in "${kyber_files[@]}"; do
        if [[ ! -f "$VENDOR_DIR/kyber/$file" ]]; then
            log_error "Missing Kyber file: $file"
            return 1
        fi
    done
    
    # Check Dilithium files  
    local dilithium_files=("ref/sign.c" "ref/api.h")
    for file in "${dilithium_files[@]}"; do
        if [[ ! -f "$VENDOR_DIR/dilithium/$file" ]]; then
            log_error "Missing Dilithium file: $file"
            return 1
        fi
    done
    
    # Check Falcon files
    local falcon_files=("falcon.c" "falcon.h")
    for file in "${falcon_files[@]}"; do
        if [[ ! -f "$VENDOR_DIR/falcon/$file" ]]; then
            log_error "Missing Falcon file: $file"
            return 1
        fi
    done
    
    log_success "Critical crypto files verified"
    return 0
}

# Main verification function
verify_vendor_integrity() {
    log_info "Starting vendor integrity verification for Cloud Run deployment..."
    
    # Basic checks for Cloud Run
    if ! check_vendor_directory; then
        return 1
    fi
    
    if ! verify_crypto_files; then
        return 1
    fi
    
    log_success "Vendor integrity verification completed successfully"
    log_info "Ready for Cloud Run deployment"
    return 0
}

# Handle different commands
case "${1:-verify}" in
    "verify")
        verify_vendor_integrity
        ;;
    "check")
        verify_vendor_integrity
        ;;
    *)
        echo "Usage: $0 [verify|check]"
        echo "  verify - Verify vendor code integrity (default)"
        echo "  check  - Same as verify"
        exit 1
        ;;
esac