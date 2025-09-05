#!/bin/bash

# Copyright 2025 Cypheron Labs, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$PROJECT_ROOT/core-lib/vendor"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 <command>"
    echo "Commands:"
    echo "  verify    - Verify integrity of vendor code"
    echo "  update    - Update SHA256SUMS files"
    echo "  help      - Show this help message"
    exit 1
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 command not found. Please install it first."
        return 1
    fi
}

verify_directory() {
    local dir="$1"
    local checksum_file="$dir/SHA256SUMS"
    
    if [[ ! -f "$checksum_file" ]]; then
        log_warn "No SHA256SUMS file found in $dir, skipping verification"
        return 0
    fi
    
    log_info "Verifying integrity of $dir"
    
    pushd "$dir" > /dev/null
    
    if sha256sum -c SHA256SUMS --quiet 2>/dev/null; then
        log_info "✓ Integrity verification passed for $dir"
        popd > /dev/null
        return 0
    else
        log_error "✗ Integrity verification failed for $dir"
        popd > /dev/null
        return 1
    fi
}

update_checksums() {
    local dir="$1"
    
    log_info "Updating checksums for $dir"
    
    pushd "$dir" > /dev/null
    
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.S" -o -name "*.s" \) \
        | sort | xargs sha256sum > SHA256SUMS
    
    log_info "✓ Updated SHA256SUMS for $dir"
    popd > /dev/null
}

verify_all() {
    check_command "sha256sum" || return 1
    
    if [[ ! -d "$VENDOR_DIR" ]]; then
        log_error "Vendor directory not found: $VENDOR_DIR"
        return 1
    fi
    
    local failed=0
    
    for crypto_lib in kyber dilithium falcon sphincsplus; do
        if [[ -d "$VENDOR_DIR/$crypto_lib" ]]; then
            if ! verify_directory "$VENDOR_DIR/$crypto_lib"; then
                failed=1
            fi
        else
            log_warn "Cryptographic library directory not found: $crypto_lib"
        fi
    done
    
    if [[ $failed -eq 0 ]]; then
        log_info " All vendor code integrity checks passed!"
        return 0
    else
        log_error " Some integrity checks failed. See output above."
        return 1
    fi
}

update_all() {
    check_command "sha256sum" || return 1
    
    if [[ ! -d "$VENDOR_DIR" ]]; then
        log_error "Vendor directory not found: $VENDOR_DIR"
        return 1
    fi
    
    for crypto_lib in kyber dilithium falcon sphincsplus; do
        if [[ -d "$VENDOR_DIR/$crypto_lib" ]]; then
            update_checksums "$VENDOR_DIR/$crypto_lib"
        else
            log_warn "Cryptographic library directory not found: $crypto_lib"
        fi
    done
    
    log_info "🎉 All checksum files updated!"
}

main() {
    case "${1:-}" in
        verify)
            verify_all
            ;;
        update)
            update_all
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: ${1:-}"
            usage
            ;;
    esac
}

main "$@"