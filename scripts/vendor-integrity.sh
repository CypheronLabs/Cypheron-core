#!/bin/bash

# Vendor Code Integrity Verification Script
# This script verifies the integrity of vendor cryptographic libraries
# and provides secure update mechanisms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_DIR="${PROJECT_ROOT}/core-lib/vendor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Function to verify SHA256 checksums
verify_checksums() {
    local algo_dir="$1"
    local checksum_file="${algo_dir}/SHA256SUMS"
    
    if [[ ! -f "${checksum_file}" ]]; then
        log_warning "No SHA256SUMS found for $(basename "${algo_dir}")"
        return 1
    fi
    
    log_info "Verifying checksums for $(basename "${algo_dir}")..."
    
    # Change to algorithm directory for relative paths
    pushd "${algo_dir}" > /dev/null
    
    local verification_failed=0
    
    # Read each line from SHA256SUMS
    while IFS= read -r line; do
        # Skip empty lines and lines starting with #
        if [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Extract hash and filename
        if [[ "${line}" =~ ^([a-f0-9]{64})[[:space:]]+(.+)$ ]]; then
            local expected_hash="${BASH_REMATCH[1]}"
            local filename="${BASH_REMATCH[2]}"
            
            if [[ -f "${filename}" ]]; then
                local actual_hash=$(sha256sum "${filename}" | cut -d' ' -f1)
                
                if [[ "${actual_hash}" == "${expected_hash}" ]]; then
                    log_success "✓ ${filename}"
                else
                    log_error "✗ ${filename} - Hash mismatch!"
                    log_error "  Expected: ${expected_hash}"
                    log_error "  Actual:   ${actual_hash}"
                    verification_failed=1
                fi
            else
                log_warning "File not found: ${filename}"
            fi
        fi
    done < "${checksum_file}"
    
    popd > /dev/null
    
    if [[ ${verification_failed} -eq 0 ]]; then
        log_success "All checksums verified for $(basename "${algo_dir}")"
        return 0
    else
        log_error "Checksum verification failed for $(basename "${algo_dir}")"
        return 1
    fi
}

# Function to generate checksums for vendor code
generate_checksums() {
    local algo_dir="$1"
    local checksum_file="${algo_dir}/SHA256SUMS"
    
    log_info "Generating checksums for $(basename "${algo_dir}")..."
    
    pushd "${algo_dir}" > /dev/null
    
    # Remove old checksum file
    rm -f "${checksum_file}"
    
    # Generate comprehensive checksums for all critical files
    find . -type f \( \
        -name "*.c" -o -name "*.h" -o -name "*.S" -o -name "*.s" \
        -o -name "*.go" -o -name "*.txt" -o -name "*.md" \
        -o -name "Makefile" -o -name "*.mk" -o -name "*.yml" \
        -o -name "*.gp" -o -name "*.inc" \
    \) \
        -not -path "./test/*" \
        -not -path "./tests/*" \
        -not -path "./benchmark/*" \
        -not -path "./nistkat/*" \
        -not -path "./.git/*" \
        | sort | xargs sha256sum > "${checksum_file}"
    
    # Add metadata to checksum file
    echo "# Vendor code checksums generated on $(date -u)" >> "${checksum_file}"
    echo "# Algorithm: $(basename "${algo_dir}")" >> "${checksum_file}"
    echo "# Total files: $(wc -l < "${checksum_file}")" >> "${checksum_file}"
    
    popd > /dev/null
    
    log_success "Checksums generated for $(basename "${algo_dir}")"
}

# Function to verify all vendor code
verify_all() {
    local overall_success=0
    
    log_info "Starting vendor code integrity verification..."
    
    for algo_dir in "${VENDOR_DIR}"/*; do
        if [[ -d "${algo_dir}" ]]; then
            if ! verify_checksums "${algo_dir}"; then
                overall_success=1
            fi
        fi
    done
    
    if [[ ${overall_success} -eq 0 ]]; then
        log_success "All vendor code integrity checks passed!"
    else
        log_error "Some vendor code integrity checks failed!"
        exit 1
    fi
}

# Function to create backup of vendor code
backup_vendor() {
    local algorithm="$1"
    local backup_reason="${2:-manual}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${VENDOR_DIR}/../backups/${algorithm}.${backup_reason}.${timestamp}"
    
    log_info "Creating backup for ${algorithm}..."
    
    # Ensure backup directory exists
    mkdir -p "${VENDOR_DIR}/../backups"
    
    if [[ -d "${VENDOR_DIR}/${algorithm}" ]]; then
        cp -r "${VENDOR_DIR}/${algorithm}" "${backup_dir}"
        
        # Create backup metadata
        cat > "${backup_dir}/BACKUP_INFO.txt" << EOF
Backup Information
==================
Algorithm: ${algorithm}
Reason: ${backup_reason}
Created: $(date -u)
Original Path: ${VENDOR_DIR}/${algorithm}
Backup Path: ${backup_dir}

Restore Command:
./scripts/vendor-integrity.sh restore ${algorithm} $(basename "${backup_dir}")
EOF
        
        log_success "Backup created: ${backup_dir}"
        echo "${backup_dir}"
    else
        log_error "Algorithm directory not found: ${VENDOR_DIR}/${algorithm}"
        return 1
    fi
}

# Function to list available backups
list_backups() {
    local algorithm="${1:-}"
    local backup_base_dir="${VENDOR_DIR}/../backups"
    
    log_info "Available backups:"
    echo "=================="
    
    if [[ ! -d "${backup_base_dir}" ]]; then
        log_warning "No backup directory found"
        return 0
    fi
    
    local backup_pattern="${algorithm:-*}"
    
    for backup_dir in "${backup_base_dir}"/${backup_pattern}.*; do
        if [[ -d "${backup_dir}" ]]; then
            local backup_name=$(basename "${backup_dir}")
            local backup_info="${backup_dir}/BACKUP_INFO.txt"
            
            echo "📦 ${backup_name}"
            
            if [[ -f "${backup_info}" ]]; then
                echo "   Created: $(grep "Created:" "${backup_info}" | cut -d: -f2-)"
                echo "   Reason: $(grep "Reason:" "${backup_info}" | cut -d: -f2-)"
            fi
            echo ""
        fi
    done
}

# Function to restore from backup
restore_vendor() {
    local algorithm="$1"
    local backup_name="$2"
    local backup_base_dir="${VENDOR_DIR}/../backups"
    local backup_dir="${backup_base_dir}/${backup_name}"
    
    log_info "Restoring ${algorithm} from backup: ${backup_name}"
    
    if [[ ! -d "${backup_dir}" ]]; then
        log_error "Backup not found: ${backup_dir}"
        return 1
    fi
    
    # Create current backup before restoring
    backup_vendor "${algorithm}" "pre-restore"
    
    # Remove current version
    if [[ -d "${VENDOR_DIR}/${algorithm}" ]]; then
        rm -rf "${VENDOR_DIR}/${algorithm}"
    fi
    
    # Restore from backup (exclude backup metadata)
    cp -r "${backup_dir}" "${VENDOR_DIR}/${algorithm}"
    rm -f "${VENDOR_DIR}/${algorithm}/BACKUP_INFO.txt"
    
    # Verify restored code
    if verify_checksums "${VENDOR_DIR}/${algorithm}"; then
        log_success "Successfully restored ${algorithm} from backup"
    else
        log_warning "Restored code failed verification - may need regeneration"
        log_info "Run: ./scripts/vendor-integrity.sh generate ${algorithm}"
    fi
}

# Function to update vendor code with comprehensive backup and rollback
update_vendor() {
    local algorithm="$1"
    local source_url="$2"
    local temp_dir=$(mktemp -d)
    
    log_info "Updating vendor code for ${algorithm}..."
    
    # Create pre-update backup
    local backup_dir=$(backup_vendor "${algorithm}" "pre-update")
    if [[ -z "${backup_dir}" ]]; then
        log_error "Failed to create backup, aborting update"
        return 1
    fi
    
    # Download and extract new code
    if ! wget -q "${source_url}" -O "${temp_dir}/source.tar.gz"; then
        log_error "Failed to download ${algorithm} source"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    # Extract and verify
    tar -xzf "${temp_dir}/source.tar.gz" -C "${temp_dir}"
    
    # Update vendor code
    rm -rf "${VENDOR_DIR}/${algorithm}"
    mv "${temp_dir}/${algorithm}" "${VENDOR_DIR}/${algorithm}"
    
    # Generate new checksums
    generate_checksums "${VENDOR_DIR}/${algorithm}"
    
    # Verify the new code
    if verify_checksums "${VENDOR_DIR}/${algorithm}"; then
        log_success "Vendor code updated successfully for ${algorithm}"
        
        # Run additional verification (if cargo test available)
        log_info "Running additional verification tests..."
        if command -v cargo >/dev/null 2>&1; then
            cd "${PROJECT_ROOT}"
            if cargo test --release 2>/dev/null; then
                log_success "All tests pass with updated vendor code"
            else
                log_error "Tests failed with updated code, rolling back..."
                restore_vendor "${algorithm}" "$(basename "${backup_dir}")"
                rm -rf "${temp_dir}"
                return 1
            fi
        fi
        
        # Keep backup for 7 days, then clean up
        touch "${backup_dir}/.cleanup_after_$(date -d '+7 days' +%Y%m%d)"
        
    else
        log_error "New vendor code failed verification, rolling back..."
        restore_vendor "${algorithm}" "$(basename "${backup_dir}")"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    rm -rf "${temp_dir}"
}

# Function to clean up old backups
cleanup_backups() {
    local backup_base_dir="${VENDOR_DIR}/../backups"
    local cleaned=0
    
    log_info "Cleaning up old backups..."
    
    if [[ ! -d "${backup_base_dir}" ]]; then
        log_info "No backup directory found"
        return 0
    fi
    
    # Clean up backups marked for cleanup
    for cleanup_marker in "${backup_base_dir}"/*/.cleanup_after_*; do
        if [[ -f "${cleanup_marker}" ]]; then
            local cleanup_date=$(basename "${cleanup_marker}" | sed 's/\.cleanup_after_//')
            local current_date=$(date +%Y%m%d)
            
            if [[ "${current_date}" -ge "${cleanup_date}" ]]; then
                local backup_dir=$(dirname "${cleanup_marker}")
                log_info "Removing old backup: $(basename "${backup_dir}")"
                rm -rf "${backup_dir}"
                ((cleaned++))
            fi
        fi
    done
    
    log_success "Cleaned up ${cleaned} old backups"
}

# Function to show vendor code status
show_status() {
    log_info "Vendor Code Status Report"
    echo "=========================="
    
    for algo_dir in "${VENDOR_DIR}"/*; do
        if [[ -d "${algo_dir}" ]]; then
            local algo_name=$(basename "${algo_dir}")
            local checksum_file="${algo_dir}/SHA256SUMS"
            
            echo -n "${algo_name}: "
            
            if [[ -f "${checksum_file}" ]]; then
                if verify_checksums "${algo_dir}" > /dev/null 2>&1; then
                    echo -e "${GREEN}✓ VERIFIED${NC}"
                else
                    echo -e "${RED}✗ FAILED${NC}"
                fi
            else
                echo -e "${YELLOW}? NO CHECKSUMS${NC}"
            fi
        fi
    done
}

# Function to audit vendor code
audit_vendor() {
    local audit_file="${PROJECT_ROOT}/VENDOR_AUDIT.md"
    
    log_info "Generating vendor code audit report..."
    
    cat > "${audit_file}" << EOF
# Vendor Code Audit Report

Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

## Summary

This document provides an audit trail of all vendor cryptographic libraries
used in the Cypheron-core project.

## Algorithms

EOF

    for algo_dir in "${VENDOR_DIR}"/*; do
        if [[ -d "${algo_dir}" ]]; then
            local algo_name=$(basename "${algo_dir}")
            local checksum_file="${algo_dir}/SHA256SUMS"
            
            cat >> "${audit_file}" << EOF
### ${algo_name}

- **Location**: \`core-lib/vendor/${algo_name}/\`
- **Checksum File**: $([ -f "${checksum_file}" ] && echo "✓ Present" || echo "✗ Missing")
- **Status**: $(verify_checksums "${algo_dir}" > /dev/null 2>&1 && echo "✓ Verified" || echo "✗ Failed")

#### Files:
EOF
            
            if [[ -f "${checksum_file}" ]]; then
                while IFS= read -r line; do
                    if [[ -n "${line}" && ! "${line}" =~ ^[[:space:]]*# ]]; then
                        if [[ "${line}" =~ ^([a-f0-9]{64})[[:space:]]+(.+)$ ]]; then
                            local hash="${BASH_REMATCH[1]}"
                            local filename="${BASH_REMATCH[2]}"
                            echo "- \`${filename}\` - \`${hash}\`" >> "${audit_file}"
                        fi
                    fi
                done < "${checksum_file}"
            fi
            
            echo "" >> "${audit_file}"
        fi
    done
    
    cat >> "${audit_file}" << EOF

## Verification Commands

To verify vendor code integrity, run:

\`\`\`bash
./scripts/vendor-integrity.sh verify
\`\`\`

To regenerate checksums:

\`\`\`bash
./scripts/vendor-integrity.sh generate <algorithm>
\`\`\`

## Update Procedures

1. Download new vendor code from official sources
2. Verify cryptographic signatures (if available)
3. Update vendor directory
4. Generate new checksums
5. Verify integrity
6. Update this audit report

## Security Considerations

- All vendor code should be obtained from official sources
- Checksums should be verified before compilation
- Any modifications to vendor code should be documented
- Regular audits should be performed to ensure integrity
EOF

    log_success "Vendor audit report generated: ${audit_file}"
}

# Main function
main() {
    case "${1:-}" in
        "verify")
            verify_all
            ;;
        "generate")
            if [[ -z "${2:-}" ]]; then
                log_error "Usage: $0 generate <algorithm>"
                exit 1
            fi
            generate_checksums "${VENDOR_DIR}/${2}"
            ;;
        "update")
            if [[ -z "${2:-}" || -z "${3:-}" ]]; then
                log_error "Usage: $0 update <algorithm> <source_url>"
                exit 1
            fi
            update_vendor "${2}" "${3}"
            ;;
        "backup")
            if [[ -z "${2:-}" ]]; then
                log_error "Usage: $0 backup <algorithm> [reason]"
                exit 1
            fi
            backup_vendor "${2}" "${3:-manual}"
            ;;
        "restore")
            if [[ -z "${2:-}" || -z "${3:-}" ]]; then
                log_error "Usage: $0 restore <algorithm> <backup_name>"
                exit 1
            fi
            restore_vendor "${2}" "${3}"
            ;;
        "list-backups")
            list_backups "${2:-}"
            ;;
        "cleanup-backups")
            cleanup_backups
            ;;
        "status")
            show_status
            ;;
        "audit")
            audit_vendor
            ;;
        *)
            echo "Usage: $0 {verify|generate|update|backup|restore|list-backups|cleanup-backups|status|audit}"
            echo ""
            echo "Commands:"
            echo "  verify                           - Verify all vendor code checksums"
            echo "  generate <algorithm>             - Generate checksums for an algorithm"
            echo "  update <algorithm> <url>         - Update vendor code from URL with backup"
            echo "  backup <algorithm> [reason]      - Create backup of algorithm code"
            echo "  restore <algorithm> <backup>     - Restore algorithm from backup"
            echo "  list-backups [algorithm]         - List available backups"
            echo "  cleanup-backups                  - Remove old backups"
            echo "  status                           - Show vendor code status"
            echo "  audit                            - Generate vendor audit report"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"