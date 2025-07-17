#!/bin/bash

# Vendor Update Checking Script
# This script safely checks for available updates to vendor cryptographic libraries
# and provides recommendations for updating while maintaining security

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_DIR="${PROJECT_ROOT}/core-lib/vendor"
VERSION_MANIFEST="${PROJECT_ROOT}/vendor-versions.toml"
TEMP_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

log_update() {
    echo -e "${PURPLE}[UPDATE]${NC} $1"
}

# Cleanup function
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

echo "🔍 Checking for Vendor Library Updates"
echo "===================================="

# Check if version manifest exists
if [[ ! -f "${VERSION_MANIFEST}" ]]; then
    log_error "Version manifest not found: ${VERSION_MANIFEST}"
    exit 1
fi

# Function to parse TOML (basic implementation)
get_toml_value() {
    local section="$1"
    local key="$2"
    local file="$3"
    
    sed -n "/^\[${section}\]/,/^\[/p" "${file}" | grep "^${key}" | cut -d'"' -f2 | head -1
}

# Function to get latest commit from repository
get_latest_commit() {
    local repo_url="$1"
    local branch="${2:-master}"
    
    log_info "Fetching latest commit for ${repo_url} (${branch})"
    
    # Use git ls-remote to get latest commit without cloning
    git ls-remote "${repo_url}" "refs/heads/${branch}" | cut -f1 || echo "unknown"
}

# Function to get latest tag from repository
get_latest_tag() {
    local repo_url="$1"
    
    log_info "Fetching latest tag for ${repo_url}"
    
    # Get all tags and find the latest one (basic version sorting)
    git ls-remote --tags "${repo_url}" | \
        grep -v '\^{}' | \
        sed 's/.*refs\/tags\///' | \
        sort -V | \
        tail -1 || echo "unknown"
}

# Function to compare versions and check for updates
check_algorithm_updates() {
    local name="$1"
    
    echo ""
    log_info "Checking updates for ${name}..."
    echo "----------------------------------------"
    
    # Get current version info from manifest
    local repo_url=$(get_toml_value "${name}" "repository" "${VERSION_MANIFEST}")
    local current_commit=$(get_toml_value "${name}" "commit" "${VERSION_MANIFEST}")
    local current_tag=$(get_toml_value "${name}" "tag" "${VERSION_MANIFEST}")
    local current_branch=$(get_toml_value "${name}" "branch" "${VERSION_MANIFEST}")
    
    if [[ -z "${repo_url}" ]]; then
        log_error "Repository URL not found for ${name}"
        return 1
    fi
    
    # Get latest information from remote
    local latest_commit=$(get_latest_commit "${repo_url}" "${current_branch}")
    local latest_tag=$(get_latest_tag "${repo_url}")
    
    # Display current vs latest
    echo "📊 Current State:"
    echo "   Repository: ${repo_url}"
    echo "   Branch: ${current_branch}"
    echo "   Current Commit: ${current_commit}"
    echo "   Current Tag: ${current_tag}"
    echo ""
    echo "📊 Latest Available:"
    echo "   Latest Commit: ${latest_commit}"
    echo "   Latest Tag: ${latest_tag}"
    echo ""
    
    # Check for updates
    local updates_available=false
    
    if [[ "${current_commit}" != "TBD" && "${current_commit}" != "${latest_commit}" ]]; then
        if [[ "${latest_commit}" != "unknown" ]]; then
            log_update "New commit available: ${current_commit} → ${latest_commit}"
            updates_available=true
        fi
    fi
    
    if [[ -n "${current_tag}" && "${current_tag}" != "${latest_tag}" ]]; then
        if [[ "${latest_tag}" != "unknown" ]]; then
            log_update "New tag available: ${current_tag} → ${latest_tag}"
            updates_available=true
        fi
    fi
    
    if [[ "${updates_available}" == "false" ]]; then
        log_success "No updates available for ${name}"
    else
        log_warning "Updates available for ${name} - Manual review recommended"
        
        # Provide update recommendations
        echo ""
        echo "🔧 Update Recommendations:"
        echo "1. Review changes: git log ${current_commit}..${latest_commit}"
        echo "2. Check for breaking changes in release notes"
        echo "3. Test in staging environment first"
        echo "4. Update vendor-versions.toml with new commit/tag"
        echo "5. Run: ./setup_vendor.sh to download updated version"
        echo "6. Run: ./scripts/vendor-integrity.sh verify"
        echo "7. Run: cargo test to ensure compatibility"
    fi
    
    return 0
}

# Function to generate update report
generate_update_report() {
    local report_file="${PROJECT_ROOT}/VENDOR_UPDATE_REPORT.md"
    
    log_info "Generating vendor update report..."
    
    cat > "${report_file}" << EOF
# Vendor Update Report

Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

## Summary

This report provides information about available updates for vendor cryptographic libraries.

## Update Status

EOF

    # Check each algorithm and append to report
    for algorithm in "kyber" "dilithium" "falcon" "sphincsplus"; do
        echo "### ${algorithm}" >> "${report_file}"
        
        local repo_url=$(get_toml_value "${algorithm}" "repository" "${VERSION_MANIFEST}")
        local current_commit=$(get_toml_value "${algorithm}" "commit" "${VERSION_MANIFEST}")
        local current_branch=$(get_toml_value "${algorithm}" "branch" "${VERSION_MANIFEST}")
        
        if [[ -n "${repo_url}" ]]; then
            local latest_commit=$(get_latest_commit "${repo_url}" "${current_branch}")
            
            cat >> "${report_file}" << EOF

- **Repository**: ${repo_url}
- **Current Branch**: ${current_branch}
- **Current Commit**: ${current_commit}
- **Latest Commit**: ${latest_commit}
- **Status**: $(if [[ "${current_commit}" != "TBD" && "${current_commit}" != "${latest_commit}" ]]; then echo "⚠️ Update Available"; else echo "✅ Up to Date"; fi)

EOF
        fi
    done
    
    cat >> "${report_file}" << EOF

## Security Considerations

- Always review changes before updating vendor libraries
- Test updates in a staging environment first
- Ensure NIST compliance is maintained after updates
- Verify cryptographic test vectors pass after updates
- Check for any API or ABI breaking changes

## Update Process

1. **Review Changes**: Examine commit history and release notes
2. **Update Manifest**: Modify vendor-versions.toml with new versions
3. **Download**: Run \`./setup_vendor.sh\` to fetch updated code
4. **Verify**: Run \`./scripts/vendor-integrity.sh verify\`
5. **Test**: Run \`cargo test\` and security tests
6. **Validate**: Ensure NIST KAT tests still pass
7. **Deploy**: Update production after successful staging tests

## Rollback Procedures

If issues are found after updating:

1. Restore previous vendor-versions.toml
2. Run \`./setup_vendor.sh\` to revert to previous versions
3. Verify integrity with \`./scripts/vendor-integrity.sh verify\`
4. Test functionality to ensure stability

EOF

    log_success "Update report generated: ${report_file}"
}

# Main execution
main() {
    case "${1:-check}" in
        "check")
            # Check all algorithms for updates
            for algorithm in "kyber" "dilithium" "falcon" "sphincsplus"; do
                check_algorithm_updates "${algorithm}"
            done
            ;;
        "report")
            generate_update_report
            ;;
        "kyber"|"dilithium"|"falcon"|"sphincsplus")
            check_algorithm_updates "$1"
            ;;
        *)
            echo "Usage: $0 [check|report|kyber|dilithium|falcon|sphincsplus]"
            echo ""
            echo "Commands:"
            echo "  check                 - Check all algorithms for updates (default)"
            echo "  report                - Generate comprehensive update report"
            echo "  <algorithm>           - Check specific algorithm for updates"
            exit 1
            ;;
    esac
}

echo ""
log_info "Starting vendor update check..."

# Run main function
main "$@"

echo ""
echo "🔒 Update check complete!"
echo ""
echo "📋 Next steps if updates are available:"
echo "1. Review changes and security implications"
echo "2. Update vendor-versions.toml with new commits/tags"
echo "3. Test updates in staging environment"
echo "4. Deploy to production after verification"
echo ""
echo "💡 Tip: Run './scripts/check-vendor-updates.sh report' for detailed report"