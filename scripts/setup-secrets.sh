#!/bin/bash

# Secret Management Script for Cypheron API
# Generates and manages secrets securely for production deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Generate cryptographically secure secrets
generate_secure_secret() {
    local length=${1:-48}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-${length}
}

# Create terraform.tfvars from template
setup_terraform_vars() {
    log "Setting up Terraform variables..."
    
    if [ -f "terraform/terraform.tfvars" ]; then
        warning "terraform.tfvars already exists. Backing up..."
        cp terraform/terraform.tfvars terraform/terraform.tfvars.backup.$(date +%s)
    fi
    
    # Generate strong secrets
    ADMIN_KEY=$(generate_secure_secret 64)
    ENCRYPTION_PASSWORD=$(generate_secure_secret 64)
    
    # Get project ID from user
    read -p "Enter your GCP Project ID: " PROJECT_ID
    
    if [ -z "$PROJECT_ID" ]; then
        error "Project ID cannot be empty"
        exit 1
    fi
    
    # Create terraform.tfvars
    cat > terraform/terraform.tfvars << EOF
# Cypheron API Production Configuration
# Generated on $(date)

# GCP Configuration
project_id = "$PROJECT_ID"
region = "us-central1"
service_name = "cypheron-api"
environment = "prod"

# Security Configuration (Auto-generated - KEEP SECURE)
master_admin_key = "$ADMIN_KEY"
encryption_password = "$ENCRYPTION_PASSWORD"

# Access Control
allowed_users = []

# Resource Limits
max_instances = 10
min_instances = 1
memory_limit = "1Gi"
cpu_limit = "1000m"

# Security Settings
enable_deletion_protection = true
EOF
    
    success "terraform.tfvars created with secure secrets"
    
    # Save secrets separately for backup
    cat > .env.secrets << EOF
# BACKUP OF GENERATED SECRETS - STORE SECURELY
# Generated on $(date)

MASTER_ADMIN_KEY=$ADMIN_KEY
ENCRYPTION_PASSWORD=$ENCRYPTION_PASSWORD
PROJECT_ID=$PROJECT_ID

# Admin API Usage:
# curl -H "X-API-Key: $ADMIN_KEY" https://your-service-url/admin/api-keys
EOF
    
    chmod 600 .env.secrets
    
    warning "IMPORTANT SECURITY REMINDERS:"
    echo "1. Secrets are saved in terraform.tfvars and .env.secrets"
    echo "2. NEVER commit these files to version control"
    echo "3. Store secrets in a secure password manager"
    echo "4. The admin key allows full access to your API"
    echo "5. Rotate secrets regularly in production"
}

# Create .gitignore entries
setup_gitignore() {
    log "Updating .gitignore for security..."
    
    if [ ! -f ".gitignore" ]; then
        touch .gitignore
    fi
    
    # Add security-related entries if not already present
    security_entries=(
        "terraform/terraform.tfvars"
        "terraform/*.tfstate"
        "terraform/*.tfstate.backup"
        "terraform/.terraform/"
        ".env.secrets"
        ".env.production"
        "*.pem"
        "*.key"
        ".secrets_generated"
    )
    
    for entry in "${security_entries[@]}"; do
        if ! grep -qx "$entry" .gitignore; then
            echo "$entry" >> .gitignore
        fi
    done
    
    success ".gitignore updated with security entries"
}

# Validate existing secrets
validate_secrets() {
    log "Validating secret strength..."
    
    if [ ! -f "terraform/terraform.tfvars" ]; then
        error "terraform.tfvars not found. Run setup first."
        exit 1
    fi
    
    # Check admin key length
    ADMIN_KEY=$(grep "master_admin_key" terraform/terraform.tfvars | cut -d'"' -f2)
    if [ ${#ADMIN_KEY} -lt 32 ]; then
        error "Admin key is too short (${#ADMIN_KEY} chars). Minimum 32 required."
        exit 1
    fi
    
    # Check encryption password length
    ENCRYPTION_PASSWORD=$(grep "encryption_password" terraform/terraform.tfvars | cut -d'"' -f2)
    if [ ${#ENCRYPTION_PASSWORD} -lt 32 ]; then
        error "Encryption password is too short (${#ENCRYPTION_PASSWORD} chars). Minimum 32 required."
        exit 1
    fi
    
    success "Secret validation passed"
    echo "- Admin key: ${#ADMIN_KEY} characters"
    echo "- Encryption password: ${#ENCRYPTION_PASSWORD} characters"
}

# Rotate secrets
rotate_secrets() {
    log "Rotating secrets..."
    
    if [ ! -f "terraform/terraform.tfvars" ]; then
        error "terraform.tfvars not found. Run setup first."
        exit 1
    fi
    
    warning "This will generate new secrets and update terraform.tfvars"
    read -p "Are you sure you want to rotate secrets? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "Secret rotation cancelled"
        exit 0
    fi
    
    # Backup current config
    cp terraform/terraform.tfvars terraform/terraform.tfvars.backup.$(date +%s)
    
    # Generate new secrets
    NEW_ADMIN_KEY=$(generate_secure_secret 64)
    NEW_ENCRYPTION_PASSWORD=$(generate_secure_secret 64)
    
    # Update terraform.tfvars
    sed -i "s/master_admin_key = .*/master_admin_key = \"$NEW_ADMIN_KEY\"/" terraform/terraform.tfvars
    sed -i "s/encryption_password = .*/encryption_password = \"$NEW_ENCRYPTION_PASSWORD\"/" terraform/terraform.tfvars
    
    success "Secrets rotated successfully"
    warning "You will need to redeploy your application for the new secrets to take effect"
}

# Check for secrets in git
check_git_security() {
    log "Checking for accidentally committed secrets..."
    
    if [ -d ".git" ]; then
        # Check if sensitive files are tracked
        sensitive_files=("terraform.tfvars" ".env.secrets" ".env.production")
        
        for file in "${sensitive_files[@]}"; do
            if git ls-files --error-unmatch "$file" >/dev/null 2>&1; then
                error "SECURITY BREACH: $file is tracked in git!"
                echo "Run: git rm --cached $file && git commit -m 'Remove sensitive file'"
            fi
        done
        
        # Check for potential secrets in commit history
        if git log --oneline | grep -i -E "(password|key|secret|token)" >/dev/null; then
            warning "Found potential secret-related commits. Review your git history."
        fi
    fi
}

# Main menu
show_menu() {
    echo "=========================================="
    echo "    Cypheron API Secret Management"
    echo "=========================================="
    echo
    echo "1. Setup secrets for new deployment"
    echo "2. Validate existing secrets"
    echo "3. Rotate secrets"
    echo "4. Check git security"
    echo "5. Exit"
    echo
    read -p "Choose an option (1-5): " choice
    
    case $choice in
        1)
            setup_terraform_vars
            setup_gitignore
            ;;
        2)
            validate_secrets
            ;;
        3)
            rotate_secrets
            ;;
        4)
            check_git_security
            ;;
        5)
            log "Exiting..."
            exit 0
            ;;
        *)
            error "Invalid option. Please choose 1-5."
            show_menu
            ;;
    esac
}

# Check if running with arguments
if [ $# -eq 0 ]; then
    show_menu
else
    case "$1" in
        "setup")
            setup_terraform_vars
            setup_gitignore
            ;;
        "validate")
            validate_secrets
            ;;
        "rotate")
            rotate_secrets
            ;;
        "check-git")
            check_git_security
            ;;
        *)
            echo "Usage: $0 [setup|validate|rotate|check-git]"
            exit 1
            ;;
    esac
fi