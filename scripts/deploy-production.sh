#!/bin/bash

# Production Deployment Script for Cypheron API
# This script ensures secure deployment with all security measures in place

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
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

# Check if required tools are installed
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v terraform &> /dev/null; then
        missing_tools+=("terraform")
    fi
    
    if ! command -v gcloud &> /dev/null; then
        missing_tools+=("gcloud")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        echo "Please install the missing tools and try again."
        exit 1
    fi
    
    success "All prerequisites installed"
}

# Validate configuration
validate_config() {
    log "Validating configuration..."
    
    if [ ! -f "terraform/terraform.tfvars" ]; then
        error "terraform/terraform.tfvars not found"
        echo "Please copy terraform/terraform.tfvars.example to terraform/terraform.tfvars and configure it"
        exit 1
    fi
    
    if [ ! -f "firestore.rules" ]; then
        error "firestore.rules not found"
        echo "Firestore security rules are required for production deployment"
        exit 1
    fi
    
    # Check if secrets are properly configured
    if grep -q "your-very-secure" terraform/terraform.tfvars; then
        error "Found placeholder values in terraform.tfvars"
        echo "Please update all placeholder values with real secrets"
        exit 1
    fi
    
    success "Configuration validated"
}

# Generate strong secrets if needed
generate_secrets() {
    log "Checking secret generation..."
    
    if [ ! -f ".secrets_generated" ]; then
        warning "Generating strong secrets for production..."
        
        ADMIN_KEY=$(openssl rand -base64 48)
        ENCRYPTION_PASSWORD=$(openssl rand -base64 48)
        
        echo "# Auto-generated secrets for production" > .env.production
        echo "ADMIN_KEY=${ADMIN_KEY}" >> .env.production
        echo "ENCRYPTION_PASSWORD=${ENCRYPTION_PASSWORD}" >> .env.production
        
        echo "Generated secrets stored in .env.production"
        echo "Please update your terraform.tfvars with these values"
        touch .secrets_generated
        
        warning "IMPORTANT: Store these secrets securely and never commit them to version control"
    fi
}

# Deploy infrastructure
deploy_infrastructure() {
    log "Deploying infrastructure with Terraform..."
    
    cd terraform
    
    # Initialize Terraform
    terraform init
    
    # Validate configuration
    terraform validate
    
    # Plan deployment
    log "Creating deployment plan..."
    terraform plan -out=tfplan
    
    # Confirm deployment
    echo
    read -p "Do you want to proceed with the deployment? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        warning "Deployment cancelled"
        exit 0
    fi
    
    # Apply deployment
    log "Applying infrastructure changes..."
    terraform apply tfplan
    
    # Clean up plan file
    rm tfplan
    
    cd ..
    success "Infrastructure deployed successfully"
}

# Deploy Firestore rules
deploy_firestore_rules() {
    log "Deploying Firestore security rules..."
    
    # Get project ID from Terraform output
    PROJECT_ID=$(cd terraform && terraform output -raw project_id)
    
    # Deploy rules using gcloud (Firebase CLI alternative)
    gcloud firestore databases update \
        --database="(default)" \
        --project="$PROJECT_ID" \
        --rules-file="firestore.rules"
    
    success "Firestore security rules deployed"
}

# Build and deploy application
deploy_application() {
    log "Building and deploying application..."
    
    # Get project ID from Terraform output
    PROJECT_ID=$(cd terraform && terraform output -raw project_id)
    
    # Configure Docker for GCR
    gcloud auth configure-docker --quiet
    
    # Build the Docker image
    log "Building Docker image..."
    docker build -f Dockerfile.production -t "gcr.io/$PROJECT_ID/cypheron-api:latest" .
    
    # Push the image
    log "Pushing image to Google Container Registry..."
    docker push "gcr.io/$PROJECT_ID/cypheron-api:latest"
    
    # Trigger Cloud Build for deployment
    log "Triggering Cloud Build deployment..."
    gcloud builds submit \
        --config=cloudbuild.yaml \
        --project="$PROJECT_ID" \
        --substitutions="_PROJECT_ID=$PROJECT_ID"
    
    success "Application deployed successfully"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    PROJECT_ID=$(cd terraform && terraform output -raw project_id)
    SERVICE_URL=$(cd terraform && terraform output -raw service_url)
    
    # Check Cloud Run service status
    REVISION=$(gcloud run revisions list \
        --service=cypheron-api \
        --region=us-central1 \
        --project="$PROJECT_ID" \
        --format="value(metadata.name)" \
        --limit=1)
    
    if [ -n "$REVISION" ]; then
        success "Cloud Run service is running: $REVISION"
    else
        error "Cloud Run service deployment failed"
        exit 1
    fi
    
    # Test health endpoint (this will fail initially due to authentication, which is expected)
    log "Testing service connectivity..."
    if curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" | grep -q "401\|403"; then
        success "Service is responding (authentication required as expected)"
    else
        warning "Service may not be responding correctly"
    fi
    
    echo
    success "Deployment verification completed"
    echo -e "${GREEN}Service URL:${NC} $SERVICE_URL"
    echo -e "${YELLOW}Note:${NC} The service requires authentication. Use your API keys to access it."
}

# Main deployment flow
main() {
    echo "=========================================="
    echo "  Cypheron API Production Deployment"
    echo "=========================================="
    echo
    
    check_prerequisites
    validate_config
    generate_secrets
    
    echo
    log "Starting production deployment..."
    
    deploy_infrastructure
    deploy_firestore_rules
    deploy_application
    verify_deployment
    
    echo
    success "🎉 Production deployment completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Create your first API key using the admin endpoints"
    echo "2. Test the API with your generated keys"
    echo "3. Monitor the service using Cloud Console"
    echo "4. Set up monitoring and alerting"
    echo
    echo "Security reminders:"
    echo "- Never commit secrets to version control"
    echo "- Regularly rotate your admin keys"
    echo "- Monitor access logs for suspicious activity"
    echo "- Keep your dependencies updated"
}

# Run main function
main "$@"