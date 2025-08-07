#!/bin/bash

# Secure Your Existing Cypheron API Service
# This script will move your hardcoded secrets to Google Secret Manager
# and update your live service for production security

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ID="cypheron-api"
SERVICE_NAME="cypheron-api-secure"
REGION="us-central1"

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

# Generate secure admin key
generate_admin_key() {
    openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
}

# Step 1: Create secrets in Secret Manager
create_secrets() {
    log "Creating secrets in Google Secret Manager..."
    
    # Generate a strong admin key
    ADMIN_KEY=$(generate_admin_key)
    
    # Use your existing encryption password initially, then you can rotate it
    ENCRYPTION_PASSWORD="Cypheron-PQ-API-Master-Key-2024-v1"
    
    # Create admin key secret
    log "Creating admin key secret..."
    if gcloud secrets describe pq-master-admin-key --project="$PROJECT_ID" >/dev/null 2>&1; then
        warning "Admin key secret already exists, updating..."
        echo -n "$ADMIN_KEY" | gcloud secrets versions add pq-master-admin-key \
            --data-file=- \
            --project="$PROJECT_ID"
    else
        echo -n "$ADMIN_KEY" | gcloud secrets create pq-master-admin-key \
            --data-file=- \
            --project="$PROJECT_ID"
    fi
    
    # Create encryption password secret
    log "Creating encryption password secret..."
    if gcloud secrets describe pq-encryption-password --project="$PROJECT_ID" >/dev/null 2>&1; then
        warning "Encryption password secret already exists, updating..."
        echo -n "$ENCRYPTION_PASSWORD" | gcloud secrets versions add pq-encryption-password \
            --data-file=- \
            --project="$PROJECT_ID"
    else
        echo -n "$ENCRYPTION_PASSWORD" | gcloud secrets create pq-encryption-password \
            --data-file=- \
            --project="$PROJECT_ID"
    fi
    
    success "Secrets created in Secret Manager"
    
    # Save admin key for your reference
    echo "# Your new admin key - STORE THIS SECURELY" > .admin-key-backup
    echo "ADMIN_KEY=$ADMIN_KEY" >> .admin-key-backup
    echo "PROJECT_ID=$PROJECT_ID" >> .admin-key-backup
    echo "SERVICE_URL=https://$SERVICE_NAME-123456789-$REGION.a.run.app" >> .admin-key-backup
    chmod 600 .admin-key-backup
    
    warning "Admin key saved to .admin-key-backup - store this securely!"
}

# Step 2: Create the secure service account
create_service_account() {
    log "Creating secure service account..."
    
    # Create service account if it doesn't exist
    if ! gcloud iam service-accounts describe firestore-accessor@"$PROJECT_ID".iam.gserviceaccount.com --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud iam service-accounts create firestore-accessor \
            --display-name="Firestore Accessor Service Account" \
            --description="Minimal permissions for Cypheron API" \
            --project="$PROJECT_ID"
    else
        log "Service account already exists"
    fi
    
    # Grant minimal Firestore permissions
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:firestore-accessor@$PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/datastore.user"
    
    # Grant Secret Manager access
    gcloud secrets add-iam-policy-binding pq-master-admin-key \
        --member="serviceAccount:firestore-accessor@$PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/secretmanager.secretAccessor" \
        --project="$PROJECT_ID"
    
    gcloud secrets add-iam-policy-binding pq-encryption-password \
        --member="serviceAccount:firestore-accessor@$PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/secretmanager.secretAccessor" \
        --project="$PROJECT_ID"
    
    success "Service account created with minimal permissions"
}

# Step 3: Deploy Firestore security rules
deploy_firestore_rules() {
    log "Deploying Firestore security rules..."
    
    if [ ! -f "firestore.rules" ]; then
        error "firestore.rules not found"
        exit 1
    fi
    
    # Deploy the rules
    gcloud firestore databases update \
        --database="(default)" \
        --project="$PROJECT_ID" \
        --rules-file="firestore.rules"
    
    success "Firestore security rules deployed"
}

# Step 4: Update the Cloud Run service
update_cloud_run_service() {
    log "Updating Cloud Run service with secure configuration..."
    
    # Update the service with:
    # 1. New service account
    # 2. Secrets from Secret Manager
    # 3. Remove hardcoded environment variables
    gcloud run services update "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --service-account="firestore-accessor@$PROJECT_ID.iam.gserviceaccount.com" \
        --update-secrets="PQ_MASTER_ADMIN_KEY=pq-master-admin-key:latest,PQ_ENCRYPTION_PASSWORD=pq-encryption-password:latest" \
        --update-env-vars="FIRESTORE_PROJECT_ID=$PROJECT_ID,FIRESTORE_COLLECTION=api_keys" \
        --no-allow-unauthenticated
    
    success "Cloud Run service updated with secure configuration"
}

# Step 5: Verify the deployment
verify_deployment() {
    log "Verifying secure deployment..."
    
    # Check service status
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(status.url)")
    
    if [ -n "$SERVICE_URL" ]; then
        success "Service is running: $SERVICE_URL"
    else
        error "Service not found or not running"
        exit 1
    fi
    
    # Test authentication (should return 401/403)
    log "Testing service authentication..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" || echo "000")
    
    if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
        success "Service requires authentication (as expected)"
    elif [[ "$HTTP_CODE" == "200" ]]; then
        warning "Service responded with 200 - check if authentication is properly configured"
    else
        warning "Service returned HTTP $HTTP_CODE - check service logs"
    fi
    
    # Show admin key for testing
    ADMIN_KEY=$(cat .admin-key-backup | grep ADMIN_KEY | cut -d'=' -f2)
    echo
    success "🎉 Security deployment completed!"
    echo
    echo "Your service is now secure:"
    echo "- Service URL: $SERVICE_URL"
    echo "- Admin Key: $ADMIN_KEY"
    echo "- All secrets are in Secret Manager"
    echo "- Service account has minimal permissions"
    echo "- Firestore has security rules"
    echo
    echo "Test admin access:"
    echo "curl -X POST '$SERVICE_URL/admin/api-keys' \\"
    echo "  -H 'X-API-Key: $ADMIN_KEY' \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{\"name\":\"Test Key\",\"permissions\":[\"kem:*\"],\"rate_limit\":100}'"
}

# Main execution
main() {
    echo "=========================================="
    echo "  Secure Your Existing Cypheron API"
    echo "=========================================="
    echo
    echo "This will:"
    echo "1. Move hardcoded secrets to Secret Manager"
    echo "2. Create a secure service account"
    echo "3. Deploy Firestore security rules"
    echo "4. Update your live service securely"
    echo
    read -p "Continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "Operation cancelled"
        exit 0
    fi
    
    create_secrets
    create_service_account
    deploy_firestore_rules
    update_cloud_run_service
    verify_deployment
}

# Run main function
main "$@"