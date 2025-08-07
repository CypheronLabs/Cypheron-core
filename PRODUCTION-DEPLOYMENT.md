# Cypheron API - Secure Production Deployment Guide

## 🚨 Security-First Production Deployment

This guide walks you through deploying the Cypheron API with enterprise-grade security measures. All critical vulnerabilities have been addressed.

## Pre-Deployment Security Checklist

- ✅ **Firestore Security Rules**: Restrict database access to authenticated service accounts only
- ✅ **No Public Access**: Cloud Run requires authentication (no `--allow-unauthenticated`)
- ✅ **Secret Management**: All secrets stored in Google Secret Manager, not hardcoded
- ✅ **Network Isolation**: VPC with private networking and firewall rules
- ✅ **Minimal IAM**: Least privilege access controls
- ✅ **Audit Logging**: Comprehensive security event logging

## Quick Start

### 1. Setup Secrets (Required First Step)

```bash
# Generate secure secrets and configure Terraform
./scripts/setup-secrets.sh setup

# This creates:
# - terraform/terraform.tfvars with strong secrets
# - .env.secrets backup file  
# - Updated .gitignore for security
```

### 2. Deploy to Production

```bash
# Complete secure deployment
./scripts/deploy-production.sh

# This will:
# - Validate configuration
# - Deploy infrastructure with Terraform
# - Apply Firestore security rules
# - Build and deploy the application
# - Verify deployment
```

## Manual Deployment Steps

If you prefer manual control, follow these steps:

### 1. Configure Secrets

```bash
# Copy and edit the Terraform variables
cp terraform/terraform.tfvars.example terraform/terraform.tfvars

# Generate strong secrets (64+ characters)
openssl rand -base64 64  # For admin key
openssl rand -base64 64  # For encryption password

# Edit terraform.tfvars with your values
```

### 2. Deploy Infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Deploy infrastructure
terraform apply
```

### 3. Deploy Firestore Rules

```bash
# Get your project ID
PROJECT_ID=$(cd terraform && terraform output -raw project_id)

# Deploy security rules
gcloud firestore databases update \
    --database="(default)" \
    --project="$PROJECT_ID" \
    --rules-file="firestore.rules"
```

### 4. Build and Deploy Application

```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build the image
docker build -f Dockerfile.production -t gcr.io/$PROJECT_ID/cypheron-api .

# Push to registry
docker push gcr.io/$PROJECT_ID/cypheron-api

# Deploy with Cloud Build
gcloud builds submit --config=cloudbuild.yaml
```

## What Terraform Creates

### Security Infrastructure

1. **VPC Network** - Isolated network environment
2. **Firewall Rules** - Restrict network access
3. **Service Account** - Minimal permissions for API access
4. **Secret Manager** - Secure secret storage
5. **Custom IAM Roles** - Least privilege access

### Application Infrastructure

1. **Cloud Run Service** - Secure containerized API
2. **Firestore Database** - Post-quantum encrypted storage
3. **VPC Connector** - Private network connectivity

### Security Features

- 🔒 **No Public Access** - Authentication required for all requests
- 🔐 **Encrypted Secrets** - All secrets stored in Secret Manager
- 🛡️ **Network Isolation** - VPC with private IP ranges
- 🔍 **Audit Logging** - Comprehensive security monitoring
- ⚡ **Auto-scaling** - Handles traffic spikes securely

## Post-Deployment Security Tasks

### 1. Create Your First API Key

```bash
# Get your service URL
SERVICE_URL=$(cd terraform && terraform output -raw service_url)
ADMIN_KEY=$(grep master_admin_key terraform/terraform.tfvars | cut -d'"' -f2)

# Create an API key
curl -X POST "$SERVICE_URL/admin/api-keys" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "permissions": ["kem:*", "sig:*"],
    "rate_limit": 1000,
    "expires_in_days": 90
  }'
```

### 2. Test Your API

```bash
# Test with your new API key
API_KEY="your-generated-api-key"

curl -X POST "$SERVICE_URL/kem/ml-kem-768/keygen" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json"
```

### 3. Monitor Your Deployment

```bash
# View logs
gcloud logs read 'resource.type=cloud_run_revision' \
  --project="$PROJECT_ID" \
  --limit=50

# Monitor security events
gcloud logs read 'jsonPayload.event_type="AccessDenied"' \
  --project="$PROJECT_ID"
```

## Security Best Practices

### Secret Management

- 🔑 **Rotate Secrets Regularly**: Use `./scripts/setup-secrets.sh rotate`
- 📝 **Never Commit Secrets**: All sensitive files are in `.gitignore`
- 🔐 **Use Strong Secrets**: Minimum 32 characters, auto-generated

### Access Control

- 👤 **Limit Admin Access**: Only authorized personnel should have admin keys
- 🎫 **Use Individual API Keys**: Create separate keys for different services
- ⏰ **Set Expiration Dates**: Regular key rotation for security

### Monitoring

- 📊 **Monitor Usage**: Track API usage patterns
- 🚨 **Set Up Alerts**: Configure alerts for suspicious activity
- 📋 **Review Logs**: Regular security log reviews

## Troubleshooting

### Common Issues

1. **"Permission Denied" Errors**
   - Check IAM permissions
   - Verify service account configuration
   - Ensure Firestore rules are deployed

2. **"Service Unavailable"**
   - Check Cloud Run deployment status
   - Verify VPC connector configuration
   - Review container logs

3. **"Invalid API Key"**
   - Verify Secret Manager configuration
   - Check environment variable injection
   - Ensure secrets are properly formatted

### Verification Commands

```bash
# Check service status
gcloud run services describe cypheron-api \
  --region=us-central1 \
  --project="$PROJECT_ID"

# Verify secrets
gcloud secrets versions list pq-master-admin-key \
  --project="$PROJECT_ID"

# Test Firestore rules
gcloud firestore databases describe \
  --database="(default)" \
  --project="$PROJECT_ID"
```

## Compliance and Auditing

Your deployment includes:

- ✅ **NIST FIPS 203/204/205** compliance tracking
- ✅ **PCI DSS** ready infrastructure
- ✅ **SOC 2 Type II** compatible logging
- ✅ **GDPR** compliant data handling

## Support

For security issues or deployment problems:

1. Check the logs first: `gcloud logs read`
2. Verify configuration: `./scripts/setup-secrets.sh validate`
3. Review Terraform state: `terraform plan`

## Security Incident Response

If you suspect a security breach:

1. **Immediately rotate all secrets**: `./scripts/setup-secrets.sh rotate`
2. **Check access logs**: Look for unauthorized access patterns
3. **Review API key usage**: Identify any suspicious activity
4. **Update Firestore rules**: Tighten access if needed
5. **Redeploy with new secrets**: `./scripts/deploy-production.sh`

---

**Remember**: Security is an ongoing process. Regularly review and update your security measures.