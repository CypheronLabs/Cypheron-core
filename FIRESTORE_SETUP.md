# Firestore Metrics Setup Guide

## 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing project
3. Enable Firestore API:
   ```
   gcloud services enable firestore.googleapis.com
   ```

## 2. Create Firestore Database

1. Navigate to Firestore in Cloud Console
2. Create database in Native mode
3. Choose region (us-central1 recommended for Cloud Run)

## 3. Service Account Setup

1. Go to IAM & Admin → Service Accounts
2. Create new service account: `cypheron-metrics`
3. Grant roles:
   - Cloud Datastore User
   - Firebase Admin SDK Administrator Service Agent
4. Create and download JSON key file

## 4. Environment Configuration

### For Local Development:
```bash
export FIRESTORE_PROJECT_ID=your-project-id
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

### For Production (Docker):
```bash
# Set in environment
export FIRESTORE_PROJECT_ID=your-project-id
export GCP_CREDENTIALS_PATH=/path/to/service-account.json

# Update .env.production
FIRESTORE_PROJECT_ID=your-project-id
```

## 5. Firestore Security Rules

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Public read access for metrics endpoints
    match /daily_stats/{document} {
      allow read: if true;
      allow write: if false; // Only server can write
    }
    
    match /endpoint_performance/{document} {
      allow read: if true;
      allow write: if false;
    }
    
    // Private collections
    match /usage_metrics/{document} {
      allow read, write: if false; // Server only
    }
  }
}
```

## 6. Test Setup

### Build and run locally:
```bash
cd rest-api
cargo build
FIRESTORE_PROJECT_ID=your-project-id cargo run
```

### Test endpoints:
```bash
# Make some API calls to generate metrics
curl -H "X-API-Key: test_key_12345_production_demo" \
     http://localhost:3000/kem/ml-kem-512/keygen

# Check metrics endpoints
curl http://localhost:3000/public/status
curl http://localhost:3000/public/metrics
curl http://localhost:3000/public/metrics/daily?days=7
```

## 7. Cloud Run Deployment

1. Build and push Docker image
2. Deploy with environment variables:
   ```bash
   gcloud run deploy cypheron-core \
     --image=ghcr.io/cypheron-labs/cypheron-core:latest \
     --set-env-vars="FIRESTORE_PROJECT_ID=your-project-id" \
     --set-env-vars="PQ_ENVIRONMENT=production" \
     --allow-unauthenticated
   ```

## 8. Website Integration

### JavaScript example:
```javascript
// Fetch public metrics for dashboard
async function getMetrics() {
  const response = await fetch('https://your-api.run.app/public/metrics?days=30');
  const data = await response.json();
  
  // Display on website
  document.getElementById('total-requests').textContent = 
    data.summary.total_requests_7_days.toLocaleString();
    
  document.getElementById('avg-response-time').textContent = 
    Math.round(data.summary.avg_response_time_ms) + 'ms';
}
```

## Cost Estimation

### Firestore Costs (approximate):
- 2000 users × 1000 requests/month = 2M requests
- Document writes: ~2M/month = $1.20
- Document reads (website): ~10K/month = $0.06
- Storage: ~1GB = $0.18
- **Total: ~$1.50/month**

## Collections Structure

### `daily_stats/{date}`
```json
{
  "date": "2024-01-15",
  "total_requests": 1500,
  "unique_keys": 45,
  "avg_response_time": 125.5,
  "error_rate": 0.2,
  "last_updated": "2024-01-15T23:59:59Z"
}
```

### `endpoint_performance/{endpoint_method}`
```json
{
  "endpoint": "/kem/ml-kem-768/keygen",
  "method": "POST",
  "total_calls": 850,
  "avg_response_time": 145.2,
  "error_count": 2,
  "last_updated": "2024-01-15T23:59:59Z"
}
```

### `usage_metrics/{metric_id}` (Private)
```json
{
  "api_key_id": "uuid",
  "endpoint": "/sig/ml-dsa-65/sign",
  "method": "POST",
  "status_code": 200,
  "response_time_ms": 89,
  "timestamp": "2024-01-15T14:30:25Z",
  "ip_address": "203.0.113.1",
  "user_agent": "MyApp/1.0"
}
```