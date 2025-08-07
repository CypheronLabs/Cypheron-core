# Cypheron Labs - Customer API Key Management

## Overview

This guide provides tools and instructions for managing API keys for your Cypheron Labs post-quantum security platform. The system provides enterprise-grade security with ML-KEM-768 post-quantum encryption and comprehensive audit logging.

## Quick Start

### Prerequisites

1. **Google Cloud SDK** installed and authenticated
2. **Python 3.7+** or **Bash** available
3. Access to the Cypheron Labs project (`cypheron-api`)

### Using the API Key Manager

#### Python Script (Recommended)
```bash
# Check service status
python3 scripts/api_key_manager.py status

# Create a new customer API key
python3 scripts/api_key_manager.py create -n "Customer Name" -d "Production API access"

# Create a temporary key (expires in 30 days)
python3 scripts/api_key_manager.py create -n "Trial User" -e 30

# List all API keys
python3 scripts/api_key_manager.py list

# Test an API key
python3 scripts/api_key_manager.py test YOUR_API_KEY_HERE
```

#### Bash Script (Alternative)
```bash
# Create a new API key
./scripts/manage-api-keys.sh create -n "Customer Name" -d "Production access"

# List keys
./scripts/manage-api-keys.sh list

# Test a key
./scripts/manage-api-keys.sh test YOUR_API_KEY_HERE
```

## Customer Onboarding Process

### For New Customers

1. **Create API Key**
   ```bash
   python3 scripts/api_key_manager.py create \
     -n "Acme Corporation" \
     -d "Production API access for Acme Corp" \
     -p "read,write"
   ```

2. **Save the API Key**
   - The API key is only shown once during creation
   - Store it securely in your customer's credential management system
   - Provide the key to the customer via secure channel

3. **Provide Documentation**
   - Share the API endpoints and usage examples
   - Include authentication headers format: `x-api-key: YOUR_API_KEY`

### For Trial/Demo Users

```bash
python3 scripts/api_key_manager.py create \
  -n "Trial User - Company Name" \
  -d "30-day trial access" \
  -p "read" \
  -e 30
```

## API Key Permissions

Available permission levels:
- `read` - Access to GET endpoints only
- `write` - Access to POST/PUT endpoints (includes read)
- `admin` - Full access (use with caution)

## Security Features

### Post-Quantum Encryption
- API keys are encrypted using ML-KEM-768 + ChaCha20-Poly1305
- Keys are stored as hashes for fast lookup
- Full key values are never stored in plain text

### Audit Logging
- All API key creation/usage is logged
- NIST FIPS 203/204/205 compliance monitoring
- Real-time security event detection

### Access Control
- Constant-time key comparison (timing attack protection)
- Rate limiting per key
- Request validation and sanitization
- VPC isolation and private networking

## API Endpoints

### Authentication
All API requests require authentication:
```bash
curl -H "x-api-key: YOUR_API_KEY" https://api.cypheronlabs.com/endpoint
```

### Key Endpoints
- `GET /health` - Service health check
- `GET /public/status` - API status information
- `POST /kem/keygen` - Generate key pairs (ML-KEM-768)
- `POST /kem/encaps` - Key encapsulation
- `POST /kem/decaps` - Key decapsulation
- `POST /sig/keygen` - Generate signing keys (ML-DSA)
- `POST /sig/sign` - Digital signing
- `POST /sig/verify` - Signature verification

### Admin Endpoints (Requires Master Admin Key)
- `GET /admin/api-keys` - List API keys
- `POST /admin/api-keys` - Create new API key
- `GET /admin/audit-logs` - Retrieve audit logs

## Troubleshooting

### Common Issues

#### 1. "401 Unauthorized" when creating keys
This usually indicates an authentication issue:

**Solution A: Verify Google Cloud Authentication**
```bash
gcloud auth list
gcloud auth login  # if needed
```

**Solution B: Check Master Admin Key**
The master admin key might need to be in a different format. Try:
```bash
# Check if the secret exists
gcloud secrets versions access latest --secret="pq-master-admin-key"

# Verify the key format (should be base64-encoded 32 bytes)
```

**Solution C: Direct Firestore Access (Emergency)**
If the API endpoints are not working, you can add keys directly to Firestore:
```bash
# This requires a separate script for direct database access
# Contact support for the Firestore management utility
```

#### 2. "403 Forbidden" from Google Frontend
This indicates Cloud Run IAM permissions are blocking requests:

**Solution:**
```bash
# Check if you have run.invoker permissions
gcloud run services get-iam-policy cypheron-api --region=us-central1
```

#### 3. Service Not Ready
If the service shows as not ready:

**Check Secrets:**
```bash
gcloud secrets versions list pq-encryption-password
gcloud secrets versions list pq-master-admin-key
```

**Check Service Status:**
```bash
gcloud run services describe cypheron-api --region=us-central1
```

### Emergency Key Creation

If the API endpoints are unavailable, you can create keys directly in Firestore using the backup script:

```bash
# Emergency key creation (requires development environment)
python3 scripts/emergency_key_creator.py \
  --customer "Emergency Customer" \
  --permissions "read" \
  --firestore-project "cypheron-api"
```

## Customer Integration Examples

### Python Example
```python
import requests

api_key = "your_api_key_here"
headers = {"x-api-key": api_key}

# Generate a key pair
response = requests.post(
    "https://api.cypheronlabs.com/kem/keygen",
    headers=headers,
    json={}
)

if response.status_code == 200:
    keys = response.json()
    print(f"Public key: {keys['public_key']}")
    print(f"Private key: {keys['private_key']}")
```

### cURL Example
```bash
# Test API connectivity
curl -H "x-api-key: YOUR_API_KEY" https://api.cypheronlabs.com/health

# Generate key pair
curl -X POST \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{}' \
  https://api.cypheronlabs.com/kem/keygen
```

### JavaScript Example
```javascript
const apiKey = 'your_api_key_here';

fetch('https://api.cypheronlabs.com/kem/keygen', {
    method: 'POST',
    headers: {
        'x-api-key': apiKey,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
})
.then(response => response.json())
.then(data => {
    console.log('Key pair generated:', data);
});
```

## Monitoring and Analytics

### Key Usage Tracking
- Each API key tracks usage count and last used timestamp
- Real-time monitoring of API performance and security events
- Compliance reporting for enterprise customers

### Alerts
- Failed authentication attempts
- Unusual usage patterns
- Key expiration warnings
- Service health issues

## Support

### Getting Help
- Technical documentation: [API Documentation Link]
- Security questions: security@cypheronlabs.com
- General support: support@cypheronlabs.com

### SLA and Uptime
- 99.9% uptime guarantee
- 24/7 monitoring and alerting
- Post-quantum security compliance (NIST FIPS 203/204/205)

## Best Practices

### For Customers
1. **Store API keys securely** - Use environment variables or secure vaults
2. **Implement proper error handling** - Check response codes and handle failures
3. **Use HTTPS only** - Never send keys over unencrypted connections
4. **Monitor usage** - Track your API usage and set up alerts
5. **Rotate keys periodically** - Request new keys on a regular schedule

### For Key Management
1. **Use descriptive names** - Include customer name and purpose
2. **Set appropriate permissions** - Follow principle of least privilege
3. **Set expiration dates for trials** - Automatically expire demo keys
4. **Monitor key usage** - Track which keys are actively used
5. **Audit regularly** - Review active keys and disable unused ones

## Pricing Tiers

### Starter (Free Tier)
- 1,000 API calls per month
- Read-only access
- Community support

### Professional
- 100,000 API calls per month
- Read/write access
- Email support
- SLA guarantee

### Enterprise
- Unlimited API calls
- Full access including admin endpoints
- Priority support
- Custom compliance reporting
- Dedicated support team

---

*For the most up-to-date information and additional resources, visit our documentation portal or contact our support team.*