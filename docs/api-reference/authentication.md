# Authentication

Cypheron-Core uses API key-based authentication to secure access to cryptographic operations. This document covers everything you need to know about authenticating with the API.

## Overview

All API endpoints require authentication using an API key. The API supports two authentication methods:

1. **X-API-Key Header** (Recommended)
2. **Authorization Header with Bearer token**

## Authentication Methods

### Method 1: X-API-Key Header

The recommended method for API authentication:

```bash
curl -X POST "https://api.cypheronlabs.com/sig/dilithium2/keygen" \
  -H "X-API-Key: your_api_key_here" \
  -H "Content-Type: application/json"
```

### Method 2: Authorization Bearer Token

Alternative method using the Authorization header:

```bash
curl -X POST "https://api.cypheronlabs.com/sig/dilithium2/keygen" \
  -H "Authorization: Bearer your_api_key_here" \
  -H "Content-Type: application/json"
```

## API Key Management

### Creating API Keys

API keys are created through the admin interface:

```bash
curl -X POST "https://api.cypheronlabs.com/admin/api-keys" \
  -H "X-API-Key: your_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production App Key",
    "permissions": ["kem:*", "sig:*", "hybrid:*"],
    "rate_limit": 1000,
    "expires_in_days": 365
  }'
```

**Response:**
```json
{
  "api_key": "cypheron_live_ABC123...",
  "key_info": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Production App Key",
    "permissions": ["kem:*", "sig:*", "hybrid:*"],
    "rate_limit": 1000,
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2025-01-15T10:30:00Z",
    "is_active": true,
    "last_used": null,
    "usage_count": 0
  }
}
```

> **Important**: The `api_key` field is only shown once during creation. Store it securely!

### API Key Properties

| Property | Description | Example |
|----------|-------------|---------|
| `name` | Human-readable identifier | "Production App Key" |
| `permissions` | Array of allowed operations | `["kem:*", "sig:verify"]` |
| `rate_limit` | Requests per minute limit | `1000` |
| `expires_in_days` | Key expiration period | `365` (optional) |

### Listing API Keys

View all API keys associated with your account:

```bash
curl -X GET "https://api.cypheronlabs.com/admin/api-keys" \
  -H "X-API-Key: your_admin_key"
```

**Response:**
```json
{
  "keys": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Production App Key", 
      "permissions": ["kem:*", "sig:*"],
      "rate_limit": 1000,
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2025-01-15T10:30:00Z",
      "is_active": true,
      "last_used": "2024-01-20T14:22:33Z",
      "usage_count": 1547
    }
  ]
}
```

## Permission System

Cypheron-Core implements a granular permission system to control access to different operations.

### Permission Format

Permissions follow the format: `resource:operation`

- `resource`: The cryptographic primitive (kem, sig, hybrid)
- `operation`: The specific action (keygen, sign, verify, etc.)
- `*`: Wildcard for all operations

### Available Permissions

| Permission | Description |
|------------|-------------|
| `*` | Full admin access to all operations |
| `kem:*` | All KEM operations |
| `kem:keygen` | KEM key generation only |
| `kem:encapsulate` | KEM encapsulation only |
| `kem:decapsulate` | KEM decapsulation only |
| `sig:*` | All signature operations |
| `sig:keygen` | Signature key generation only |
| `sig:sign` | Message signing only |
| `sig:verify` | Signature verification only |
| `hybrid:*` | All hybrid operations |
| `hybrid:sign` | Hybrid signing only |

### Permission Examples

**Read-Only API Key** (verification only):
```json
{
  "name": "Verification Service",
  "permissions": ["sig:verify"],
  "rate_limit": 500
}
```

**KEM-Only API Key** (for key exchange):
```json
{
  "name": "Key Exchange Service", 
  "permissions": ["kem:*"],
  "rate_limit": 200
}
```

**Full Production Key**:
```json
{
  "name": "Main Application",
  "permissions": ["kem:*", "sig:*", "hybrid:*"],
  "rate_limit": 2000
}
```

## Rate Limiting

Each API key has an associated rate limit that controls the maximum number of requests per minute.

### Rate Limit Headers

Every API response includes rate limiting information:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1642681200
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Total requests allowed per minute |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

### Rate Limit Exceeded

When you exceed your rate limit:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": "rate_limit_exceeded",
  "message": "Rate limit of 1000 requests per minute exceeded",
  "retry_after": 60,
  "code": 429
}
```

### Rate Limit Best Practices

1. **Monitor Usage**: Track rate limit headers to avoid hitting limits
2. **Implement Backoff**: Use exponential backoff when receiving 429 responses
3. **Request Appropriate Limits**: Choose rate limits based on your usage patterns
4. **Cache Results**: Cache responses when possible to reduce API calls

## Security Best Practices

### API Key Security

1. **Secure Storage**: Never store API keys in code or version control
2. **Environment Variables**: Use environment variables or secure key management
3. **Principle of Least Privilege**: Grant minimal required permissions
4. **Regular Rotation**: Rotate API keys periodically
5. **Monitor Usage**: Review audit logs for suspicious activity

### Implementation Examples

**Environment Variables** (Recommended):
```bash
export CYPHERON_CORE_API_KEY="cypheron_live_your_key_here"
```

**Secure Key Management**:
```python
import os
from azure.keyvault.secrets import SecretClient

# Load from Azure Key Vault
client = SecretClient(vault_url="https://vault.vault.azure.net/")
api_key = client.get_secret("cypheron-core-api-key").value
```

**Never Do This**:
```python
# DON'T: Hardcode API keys
api_key = "cypheron_live_ABC123..."  # BAD!

# DON'T: Store in version control
config.json: {"api_key": "cypheron_live_ABC123..."}  # BAD!
```

## Authentication Errors

### Error Response Format

All authentication errors return a consistent format:

```json
{
  "error": "error_code",
  "message": "Human readable description", 
  "code": 401
}
```

### Common Authentication Errors

**Missing API Key**:
```bash
# Request without authentication
curl -X POST "https://api.cypheronlabs.com/sig/dilithium2/keygen"
```

```json
{
  "error": "missing_api_key",
  "message": "API key required. Use X-API-Key header or Authorization: Bearer <key>",
  "code": 401
}
```

**Invalid API Key**:
```json
{
  "error": "invalid_api_key", 
  "message": "Invalid or expired API key",
  "code": 401
}
```

**Insufficient Permissions**:
```json
{
  "error": "insufficient_permissions",
  "message": "Insufficient permissions for resource: sig:sign",
  "code": 403
}
```

**Expired API Key**:
```json
{
  "error": "invalid_api_key",
  "message": "Invalid or expired API key", 
  "code": 401
}
```

### Handling Authentication Errors

**Python Example**:
```python
import requests

def make_authenticated_request(endpoint, api_key, data=None):
    headers = {
        'X-API-Key': api_key,
        'Content-Type': 'application/json'
    }
    
    response = requests.post(endpoint, headers=headers, json=data)
    
    if response.status_code == 401:
        error = response.json()
        if error['error'] == 'missing_api_key':
            raise ValueError("API key not provided")
        elif error['error'] == 'invalid_api_key':
            raise ValueError("API key is invalid or expired")
    elif response.status_code == 403:
        raise PermissionError("Insufficient permissions for this operation")
    elif response.status_code == 429:
        raise RuntimeError("Rate limit exceeded")
    
    response.raise_for_status()
    return response.json()
```

## Monitoring and Auditing

### Audit Logs

All API key usage is logged for security monitoring:

```bash
curl -X GET "https://api.cypheronlabs.com/admin/audit-logs?limit=50" \
  -H "X-API-Key: your_admin_key"
```

**Response:**
```json
{
  "events": [
    {
      "id": "evt_123456",
      "timestamp": "2024-01-20T14:22:33Z",
      "event_type": "api_key_used",
      "api_key_id": "550e8400-e29b-41d4-a716-446655440000",
      "ip_address": "192.168.1.100",
      "request_method": "POST",
      "request_path": "/sig/dilithium2/sign",
      "response_status": 200,
      "response_time_ms": 45
    }
  ]
}
```

### Security Events

Monitor these security events in audit logs:

- `api_key_used`: Normal API key usage
- `authentication_failed`: Failed authentication attempts
- `authorization_failed`: Permission denied
- `rate_limit_exceeded`: Rate limit violations
- `suspicious_activity`: Detected anomalies

## Integration Examples

### Client Libraries

**Python Client**:
```python
class CypheronCoreClient:
    def __init__(self, api_key, base_url="https://api.cypheronlabs.com"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def sign_message(self, algorithm, private_key, message):
        response = self.session.post(
            f"{self.base_url}/sig/{algorithm}/sign",
            json={
                "private_key": private_key,
                "message": message
            }
        )
        response.raise_for_status()
        return response.json()
```

**JavaScript Client**:
```javascript
class CypheronCoreClient {
    constructor(apiKey, baseUrl = 'https://api.cypheronlabs.com') {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }
    
    async signMessage(algorithm, privateKey, message) {
        const response = await fetch(`${this.baseUrl}/sig/${algorithm}/sign`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                private_key: privateKey,
                message: message
            })
        });
        
        if (!response.ok) {
            throw new Error(`API call failed: ${response.status}`);
        }
        
        return response.json();
    }
}
```

## Next Steps

- **API Reference**: Explore [KEM Operations](kem.md), [Digital Signatures](signatures.md), and [Hybrid Cryptography](hybrid.md)
- **Security**: Learn about [API Security Features](../security/api-security.md)
- **Examples**: See [Client Libraries](../examples/client-libraries.md) for complete implementations
- **Production**: Review [Deployment Best Practices](../advanced/deployment.md)

---

*Ready to make authenticated API calls? Continue to [KEM Operations](kem.md) or [Digital Signatures](signatures.md).*