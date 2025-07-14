# Cypheron Core API Cheat Sheet

## Quick Start

**Your API Key**: `pq_live_test123`  
**Base URL**: `http://localhost:3000` (local) or `https://api.cypheronlabs.com` (production)

## Authentication

All requests require the API key in the header:
```bash
-H "X-API-Key: pq_live_test123"
```

## Health & Status

### Health Check
```bash
curl -H "X-API-Key: pq_live_test123" http://localhost:3000/health
```

### API Info
```bash
curl -H "X-API-Key: pq_live_test123" http://localhost:3000/info
```

## Post-Quantum Key Encapsulation (KEM)

### Generate KEM Keys

#### Kyber-768 (ML-KEM-768)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/kem/kyber768/keygen
```

#### Kyber-512 (ML-KEM-512)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/kem/kyber512/keygen
```

#### Kyber-1024 (ML-KEM-1024)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/kem/kyber1024/keygen
```

### Encapsulate Secret
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"pk": "YOUR_PUBLIC_KEY_HERE"}' \
  http://localhost:3000/kem/kyber768/encapsulate
```

### Decapsulate Secret
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"sk": "YOUR_SECRET_KEY_HERE", "ct": "YOUR_CIPHERTEXT_HERE"}' \
  http://localhost:3000/kem/kyber768/decapsulate
```

## Post-Quantum Digital Signatures

### Generate Signature Keys

#### Dilithium-2 (ML-DSA-44)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/dilithium2/keygen
```

#### Dilithium-3 (ML-DSA-65)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/dilithium3/keygen
```

#### Dilithium-5 (ML-DSA-87)
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/dilithium5/keygen
```

#### Falcon-512
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/falcon512/keygen
```

#### Falcon-1024
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/falcon1024/keygen
```

### Sign Document
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"sk": "YOUR_SECRET_KEY", "message": "SGVsbG8gV29ybGQ="}' \
  http://localhost:3000/sig/dilithium3/sign
```

### Verify Signature
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"pk": "YOUR_PUBLIC_KEY", "message": "SGVsbG8gV29ybGQ=", "signature": "YOUR_SIGNATURE"}' \
  http://localhost:3000/sig/dilithium3/verify
```

## Hybrid Cryptography (Classical + Post-Quantum)

### Hybrid Sign
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"message": "SGVsbG8gV29ybGQ=", "classical_algorithm": "ed25519", "pq_algorithm": "dilithium3"}' \
  http://localhost:3000/hybrid/sign
```

### Hybrid Verify
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"message": "SGVsbG8gV29ybGQ=", "classical_signature": "YOUR_CLASSICAL_SIG", "pq_signature": "YOUR_PQ_SIG"}' \
  http://localhost:3000/hybrid/verify
```

## NIST Competition Algorithms

### SPHINCS+ (Hash-Based Signatures)
```bash
# SPHINCS+ SHA2-128f
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/sphincs_sha2_128f/keygen

# SPHINCS+ SHA2-192f
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/sphincs_sha2_192f/keygen

# SPHINCS+ SHA2-256f
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/sphincs_sha2_256f/keygen
```

## Admin & Management

### Create New API Key
```bash
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My New API Key",
    "permissions": ["kem:*", "sig:*", "hybrid:*"],
    "rate_limit": 100,
    "expires_in_days": 90
  }' \
  http://localhost:3000/admin/api-keys
```

### List API Keys
```bash
curl -H "X-API-Key: pq_live_test123" \
  http://localhost:3000/admin/api-keys
```

## Monitoring & Metrics

### Get Metrics
```bash
curl -H "X-API-Key: pq_live_test123" \
  http://localhost:3000/metrics
```

### Security Events
```bash
curl -H "X-API-Key: pq_live_test123" \
  http://localhost:3000/admin/security-events
```

## Common Use Cases

### 1. Complete KEM Workflow
```bash
# Step 1: Generate keys
KEYS=$(curl -s -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/kem/kyber768/keygen)

# Step 2: Extract public key (you'll need to parse JSON)
PK=$(echo $KEYS | jq -r '.pk')

# Step 3: Encapsulate
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d "{\"pk\": \"$PK\"}" \
  http://localhost:3000/kem/kyber768/encapsulate
```

### 2. Complete Signature Workflow
```bash
# Step 1: Generate signature keys
KEYS=$(curl -s -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  http://localhost:3000/sig/dilithium3/keygen)

# Step 2: Sign a message (base64 encoded "Hello World")
curl -X POST -H "X-API-Key: pq_live_test123" \
  -H "Content-Type: application/json" \
  -d '{"sk": "YOUR_SECRET_KEY", "message": "SGVsbG8gV29ybGQ="}' \
  http://localhost:3000/sig/dilithium3/sign
```

### 3. Test Message Encoding
```bash
# Encode message to base64
echo -n "Hello World" | base64
# Output: SGVsbG8gV29ybGQ=

# Decode message from base64
echo "SGVsbG8gV29ybGQ=" | base64 -d
# Output: Hello World
```

## Error Handling

### Common Error Responses
- **401 Unauthorized**: Invalid API key
- **403 Forbidden**: Insufficient permissions
- **400 Bad Request**: Invalid input data
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Crypto operation failed

### Rate Limits
- **Default**: 100 requests per minute
- **Burst**: Up to 120 requests in short periods
- **Admin endpoints**: Lower limits (20 requests per minute)

## Tips & Best Practices

1. **Always use HTTPS** in production
2. **Store API keys securely** (environment variables, not code)
3. **Encode messages in base64** for signing operations
4. **Parse JSON responses** to extract keys and results
5. **Handle rate limits** with exponential backoff
6. **Monitor API health** before critical operations
7. **Use appropriate algorithm strengths** for your security needs

## Algorithm Recommendations

### For Maximum Security (DoD/Government)
- **KEM**: ML-KEM-1024 (Kyber-1024)
- **Signatures**: ML-DSA-87 (Dilithium-5) or SPHINCS+ SHA2-256f

### For Balanced Performance/Security
- **KEM**: ML-KEM-768 (Kyber-768) 
- **Signatures**: ML-DSA-65 (Dilithium-3)

### For High Performance
- **KEM**: ML-KEM-512 (Kyber-512)
- **Signatures**: ML-DSA-44 (Dilithium-2) or Falcon-512

---

**Note**: Replace `localhost:3000` with `api.cypheronlabs.com` when using production deployment.