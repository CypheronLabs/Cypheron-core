# Quick Start Guide

Get up and running with Cypheron-Core in 5 minutes! This guide will have you making your first post-quantum cryptographic operations.

## Prerequisites

- Access to a Cypheron-Core API instance
- `curl` or any HTTP client
- Basic understanding of REST APIs

## Step 1: Get Your API Key

Cypheron-Core uses API key authentication. For this quickstart, we'll use the test API key:

```bash
cypheron_test_key_12345
```

> **Production Note**: In production, you'll create unique API keys through the admin interface. See [Authentication](../api-reference/authentication.md) for details.

## Step 2: Verify API Access

Test your connection to the API:

```bash
curl -X POST "http://127.0.0.1:3000/sig/ml-dsa-44/keygen" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json"
```

If successful, you'll see a response with public and private keys:

```json
{
  "pk": "base64_encoded_public_key...",
  "sk": "base64_encoded_private_key..."
}
```

## Step 3: Your First Post-Quantum Operations

Let's walk through the three main types of operations: key generation, signing, and key encapsulation.

### A. Digital Signatures (Authentication)

Digital signatures provide authentication, integrity, and non-repudiation.

#### 1. Generate a Signing Key Pair

```bash
curl -X POST "http://127.0.0.1:3000/sig/ml-dsa-44/keygen" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json"
```

**Response:**

```json
{
  "pk": "5FtUEZJao8UFF6TQnCIwob...",
  "sk": "5FtUEZJao8UFF6TQnCIwob..."
}
```

Save these keys for the next steps:

- `pk`: Public key (share this)
- `sk`: Private key (keep this secret!)

#### 2. Sign a Message

```bash
# Replace YOUR_PRIVATE_KEY with the sk value from step 1
curl -X POST "http://127.0.0.1:3000/sig/ml-dsa-44/sign" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "YOUR_PRIVATE_KEY",
    "message": "SGVsbG8gUG9zdC1RdWFudHVtIFdvcmxkIQ=="
  }'
```

> **Note**: The message is base64 encoded. "SGVsbG8gUG9zdC1RdWFudHVtIFdvcmxkIQ==" decodes to "Hello Post-Quantum World!"

**Response:**

```json
{
  "signature": "3xKj9L8mN2pQ7...",
  "algorithm": "ml-dsa-44"
}
```

#### 3. Verify the Signature

```bash
# Replace YOUR_PUBLIC_KEY and YOUR_SIGNATURE with values from previous steps
curl -X POST "http://127.0.0.1:3000/sig/ml-dsa-44/verify" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "YOUR_PUBLIC_KEY",
    "message": "SGVsbG8gUG9zdC1RdWFudHVtIFdvcmxkIQ==",
    "signature": "YOUR_SIGNATURE"
  }'
```

**Response:**

```json
{
  "valid": true,
  "algorithm": "ml-dsa-44"
}
```

### B. Key Encapsulation (Secure Communication)

Key encapsulation mechanisms (KEMs) establish shared secrets for secure communication.

#### 1. Generate a KEM Key Pair

```bash
curl -X POST "http://127.0.0.1:3000/kem/ml-kem-512/keygen" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json"
```

**Response:**

```json
{
  "pk": "dGhpcyBpcyBhIGZha2Uga3li...",
  "sk": "dGhpcyBpcyBhIGZha2Uga3li..."
}
```

#### 2. Encapsulate a Shared Secret

Use the public key to create a shared secret and ciphertext:

```bash
# Replace YOUR_PUBLIC_KEY with the pk value from step 1
curl -X POST "http://127.0.0.1:3000/kem/ml-kem-512/encapsulate" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "YOUR_PUBLIC_KEY"
  }'
```

**Response:**

```json
{
  "shared_secret": "mK8rX9vB3pL2...",
  "ciphertext": "ciphertext_data..."
}
```

#### 3. Decapsulate the Shared Secret

Use the private key to recover the shared secret:

```bash
# Replace YOUR_PRIVATE_KEY and YOUR_CIPHERTEXT
curl -X POST "http://127.0.0.1:3000/kem/ml-kem-512/decapsulate" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "YOUR_PRIVATE_KEY",
    "ciphertext": "YOUR_CIPHERTEXT"
  }'
```

**Response:**

```json
{
  "shared_secret": "mK8rX9vB3pL2..."
}
```

The shared secret from decapsulation should match the one from encapsulation!

### C. Hybrid Cryptography (Best of Both Worlds)

Hybrid cryptography combines classical and post-quantum algorithms for enhanced security during the migration period.

```bash
curl -X POST "http://127.0.0.1:3000/hybrid/sign" \
  -H "X-API-Key: cypheron_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SGVsbG8gSHlicmlkIFdvcmxkIQ==",
    "classical_algorithm": "ed25519",
    "pq_algorithm": "ml-dsa-44"
  }'
```

**Response:**

```json
{
  "classical_signature": "Ed25519_signature...",
  "pq_signature": "ML-DSA-44_signature...",
  "classical_public_key": "Ed25519_pubkey...",
  "pq_public_key": "ML-DSA-44_pubkey...",
  "combined_signature": "combined_signature_data..."
}
```

## Step 4: Understanding the Response

All successful API calls return JSON with the requested cryptographic data:

### Key Generation Responses

```json
{
  "pk": "base64_encoded_public_key",
  "sk": "base64_encoded_private_key"
}
```

### Signature Responses

```json
{
  "signature": "base64_encoded_signature",
  "algorithm": "algorithm_name"
}
```

### Verification Responses

```json
{
  "valid": true,
  "algorithm": "algorithm_name"
}
```

### Error Responses

```json
{
  "error": "error_code",
  "message": "Human readable description",
  "code": 400
}
```

## Step 5: Try Different Algorithms

Cypheron-Core supports multiple algorithms. Try these variations:

### Signature Algorithms

```bash
# ML-DSA variants (formerly Dilithium, lattice-based)
/sig/ml-dsa-44/keygen  # NIST Level 2 (formerly Dilithium-2)
/sig/ml-dsa-65/keygen  # NIST Level 3 (formerly Dilithium-3)
/sig/ml-dsa-87/keygen  # NIST Level 5 (formerly Dilithium-5)

# Falcon variants (lattice-based, compact)
/sig/falcon512/keygen   # NIST Level 1
/sig/falcon1024/keygen  # NIST Level 5

# SPHINCS+ variants (hash-based)
/sig/sphincs_haraka_128f/keygen  # Fast variant
/sig/sphincs_haraka_128s/keygen  # Small variant
```

### KEM Algorithms

```bash
# ML-KEM variants (formerly Kyber)
/kem/ml-kem-512/keygen   # NIST Level 1 (formerly Kyber-512)
/kem/ml-kem-768/keygen   # NIST Level 3 (formerly Kyber-768)
/kem/ml-kem-1024/keygen  # NIST Level 5 (formerly Kyber-1024)
```

## Step 6: Monitor Your Usage

Check your API key usage and create new keys:

```bash
# List your API keys
curl -X GET "http://127.0.0.1:3000/admin/api-keys" \
  -H "X-API-Key: cypheron_test_key_12345"

# View audit logs
curl -X GET "http://127.0.0.1:3000/admin/audit-logs?limit=10" \
  -H "X-API-Key: cypheron_test_key_12345"
```

## Common Patterns

### Pattern 1: Secure Message Exchange

1. Both parties generate KEM key pairs
2. Party A encapsulates using Party B's public key
3. Party A sends ciphertext to Party B
4. Party B decapsulates to get shared secret
5. Use shared secret for symmetric encryption

### Pattern 2: Document Signing

1. Generate signature key pair
2. Sign document hash with private key
3. Distribute document + signature + public key
4. Recipients verify signature with public key

### Pattern 3: Migration-Safe Deployment

1. Use hybrid signatures for new systems
2. Gradually phase out classical-only signatures
3. Maintain compatibility during transition period

## What's Next?

Now that you've completed the quickstart:

- **Learn More**: [Installation & Setup](installation.md) for production deployment
- **Deep Dive**: [API Reference](../api-reference/) for complete documentation  
- **See Examples**: [Language-Specific Clients](../examples/client-libraries.md)
- **Security**: [Security Best Practices](../security/best-practices.md)
- **Production**: [Deployment Guide](../advanced/deployment.md)

## Troubleshooting

### Common Issues

**401 Unauthorized**

- Check your API key is correct
- Verify the `X-API-Key` header is set
- Ensure the API key hasn't expired

**400 Bad Request**

- Verify JSON payload is valid
- Check base64 encoding of keys/messages
- Ensure required fields are provided

**429 Rate Limited**

- Your API key has exceeded rate limits
- Wait for the rate limit window to reset
- Consider upgrading your API key limits

**500 Internal Server Error**

- Check server logs for details
- Verify the cryptographic operation is valid
- Contact support if the issue persists

### Getting Help

- **API Reference**: Detailed parameter documentation
- **Examples**: Working code in multiple languages
- **GitHub Issues**: Report bugs and request features
- **Community**: Join discussions about post-quantum crypto

---

*Congratulations! You've completed your first post-quantum cryptographic operations. Ready to integrate this into your application? Check out the [API Reference](../api-reference/) for detailed documentation.*
