# PQ-Core API Client Examples

This document provides examples of how to interact with the PQ-Core API using various tools and programming languages.

## API Authentication

All API endpoints require authentication using an API key. You can provide the API key in two ways:

1. **X-API-Key Header**: `X-API-Key: your_api_key_here`
2. **Authorization Header**: `Authorization: Bearer your_api_key_here`

### Test API Key

For testing purposes, use: `pq_test_key_12345`

## cURL Examples

### 1. KEM Operations

#### Generate KEM Keypair
```bash
curl -X POST "http://127.0.0.1:3000/kem/kyber512/keygen" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json"
```

#### KEM Encapsulation
```bash
curl -X POST "http://127.0.0.1:3000/kem/kyber512/encapsulate" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64_encoded_public_key_here"
  }'
```

#### KEM Decapsulation
```bash
curl -X POST "http://127.0.0.1:3000/kem/kyber512/decapsulate" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "base64_encoded_private_key_here",
    "ciphertext": "base64_encoded_ciphertext_here"
  }'
```

### 2. Digital Signature Operations

#### Generate Signature Keypair
```bash
curl -X POST "http://127.0.0.1:3000/sig/dilithium2/keygen" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json"
```

#### Sign Message
```bash
curl -X POST "http://127.0.0.1:3000/sig/dilithium2/sign" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "base64_encoded_private_key_here",
    "message": "SGVsbG8gV29ybGQ="
  }'
```

#### Verify Signature
```bash
curl -X POST "http://127.0.0.1:3000/sig/dilithium2/verify" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64_encoded_public_key_here",
    "message": "SGVsbG8gV29ybGQ=",
    "signature": "base64_encoded_signature_here"
  }'
```

### 3. Hybrid Cryptography

#### Hybrid Sign (Classical + Post-Quantum)
```bash
curl -X POST "http://127.0.0.1:3000/hybrid/sign" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SGVsbG8gV29ybGQ=",
    "classical_algorithm": "ed25519",
    "pq_algorithm": "dilithium2"
  }'
```

### 4. Admin Operations

#### Create New API Key
```bash
curl -X POST "http://127.0.0.1:3000/admin/api-keys" \
  -H "X-API-Key: pq_test_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application Key",
    "permissions": ["kem:*", "sig:*"],
    "rate_limit": 100,
    "expires_in_days": 30
  }'
```

#### List API Keys
```bash
curl -X GET "http://127.0.0.1:3000/admin/api-keys" \
  -H "X-API-Key: pq_test_key_12345"
```

#### View Audit Logs
```bash
curl -X GET "http://127.0.0.1:3000/admin/audit-logs?limit=50&type=security" \
  -H "X-API-Key: pq_test_key_12345"
```

## Python Example

```python
import requests
import base64
import json

class PQCoreClient:
    def __init__(self, base_url="http://127.0.0.1:3000", api_key="pq_test_key_12345"):
        self.base_url = base_url
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def kem_keygen(self, algorithm="kyber512"):
        """Generate KEM keypair"""
        response = requests.post(
            f"{self.base_url}/kem/{algorithm}/keygen",
            headers=self.headers
        )
        return response.json()
    
    def kem_encapsulate(self, algorithm, public_key):
        """KEM encapsulation"""
        response = requests.post(
            f"{self.base_url}/kem/{algorithm}/encapsulate",
            headers=self.headers,
            json={"public_key": public_key}
        )
        return response.json()
    
    def sig_keygen(self, algorithm="dilithium2"):
        """Generate signature keypair"""
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/keygen",
            headers=self.headers
        )
        return response.json()
    
    def sign_message(self, algorithm, private_key, message):
        """Sign a message"""
        # Convert message to base64 if it's a string
        if isinstance(message, str):
            message = base64.b64encode(message.encode()).decode()
        
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/sign",
            headers=self.headers,
            json={
                "private_key": private_key,
                "message": message
            }
        )
        return response.json()
    
    def verify_signature(self, algorithm, public_key, message, signature):
        """Verify a signature"""
        if isinstance(message, str):
            message = base64.b64encode(message.encode()).decode()
        
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/verify",
            headers=self.headers,
            json={
                "public_key": public_key,
                "message": message,
                "signature": signature
            }
        )
        return response.json()

# Example usage
if __name__ == "__main__":
    client = PQCoreClient()
    
    # Generate keys
    print("Generating Dilithium2 keypair...")
    keys = client.sig_keygen("dilithium2")
    print(f"Public key: {keys['public_key'][:50]}...")
    print(f"Private key: {keys['private_key'][:50]}...")
    
    # Sign message
    message = "Hello, Post-Quantum World!"
    print(f"\nSigning message: {message}")
    signature_result = client.sign_message(
        "dilithium2",
        keys["private_key"],
        message
    )
    print(f"Signature: {signature_result['signature'][:50]}...")
    
    # Verify signature
    print("\nVerifying signature...")
    verification = client.verify_signature(
        "dilithium2",
        keys["public_key"],
        message,
        signature_result["signature"]
    )
    print(f"Verification result: {verification['valid']}")
```

## JavaScript/Node.js Example

```javascript
const axios = require('axios');

class PQCoreClient {
    constructor(baseUrl = 'http://127.0.0.1:3000', apiKey = 'pq_test_key_12345') {
        this.baseUrl = baseUrl;
        this.headers = {
            'X-API-Key': apiKey,
            'Content-Type': 'application/json'
        };
    }

    async kemKeygen(algorithm = 'kyber512') {
        const response = await axios.post(
            `${this.baseUrl}/kem/${algorithm}/keygen`,
            {},
            { headers: this.headers }
        );
        return response.data;
    }

    async sigKeygen(algorithm = 'dilithium2') {
        const response = await axios.post(
            `${this.baseUrl}/sig/${algorithm}/keygen`,
            {},
            { headers: this.headers }
        );
        return response.data;
    }

    async signMessage(algorithm, privateKey, message) {
        // Convert message to base64
        const messageBase64 = Buffer.from(message).toString('base64');
        
        const response = await axios.post(
            `${this.baseUrl}/sig/${algorithm}/sign`,
            {
                private_key: privateKey,
                message: messageBase64
            },
            { headers: this.headers }
        );
        return response.data;
    }

    async verifySignature(algorithm, publicKey, message, signature) {
        const messageBase64 = Buffer.from(message).toString('base64');
        
        const response = await axios.post(
            `${this.baseUrl}/sig/${algorithm}/verify`,
            {
                public_key: publicKey,
                message: messageBase64,
                signature: signature
            },
            { headers: this.headers }
        );
        return response.data;
    }
}

// Example usage
async function example() {
    const client = new PQCoreClient();
    
    try {
        // Generate keys
        console.log('Generating Falcon-512 keypair...');
        const keys = await client.sigKeygen('falcon512');
        console.log(`Public key: ${keys.public_key.substring(0, 50)}...`);
        
        // Sign message
        const message = 'Hello, Post-Quantum Cryptography!';
        console.log(`\nSigning message: ${message}`);
        const signatureResult = await client.signMessage('falcon512', keys.private_key, message);
        console.log(`Signature: ${signatureResult.signature.substring(0, 50)}...`);
        
        // Verify signature
        console.log('\nVerifying signature...');
        const verification = await client.verifySignature(
            'falcon512',
            keys.public_key,
            message,
            signatureResult.signature
        );
        console.log(`Verification result: ${verification.valid}`);
        
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
    }
}

example();
```

## Security Headers

The API includes the following security headers in all responses:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`

## Rate Limiting

- Default rate limit: 60 requests per minute per API key
- Rate limit exceeded returns HTTP 429 with `Retry-After` header
- Rate limits can be customized per API key

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "code": 400
}
```

Common error codes:
- `400`: Bad Request (invalid parameters)
- `401`: Unauthorized (missing or invalid API key)
- `403`: Forbidden (insufficient permissions)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

## Available Algorithms

### KEM (Key Encapsulation Mechanism)
- `kyber512`
- `kyber768`
- `kyber1024`

### Digital Signatures
- `dilithium2`
- `dilithium3`
- `dilithium5`
- `falcon512`
- `falcon1024`
- `sphincs_haraka_128f`
- `sphincs_haraka_128s`
- `sphincs_haraka_192f`
- `sphincs_haraka_192s`
- `sphincs_haraka_256f`
- `sphincs_haraka_256s`

### Hybrid Signatures
- Classical: `ed25519`, `secp256k1`
- Post-Quantum: Any of the above signature algorithms