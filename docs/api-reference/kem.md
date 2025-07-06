# Key Encapsulation Mechanisms (KEM)

Key Encapsulation Mechanisms provide a secure way to establish shared secrets between parties. This document covers all KEM operations available in Cypheron-Core.

## Overview

KEMs are the post-quantum replacement for key exchange mechanisms like Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH). They enable two parties to establish a shared secret key that can be used for symmetric encryption.

### How KEMs Work

1. **Key Generation**: Generate a public/private key pair
2. **Encapsulation**: Use the public key to generate a shared secret and ciphertext
3. **Decapsulation**: Use the private key to recover the shared secret from the ciphertext

### Security Properties

- **Confidentiality**: Only the holder of the private key can recover the shared secret
- **Quantum Resistance**: Secure against both classical and quantum computer attacks
- **Perfect Forward Secrecy**: When combined with ephemeral keys
- **Non-Interactive**: No back-and-forth communication required

## Supported Algorithms

Cypheron-Core implements the Kyber family of KEM algorithms, standardized by NIST as ML-KEM.

| Algorithm | Security Level | Public Key Size | Private Key Size | Ciphertext Size | Shared Secret Size |
|-----------|----------------|-----------------|------------------|-----------------|-------------------|
| kyber512  | NIST Level 1   | 800 bytes       | 1,632 bytes      | 768 bytes       | 32 bytes          |
| kyber768  | NIST Level 3   | 1,184 bytes     | 2,400 bytes      | 1,088 bytes     | 32 bytes          |
| kyber1024 | NIST Level 5   | 1,568 bytes     | 3,168 bytes      | 1,568 bytes     | 32 bytes          |

### Algorithm Selection Guide

**Kyber-512** (NIST Level 1):
- **Use Case**: IoT devices, constrained environments
- **Security**: Equivalent to AES-128
- **Performance**: Fastest, smallest keys
- **Recommendation**: Only for non-critical applications

**Kyber-768** (NIST Level 3):
- **Use Case**: Most applications, web services, mobile apps
- **Security**: Equivalent to AES-192  
- **Performance**: Good balance of security and speed
- **Recommendation**: Default choice for most use cases

**Kyber-1024** (NIST Level 5):
- **Use Case**: High-security applications, government, finance
- **Security**: Equivalent to AES-256
- **Performance**: Slower, larger keys
- **Recommendation**: When maximum security is required

## API Endpoints

### Key Generation

Generate a new KEM key pair.

**Endpoint**: `POST /kem/{algorithm}/keygen`

**Parameters**:
- `algorithm`: One of `kyber512`, `kyber768`, `kyber1024`

**Request**:
```bash
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/keygen" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json"
```

**Response**:
```json
{
  "pk": "base64_encoded_public_key...",
  "sk": "base64_encoded_private_key..."
}
```

**Response Fields**:
- `pk`: Base64-encoded public key (share this)
- `sk`: Base64-encoded private key (keep secret!)

### Encapsulation

Generate a shared secret and ciphertext using a public key.

**Endpoint**: `POST /kem/{algorithm}/encapsulate`

**Parameters**:
- `algorithm`: One of `kyber512`, `kyber768`, `kyber1024`

**Request Body**:
```json
{
  "public_key": "base64_encoded_public_key"
}
```

**Request**:
```bash
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/encapsulate" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "dGhpcyBpcyBhIGZha2UgcHVibGljIGtleQ=="
  }'
```

**Response**:
```json
{
  "shared_secret": "mK8rX9vB3pL2nQ7yE4tR6uI1oP5sA8cV...",
  "ciphertext": "aGVsbG8gd29ybGQgdGhpcyBpcyBjeXBoZXJ0ZXh0..."
}
```

**Response Fields**:
- `shared_secret`: Base64-encoded 32-byte shared secret
- `ciphertext`: Base64-encoded ciphertext (send to recipient)

### Decapsulation

Recover the shared secret from ciphertext using a private key.

**Endpoint**: `POST /kem/{algorithm}/decapsulate`

**Parameters**:
- `algorithm`: One of `kyber512`, `kyber768`, `kyber1024`

**Request Body**:
```json
{
  "private_key": "base64_encoded_private_key",
  "ciphertext": "base64_encoded_ciphertext"
}
```

**Request**:
```bash
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/decapsulate" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "cHJpdmF0ZSBrZXkgZGF0YSBoZXJl...",
    "ciphertext": "aGVsbG8gd29ybGQgdGhpcyBpcyBjeXBoZXJ0ZXh0..."
  }'
```

**Response**:
```json
{
  "shared_secret": "mK8rX9vB3pL2nQ7yE4tR6uI1oP5sA8cV..."
}
```

**Response Fields**:
- `shared_secret`: Base64-encoded 32-byte shared secret (should match encapsulation)

## Complete KEM Workflow

Here's a complete example showing how two parties (Alice and Bob) can establish a shared secret:

### Step 1: Bob generates a key pair

```bash
# Bob generates his KEM key pair
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/keygen" \
  -H "X-API-Key: bob_api_key" \
  -H "Content-Type: application/json"
```

**Bob receives**:
```json
{
  "pk": "Qm9iJ3MgcHVibGljIGtleQ==",
  "sk": "Qm9iJ3MgcHJpdmF0ZSBrZXk="
}
```

Bob keeps his private key (`sk`) secret and shares his public key (`pk`) with Alice.

### Step 2: Alice encapsulates using Bob's public key

```bash
# Alice creates shared secret using Bob's public key
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/encapsulate" \
  -H "X-API-Key: alice_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "Qm9iJ3MgcHVibGljIGtleQ=="
  }'
```

**Alice receives**:
```json
{
  "shared_secret": "c2hhcmVkIHNlY3JldCBkYXRh",
  "ciphertext": "Y2lwaGVydGV4dCBkYXRh"
}
```

Alice now has:
- `shared_secret`: The secret key for symmetric encryption
- `ciphertext`: Data to send to Bob

### Step 3: Alice sends ciphertext to Bob

Alice sends the `ciphertext` to Bob through any communication channel (email, message, etc.). The ciphertext can be transmitted over an insecure channel.

### Step 4: Bob decapsulates to get the shared secret

```bash
# Bob recovers the shared secret using his private key
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/decapsulate" \
  -H "X-API-Key: bob_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "Qm9iJ3MgcHJpdmF0ZSBrZXk=",
    "ciphertext": "Y2lwaGVydGV4dCBkYXRh"
  }'
```

**Bob receives**:
```json
{
  "shared_secret": "c2hhcmVkIHNlY3JldCBkYXRh"
}
```

### Step 5: Both parties have the same shared secret

Both Alice and Bob now have the same `shared_secret` that they can use for:
- Symmetric encryption (AES)
- Message authentication (HMAC)
- Key derivation (HKDF)

## Integration Patterns

### Pattern 1: One-Time Key Exchange

For establishing a single shared secret:

```python
def establish_shared_secret(recipient_public_key):
    # Encapsulate using recipient's public key
    response = requests.post(
        "https://api.cypheronlabs.com/kem/kyber768/encapsulate",
        headers={"X-API-Key": api_key},
        json={"public_key": recipient_public_key}
    )
    result = response.json()
    
    # Send ciphertext to recipient
    send_to_recipient(result["ciphertext"])
    
    # Use shared secret for encryption
    return result["shared_secret"]

def receive_shared_secret(private_key, ciphertext):
    # Decapsulate to get shared secret
    response = requests.post(
        "https://api.cypheronlabs.com/kem/kyber768/decapsulate", 
        headers={"X-API-Key": api_key},
        json={
            "private_key": private_key,
            "ciphertext": ciphertext
        }
    )
    return response.json()["shared_secret"]
```

### Pattern 2: Ephemeral Key Exchange

For perfect forward secrecy, generate new key pairs for each session:

```python
def establish_ephemeral_secret():
    # Generate new key pair for this session
    keygen_response = requests.post(
        "https://api.cypheronlabs.com/kem/kyber768/keygen",
        headers={"X-API-Key": api_key}
    )
    keys = keygen_response.json()
    
    # Use the keys for one session, then discard
    try:
        return perform_key_exchange(keys)
    finally:
        # Securely delete ephemeral keys
        secure_delete(keys["sk"])
```

### Pattern 3: Hybrid KEM (Classical + Post-Quantum)

Combine classical ECDH with post-quantum KEM for defense in depth:

```python
def hybrid_key_exchange(classical_pubkey, pq_pubkey):
    # Classical ECDH
    classical_secret = ecdh_exchange(classical_pubkey)
    
    # Post-quantum KEM
    pq_response = requests.post(
        "https://api.cypheronlabs.com/kem/kyber768/encapsulate",
        headers={"X-API-Key": api_key},
        json={"public_key": pq_pubkey}
    )
    pq_secret = pq_response.json()["shared_secret"]
    
    # Combine both secrets
    combined_secret = hkdf_expand(
        classical_secret + pq_secret,
        length=32,
        info=b"hybrid-kem"
    )
    
    return combined_secret, pq_response.json()["ciphertext"]
```

## Error Handling

### Common Errors

**Invalid Algorithm**:
```json
{
  "error": "invalid_algorithm",
  "message": "Algorithm 'kyber999' not supported",
  "code": 400
}
```

**Invalid Public Key**:
```json
{
  "error": "invalid_public_key", 
  "message": "Public key has invalid format or length",
  "code": 400
}
```

**Invalid Private Key**:
```json
{
  "error": "invalid_private_key",
  "message": "Private key has invalid format or length", 
  "code": 400
}
```

**Invalid Ciphertext**:
```json
{
  "error": "invalid_ciphertext",
  "message": "Ciphertext has invalid format or length",
  "code": 400
}
```

**Decapsulation Failure**:
```json
{
  "error": "decapsulation_failed",
  "message": "Failed to decapsulate ciphertext with provided private key",
  "code": 400
}
```

### Error Handling Best Practices

```python
def safe_kem_operation(operation, **kwargs):
    try:
        response = requests.post(
            f"https://api.cypheronlabs.com/kem/{operation}",
            headers={"X-API-Key": api_key},
            json=kwargs
        )
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            error = e.response.json()
            if error["error"] == "invalid_public_key":
                raise ValueError("Invalid public key format")
            elif error["error"] == "decapsulation_failed":
                raise ValueError("Decapsulation failed - key/ciphertext mismatch")
        raise
        
    except requests.exceptions.RequestException:
        # Handle network errors
        raise ConnectionError("Failed to connect to Cypheron-Core API")
```

## Performance Considerations

### Benchmarks

Typical performance characteristics on modern hardware:

| Algorithm | Key Generation | Encapsulation | Decapsulation |
|-----------|----------------|---------------|---------------|
| kyber512  | ~0.1ms        | ~0.1ms        | ~0.1ms        |
| kyber768  | ~0.2ms        | ~0.2ms        | ~0.2ms        |
| kyber1024 | ~0.3ms        | ~0.3ms        | ~0.3ms        |

### Optimization Tips

1. **Cache Key Pairs**: Reuse key pairs when appropriate
2. **Batch Operations**: Group multiple operations when possible
3. **Algorithm Choice**: Use Kyber-768 for best security/performance balance
4. **Connection Pooling**: Reuse HTTP connections for multiple requests

### Memory Usage

| Algorithm | Public Key | Private Key | Ciphertext | Memory Peak |
|-----------|------------|-------------|------------|-------------|
| kyber512  | 800 B      | 1,632 B     | 768 B      | ~4 KB       |
| kyber768  | 1,184 B    | 2,400 B     | 1,088 B    | ~6 KB       |
| kyber1024 | 1,568 B    | 3,168 B     | 1,568 B    | ~8 KB       |

## Security Considerations

### Key Management

1. **Private Key Protection**: Store private keys securely (HSM, secure enclave)
2. **Key Rotation**: Regularly rotate long-term keys
3. **Ephemeral Keys**: Use ephemeral keys for perfect forward secrecy
4. **Secure Deletion**: Properly delete keys from memory after use

### Implementation Security

1. **Constant-Time Operations**: The API uses constant-time implementations
2. **Side-Channel Resistance**: Protected against timing and power analysis
3. **Random Number Generation**: Uses cryptographically secure random sources
4. **Memory Protection**: Keys are cleared from memory after operations

### Protocol Design

1. **Authentication**: Combine KEMs with authentication mechanisms
2. **Replay Protection**: Include timestamps or nonces in protocols
3. **Forward Secrecy**: Use ephemeral keys when possible
4. **Hybrid Security**: Consider combining with classical algorithms during transition

## Migration from Classical KEMs

### From ECDH

**Before (ECDH)**:
```python
# Classical ECDH
alice_private = generate_private_key()
alice_public = alice_private.public_key()

bob_private = generate_private_key() 
bob_public = bob_private.public_key()

# Alice computes shared secret
shared_secret = alice_private.exchange(bob_public)
```

**After (Kyber)**:
```python
# Post-quantum KEM
# Bob generates key pair
bob_keys = cypheron_client.kem_keygen("kyber768")

# Alice encapsulates
result = cypheron_client.kem_encapsulate("kyber768", bob_keys["pk"])
alice_secret = result["shared_secret"]

# Alice sends ciphertext to Bob
# Bob decapsulates
bob_result = cypheron_client.kem_decapsulate("kyber768", bob_keys["sk"], result["ciphertext"])
bob_secret = bob_result["shared_secret"]

# alice_secret == bob_secret
```

### Migration Strategy

1. **Phase 1**: Deploy hybrid (ECDH + Kyber) systems
2. **Phase 2**: Gradually increase reliance on Kyber
3. **Phase 3**: Phase out ECDH in favor of Kyber-only

## Next Steps

- **Digital Signatures**: Learn about [Digital Signatures](signatures.md)
- **Hybrid Crypto**: Explore [Hybrid Cryptography](hybrid.md)
- **Examples**: See [Integration Patterns](../examples/integration-patterns.md)
- **Security**: Review [Security Best Practices](../security/best-practices.md)

---

*Ready to add authentication to your key exchange? Continue to [Digital Signatures](signatures.md).*