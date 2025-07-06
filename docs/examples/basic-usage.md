# Basic Usage Examples

This guide provides practical examples for common post-quantum cryptography tasks using Cypheron-Core. Each example includes complete, working code that you can adapt for your applications.

## Prerequisites

- Cypheron-Core API access with valid API key
- Basic understanding of REST APIs
- One of: `curl`, Python with `requests`, or Node.js with `axios`

## Example 1: Secure Document Signing

This example shows how to digitally sign a document and verify the signature.

### Scenario

You need to sign a contract or document to prove authenticity and prevent tampering.

### Implementation

**Step 1: Generate signing keys**

```bash
curl -X POST "https://api.cypheronlabs.com/sig/dilithium3/keygen" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json"
```

**Response:**

```json
{
  "pk": "RGlsaXRoaXVtMyBwdWJsaWMga2V5IGRhdGE...",
  "sk": "RGlsaXRoaXVtMyBwcml2YXRlIGtleSBkYXRh..."
}
```

**Step 2: Prepare document**

```bash
# Create hash of document (in practice, hash the actual file)
DOCUMENT_HASH=$(echo "This is my important contract" | base64)
echo "Document hash: $DOCUMENT_HASH"
```

**Step 3: Sign the document**

```bash
curl -X POST "https://api.cypheronlabs.com/sig/dilithium3/sign" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d "{
    \"private_key\": \"RGlsaXRoaXVtMyBwcml2YXRlIGtleSBkYXRh...\",
    \"message\": \"$DOCUMENT_HASH\"
  }"
```

**Response:**

```json
{
  "signature": "RGlsaXRoaXVtMyBzaWduYXR1cmUgZGF0YQ...",
  "algorithm": "dilithium3"
}
```

**Step 4: Verify the signature**

```bash
curl -X POST "https://api.cypheronlabs.com/sig/dilithium3/verify" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d "{
    \"public_key\": \"RGlsaXRoaXVtMyBwdWJsaWMga2V5IGRhdGE...\",
    \"message\": \"$DOCUMENT_HASH\",
    \"signature\": \"RGlsaXRoaXVtMyBzaWduYXR1cmUgZGF0YQ...\"
  }"
```

**Response:**

```json
{
  "valid": true,
  "algorithm": "dilithium3"
}
```

### Python Implementation

```python
import requests
import base64
import hashlib

class DocumentSigner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.cypheronlabs.com"
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def generate_signing_keys(self, algorithm="dilithium3"):
        """Generate a new signing key pair"""
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/keygen",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def sign_document(self, document_content, private_key, algorithm="dilithium3"):
        """Sign a document and return signature"""
        # Hash the document
        document_hash = hashlib.sha256(document_content.encode()).digest()
        document_b64 = base64.b64encode(document_hash).decode()
        
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/sign",
            headers=self.headers,
            json={
                "private_key": private_key,
                "message": document_b64
            }
        )
        response.raise_for_status()
        return response.json()
    
    def verify_document(self, document_content, signature, public_key, algorithm="dilithium3"):
        """Verify a document signature"""
        # Hash the document (same as signing)
        document_hash = hashlib.sha256(document_content.encode()).digest()
        document_b64 = base64.b64encode(document_hash).decode()
        
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/verify",
            headers=self.headers,
            json={
                "public_key": public_key,
                "message": document_b64,
                "signature": signature
            }
        )
        response.raise_for_status()
        return response.json()

# Example usage
if __name__ == "__main__":
    signer = DocumentSigner("your_api_key")
    
    # Generate keys
    keys = signer.generate_signing_keys()
    print(f"Generated keys: {keys['pk'][:50]}...")
    
    # Sign document
    document = "This is my important contract that needs to be signed."
    signature_result = signer.sign_document(document, keys["sk"])
    print(f"Document signed: {signature_result['signature'][:50]}...")
    
    # Verify signature
    verification = signer.verify_document(
        document, 
        signature_result["signature"], 
        keys["pk"]
    )
    print(f"Signature valid: {verification['valid']}")
```

## Example 2: Secure Message Exchange

This example demonstrates secure communication between two parties using key encapsulation.

### Scenario

Alice wants to send Bob a confidential message. They need to establish a shared secret for encryption.

### Implementation

**Step 1: Bob generates KEM keys**

```bash
# Bob generates his key pair
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/keygen" \
  -H "X-API-Key: bob_api_key" \
  -H "Content-Type: application/json"
```

**Bob's response:**

```json
{
  "pk": "Qm9iJ3MgS3liZXI3NjggcHVibGljIGtleQ==",
  "sk": "Qm9iJ3MgS3liZXI3NjggcHJpdmF0ZSBrZXk="
}
```

**Step 2: Alice encapsulates a shared secret**

```bash
# Alice creates shared secret using Bob's public key
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/encapsulate" \
  -H "X-API-Key: alice_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "Qm9iJ3MgS3liZXI3NjggcHVibGljIGtleQ=="
  }'
```

**Alice's response:**

```json
{
  "shared_secret": "QWxpY2UgYW5kIEJvYiBzaGFyZWQgc2VjcmV0",
  "ciphertext": "RW5jYXBzdWxhdGVkIGRhdGEgZm9yIEJvYg=="
}
```

**Step 3: Alice encrypts her message**

```python
# Alice encrypts her message with the shared secret
from cryptography.fernet import Fernet
import base64

shared_secret = base64.b64decode("QWxpY2UgYW5kIEJvYiBzaGFyZWQgc2VjcmV0")
fernet_key = base64.urlsafe_b64encode(shared_secret)
cipher = Fernet(fernet_key)

message = "This is Alice's confidential message to Bob"
encrypted_message = cipher.encrypt(message.encode())
```

**Step 4: Alice sends to Bob**
Alice sends Bob:

- The ciphertext from KEM encapsulation
- The encrypted message

**Step 5: Bob decapsulates and decrypts**

```bash
# Bob recovers the shared secret
curl -X POST "https://api.cypheronlabs.com/kem/kyber768/decapsulate" \
  -H "X-API-Key: bob_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "Qm9iJ3MgS3liZXI3NjggcHJpdmF0ZSBrZXk=",
    "ciphertext": "RW5jYXBzdWxhdGVkIGRhdGEgZm9yIEJvYg=="
  }'
```

**Bob's response:**

```json
{
  "shared_secret": "QWxpY2UgYW5kIEJvYiBzaGFyZWQgc2VjcmV0"
}
```

```python
# Bob decrypts Alice's message
shared_secret = base64.b64decode("QWxpY2UgYW5kIEJvYiBzaGFyZWQgc2VjcmV0")
fernet_key = base64.urlsafe_b64encode(shared_secret)
cipher = Fernet(fernet_key)

decrypted_message = cipher.decrypt(encrypted_message)
print(f"Alice's message: {decrypted_message.decode()}")
```

### Complete Python Implementation

```python
import requests
import base64
from cryptography.fernet import Fernet
import hashlib

class SecureMessenger:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.cypheronlabs.com"
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def generate_kem_keys(self, algorithm="kyber768"):
        """Generate KEM key pair for receiving messages"""
        response = requests.post(
            f"{self.base_url}/kem/{algorithm}/keygen",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def encapsulate_secret(self, public_key, algorithm="kyber768"):
        """Create shared secret using recipient's public key"""
        response = requests.post(
            f"{self.base_url}/kem/{algorithm}/encapsulate",
            headers=self.headers,
            json={"public_key": public_key}
        )
        response.raise_for_status()
        return response.json()
    
    def decapsulate_secret(self, private_key, ciphertext, algorithm="kyber768"):
        """Recover shared secret using private key"""
        response = requests.post(
            f"{self.base_url}/kem/{algorithm}/decapsulate",
            headers=self.headers,
            json={
                "private_key": private_key,
                "ciphertext": ciphertext
            }
        )
        response.raise_for_status()
        return response.json()
    
    def encrypt_message(self, message, shared_secret_b64):
        """Encrypt message using shared secret"""
        # Derive encryption key from shared secret
        shared_secret = base64.b64decode(shared_secret_b64)
        key = hashlib.sha256(shared_secret).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        
        cipher = Fernet(fernet_key)
        encrypted = cipher.encrypt(message.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message_b64, shared_secret_b64):
        """Decrypt message using shared secret"""
        # Derive decryption key from shared secret
        shared_secret = base64.b64decode(shared_secret_b64)
        key = hashlib.sha256(shared_secret).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        
        cipher = Fernet(fernet_key)
        encrypted = base64.b64decode(encrypted_message_b64)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()

# Example: Alice sends Bob a secure message
def alice_bob_example():
    alice = SecureMessenger("alice_api_key")
    bob = SecureMessenger("bob_api_key")
    
    # Bob generates keys and shares public key
    bob_keys = bob.generate_kem_keys()
    print("Bob generated KEM keys")
    
    # Alice creates shared secret
    kem_result = alice.encapsulate_secret(bob_keys["pk"])
    shared_secret = kem_result["shared_secret"]
    ciphertext = kem_result["ciphertext"]
    print("Alice created shared secret")
    
    # Alice encrypts her message
    message = "Hello Bob! This is a secret message from Alice."
    encrypted_message = alice.encrypt_message(message, shared_secret)
    print("Alice encrypted message")
    
    # Alice sends to Bob: ciphertext + encrypted_message
    print(f"Alice sends to Bob:")
    print(f"  KEM ciphertext: {ciphertext[:50]}...")
    print(f"  Encrypted message: {encrypted_message[:50]}...")
    
    # Bob recovers shared secret
    bob_secret = bob.decapsulate_secret(bob_keys["sk"], ciphertext)
    print("Bob recovered shared secret")
    
    # Bob decrypts message
    decrypted = bob.decrypt_message(encrypted_message, bob_secret["shared_secret"])
    print(f"Bob decrypted message: '{decrypted}'")

if __name__ == "__main__":
    alice_bob_example()
```

## Example 3: Multi-Party Signature Verification

This example shows how to verify signatures from multiple parties, useful for document approval workflows.

### Scenario

A document needs approval from three department heads. Each must sign with their own key.

### Implementation

```python
import requests
import base64
import hashlib
from typing import List, Dict

class MultiPartyVerifier:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.cypheronlabs.com"
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def verify_signature(self, document_hash, signature, public_key, algorithm="dilithium3"):
        """Verify a single signature"""
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/verify",
            headers=self.headers,
            json={
                "public_key": public_key,
                "message": document_hash,
                "signature": signature
            }
        )
        response.raise_for_status()
        return response.json()["valid"]
    
    def verify_multi_party_document(self, document_content: str, signatures: List[Dict]) -> Dict:
        """
        Verify multiple signatures on the same document
        
        signatures format: [
            {
                "signature": "base64_signature",
                "public_key": "base64_public_key", 
                "signer_name": "Alice",
                "algorithm": "dilithium3"
            },
            ...
        ]
        """
        # Hash the document
        document_hash = hashlib.sha256(document_content.encode()).digest()
        document_b64 = base64.b64encode(document_hash).decode()
        
        results = {
            "document_hash": document_b64,
            "total_signatures": len(signatures),
            "valid_signatures": 0,
            "verification_results": []
        }
        
        for i, sig_info in enumerate(signatures):
            try:
                is_valid = self.verify_signature(
                    document_b64,
                    sig_info["signature"],
                    sig_info["public_key"],
                    sig_info.get("algorithm", "dilithium3")
                )
                
                result = {
                    "signer": sig_info.get("signer_name", f"Signer {i+1}"),
                    "algorithm": sig_info.get("algorithm", "dilithium3"),
                    "valid": is_valid,
                    "error": None
                }
                
                if is_valid:
                    results["valid_signatures"] += 1
                    
            except Exception as e:
                result = {
                    "signer": sig_info.get("signer_name", f"Signer {i+1}"),
                    "algorithm": sig_info.get("algorithm", "dilithium3"),
                    "valid": False,
                    "error": str(e)
                }
            
            results["verification_results"].append(result)
        
        results["all_valid"] = results["valid_signatures"] == results["total_signatures"]
        return results

# Example usage
def multi_party_approval_example():
    verifier = MultiPartyVerifier("your_api_key")
    
    # Document that needs approval
    document = """
    BUDGET APPROVAL REQUEST
    Department: Engineering
    Amount: $150,000
    Purpose: Q1 2024 Infrastructure Upgrade
    
    This request requires approval from:
    - CTO (Technical approval)
    - CFO (Financial approval) 
    - CEO (Executive approval)
    """
    
    # Signatures from each approver (in practice, these would be generated separately)
    signatures = [
        {
            "signature": "Q1RPIHNpZ25hdHVyZSBkYXRh...",
            "public_key": "Q1RPIHB1YmxpYyBrZXkgZGF0YQ==",
            "signer_name": "Alice Johnson (CTO)",
            "algorithm": "dilithium3"
        },
        {
            "signature": "Q0ZPIHNpZ25hdHVyZSBkYXRh...",
            "public_key": "Q0ZPIHB1YmxpYyBrZXkgZGF0YQ==", 
            "signer_name": "Bob Smith (CFO)",
            "algorithm": "dilithium3"
        },
        {
            "signature": "Q0VPIHNpZ25hdHVyZSBkYXRh...",
            "public_key": "Q0VPIHB1YmxpYyBrZXkgZGF0YQ==",
            "signer_name": "Carol Brown (CEO)",
            "algorithm": "dilithium3"
        }
    ]
    
    # Verify all signatures
    results = verifier.verify_multi_party_document(document, signatures)
    
    print("Multi-Party Signature Verification Results:")
    print(f"Total signatures: {results['total_signatures']}")
    print(f"Valid signatures: {results['valid_signatures']}")
    print(f"All signatures valid: {results['all_valid']}")
    print()
    
    for result in results["verification_results"]:
        status = "VALID" if result["valid"] else "INVALID"
        print(f"{status} - {result['signer']} ({result['algorithm']})")
        if result["error"]:
            print(f"  Error: {result['error']}")
    
    if results["all_valid"]:
        print("\nDocument fully approved by all parties!")
    else:
        print(f"\nDocument approval incomplete ({results['valid_signatures']}/{results['total_signatures']})")

if __name__ == "__main__":
    multi_party_approval_example()
```

## Example 4: Hybrid Cryptography for Migration

This example shows how to use hybrid cryptography to gradually migrate from classical to post-quantum algorithms.

### Scenario

Your organization is migrating from RSA/ECDSA to post-quantum cryptography but needs to maintain compatibility during the transition.

### Implementation

```bash
# Create a hybrid signature (classical + post-quantum)
curl -X POST "https://api.cypheronlabs.com/hybrid/sign" \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SW1wb3J0YW50IGRvY3VtZW50IGZvciBtaWdyYXRpb24=",
    "classical_algorithm": "ed25519",
    "pq_algorithm": "dilithium3"
  }'
```

**Response:**

```json
{
  "classical_signature": "RWQyNTUxOSBzaWduYXR1cmU=",
  "pq_signature": "RGlsaXRoaXVtMyBzaWduYXR1cmU=",
  "classical_public_key": "RWQyNTUxOSBwdWJrZXk=",
  "pq_public_key": "RGlsaXRoaXVtMyBwdWJrZXk=",
  "combined_signature": "Q29tYmluZWQgc2lnbmF0dXJl"
}
```

### Python Implementation

```python
class HybridCryptoManager:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.cypheronlabs.com"
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def create_hybrid_signature(self, message, classical_alg="ed25519", pq_alg="dilithium3"):
        """Create hybrid signature combining classical and post-quantum"""
        message_b64 = base64.b64encode(message.encode()).decode()
        
        response = requests.post(
            f"{self.base_url}/hybrid/sign",
            headers=self.headers,
            json={
                "message": message_b64,
                "classical_algorithm": classical_alg,
                "pq_algorithm": pq_alg
            }
        )
        response.raise_for_status()
        return response.json()
    
    def verify_hybrid_signature(self, message, hybrid_sig, require_both=True):
        """
        Verify hybrid signature
        
        require_both: If True, both signatures must be valid
                     If False, either signature being valid is sufficient
        """
        message_b64 = base64.b64encode(message.encode()).decode()
        
        # Verify classical signature
        classical_valid = self.verify_classical_signature(
            message_b64, 
            hybrid_sig["classical_signature"],
            hybrid_sig["classical_public_key"]
        )
        
        # Verify post-quantum signature  
        pq_valid = self.verify_pq_signature(
            message_b64,
            hybrid_sig["pq_signature"], 
            hybrid_sig["pq_public_key"]
        )
        
        if require_both:
            return classical_valid and pq_valid
        else:
            return classical_valid or pq_valid
    
    def verify_classical_signature(self, message, signature, public_key):
        """Verify classical signature (placeholder - implement with your classical crypto library)"""
        # In practice, use cryptography library or similar
        return True  # Placeholder
    
    def verify_pq_signature(self, message, signature, public_key, algorithm="dilithium3"):
        """Verify post-quantum signature"""
        response = requests.post(
            f"{self.base_url}/sig/{algorithm}/verify",
            headers=self.headers,
            json={
                "public_key": public_key,
                "message": message,
                "signature": signature
            }
        )
        response.raise_for_status()
        return response.json()["valid"]

# Migration workflow example
def migration_workflow_example():
    hybrid_manager = HybridCryptoManager("your_api_key")
    
    document = "Important contract requiring hybrid signatures during migration period"
    
    # Phase 1: Create hybrid signature
    print("Phase 1: Creating hybrid signature...")
    hybrid_sig = hybrid_manager.create_hybrid_signature(document)
    print("Hybrid signature created")
    
    # Phase 2: Verify with both algorithms required (strict mode)
    print("\nPhase 2: Strict verification (both signatures required)...")
    strict_valid = hybrid_manager.verify_hybrid_signature(
        document, hybrid_sig, require_both=True
    )
    print(f"Strict verification: {strict_valid}")
    
    # Phase 3: Verify with either algorithm sufficient (migration mode)
    print("\nPhase 3: Migration verification (either signature sufficient)...")
    migration_valid = hybrid_manager.verify_hybrid_signature(
        document, hybrid_sig, require_both=False
    )
    print(f"Migration verification: {migration_valid}")
    
    print("\nMigration Strategy:")
    print("1. Deploy hybrid signatures in all new systems")
    print("2. Gradually update verification to prefer PQ signatures")
    print("3. Eventually phase out classical signatures")
    print("4. Maintain backward compatibility during transition")

if __name__ == "__main__":
    migration_workflow_example()
```

## Common Patterns Summary

### Pattern 1: Document Authentication

- Generate signing keys
- Hash document content
- Sign hash with private key
- Distribute document + signature + public key
- Recipients verify signature

### Pattern 2: Secure Communication

- Recipient generates KEM keys
- Sender encapsulates shared secret
- Use shared secret for symmetric encryption
- Recipient decapsulates shared secret
- Decrypt messages with shared secret

### Pattern 3: Multi-Party Approval

- Multiple parties sign same document
- Collect all signatures and public keys
- Verify each signature independently
- Require all signatures to be valid

### Pattern 4: Migration Strategy

- Use hybrid signatures during transition
- Verify both classical and post-quantum
- Gradually phase out classical algorithms
- Maintain backward compatibility

## Next Steps

- **Client Libraries**: See [Language-Specific Clients](client-libraries.md) for complete SDKs
- **Integration**: Learn [Integration Patterns](integration-patterns.md) for production use
- **Security**: Review [Security Best Practices](../security/best-practices.md)
- **Advanced**: Explore [Performance Optimization](../advanced/performance.md)

---

*Ready for more advanced examples? Continue to [Client Libraries](client-libraries.md) for complete SDK implementations.*
