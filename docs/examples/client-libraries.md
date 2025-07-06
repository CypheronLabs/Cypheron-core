# Language-Specific Client Libraries

This guide provides complete client library implementations for popular programming languages, making it easy to integrate Cypheron-Core into your applications.

## Python Client Library

### Complete Implementation

```python
"""
Cypheron-Core Python Client Library
A complete client for interacting with the Cypheron-Core post-quantum cryptography API.
"""

import requests
import base64
import hashlib
import time
import json
from typing import Optional, Dict, List, Union
from dataclasses import dataclass
from enum import Enum


class CypheronCoreError(Exception):
    """Base exception for Cypheron-Core client errors"""
    pass


class AuthenticationError(CypheronCoreError):
    """Raised when API authentication fails"""
    pass


class ValidationError(CypheronCoreError):
    """Raised when input validation fails"""
    pass


class RateLimitError(CypheronCoreError):
    """Raised when rate limit is exceeded"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message)
        self.retry_after = retry_after


class Algorithm(Enum):
    """Supported algorithms"""
    # KEM algorithms
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"
    
    # Signature algorithms
    DILITHIUM_2 = "dilithium2"
    DILITHIUM_3 = "dilithium3"
    DILITHIUM_5 = "dilithium5"
    FALCON_512 = "falcon512"
    FALCON_1024 = "falcon1024"
    SPHINCS_HARAKA_128F = "sphincs_haraka_128f"
    SPHINCS_HARAKA_128S = "sphincs_haraka_128s"
    SPHINCS_HARAKA_192F = "sphincs_haraka_192f"
    SPHINCS_HARAKA_192S = "sphincs_haraka_192s"
    SPHINCS_HARAKA_256F = "sphincs_haraka_256f"
    SPHINCS_HARAKA_256S = "sphincs_haraka_256s"


@dataclass
class KeyPair:
    """Represents a cryptographic key pair"""
    public_key: str
    private_key: str
    algorithm: str


@dataclass
class KEMResult:
    """Result of KEM encapsulation"""
    shared_secret: str
    ciphertext: str


@dataclass
class SignatureResult:
    """Result of digital signature operation"""
    signature: str
    algorithm: str


@dataclass
class VerificationResult:
    """Result of signature verification"""
    valid: bool
    algorithm: str


@dataclass
class HybridSignatureResult:
    """Result of hybrid signature operation"""
    classical_signature: str
    pq_signature: str
    classical_public_key: str
    pq_public_key: str
    combined_signature: str


class CypheronCoreClient:
    """
    Cypheron-Core API Client
    
    Provides methods for all post-quantum cryptographic operations including
    KEM, digital signatures, and hybrid cryptography.
    """
    
    def __init__(self, 
                 api_key: str,
                 base_url: str = "https://api.cypheronlabs.com",
                 timeout: int = 30,
                 max_retries: int = 3):
        """
        Initialize the Cypheron-Core client
        
        Args:
            api_key: Your Cypheron-Core API key
            base_url: Base URL of the Cypheron-Core API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'cypheron-core-python-client/1.0.0'
        })
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make an authenticated HTTP request to the API"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    timeout=self.timeout
                )
                
                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    if attempt < self.max_retries:
                        time.sleep(min(retry_after, 60))
                        continue
                    else:
                        raise RateLimitError(
                            "Rate limit exceeded", 
                            retry_after=retry_after
                        )
                
                # Handle authentication errors
                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key")
                
                # Handle validation errors
                if response.status_code == 400:
                    error_data = response.json()
                    raise ValidationError(f"Validation error: {error_data.get('message', 'Unknown error')}")
                
                # Raise for other HTTP errors
                response.raise_for_status()
                
                return response.json()
                
            except requests.exceptions.Timeout:
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                raise
            
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                raise CypheronCoreError(f"Request failed: {str(e)}")
        
        raise CypheronCoreError("Max retries exceeded")
    
    # KEM Operations
    
    def kem_keygen(self, algorithm: Union[Algorithm, str]) -> KeyPair:
        """
        Generate a KEM key pair
        
        Args:
            algorithm: KEM algorithm to use (kyber512, kyber768, kyber1024)
            
        Returns:
            KeyPair object containing public and private keys
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        result = self._make_request('POST', f'/kem/{algorithm}/keygen')
        return KeyPair(
            public_key=result['pk'],
            private_key=result['sk'],
            algorithm=algorithm
        )
    
    def kem_encapsulate(self, algorithm: Union[Algorithm, str], public_key: str) -> KEMResult:
        """
        Encapsulate a shared secret using KEM
        
        Args:
            algorithm: KEM algorithm to use
            public_key: Base64-encoded public key
            
        Returns:
            KEMResult containing shared secret and ciphertext
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        result = self._make_request(
            'POST', 
            f'/kem/{algorithm}/encapsulate',
            {'public_key': public_key}
        )
        return KEMResult(
            shared_secret=result['shared_secret'],
            ciphertext=result['ciphertext']
        )
    
    def kem_decapsulate(self, algorithm: Union[Algorithm, str], 
                       private_key: str, ciphertext: str) -> str:
        """
        Decapsulate a shared secret using KEM
        
        Args:
            algorithm: KEM algorithm to use
            private_key: Base64-encoded private key
            ciphertext: Base64-encoded ciphertext
            
        Returns:
            Base64-encoded shared secret
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        result = self._make_request(
            'POST',
            f'/kem/{algorithm}/decapsulate',
            {
                'private_key': private_key,
                'ciphertext': ciphertext
            }
        )
        return result['shared_secret']
    
    # Digital Signature Operations
    
    def sig_keygen(self, algorithm: Union[Algorithm, str]) -> KeyPair:
        """
        Generate a signature key pair
        
        Args:
            algorithm: Signature algorithm to use
            
        Returns:
            KeyPair object containing public and private keys
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        result = self._make_request('POST', f'/sig/{algorithm}/keygen')
        return KeyPair(
            public_key=result['pk'],
            private_key=result['sk'],
            algorithm=algorithm
        )
    
    def sign_message(self, algorithm: Union[Algorithm, str], 
                    private_key: str, message: Union[str, bytes]) -> SignatureResult:
        """
        Sign a message
        
        Args:
            algorithm: Signature algorithm to use
            private_key: Base64-encoded private key
            message: Message to sign (string or bytes)
            
        Returns:
            SignatureResult containing the signature
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        # Convert message to base64
        if isinstance(message, str):
            message_b64 = base64.b64encode(message.encode()).decode()
        else:
            message_b64 = base64.b64encode(message).decode()
        
        result = self._make_request(
            'POST',
            f'/sig/{algorithm}/sign',
            {
                'private_key': private_key,
                'message': message_b64
            }
        )
        return SignatureResult(
            signature=result['signature'],
            algorithm=result['algorithm']
        )
    
    def verify_signature(self, algorithm: Union[Algorithm, str],
                        public_key: str, message: Union[str, bytes], 
                        signature: str) -> VerificationResult:
        """
        Verify a digital signature
        
        Args:
            algorithm: Signature algorithm to use
            public_key: Base64-encoded public key
            message: Original message (string or bytes)
            signature: Base64-encoded signature
            
        Returns:
            VerificationResult indicating if signature is valid
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
            
        # Convert message to base64
        if isinstance(message, str):
            message_b64 = base64.b64encode(message.encode()).decode()
        else:
            message_b64 = base64.b64encode(message).decode()
        
        result = self._make_request(
            'POST',
            f'/sig/{algorithm}/verify',
            {
                'public_key': public_key,
                'message': message_b64,
                'signature': signature
            }
        )
        return VerificationResult(
            valid=result['valid'],
            algorithm=result['algorithm']
        )
    
    # Hybrid Cryptography Operations
    
    def hybrid_sign(self, message: Union[str, bytes],
                   classical_algorithm: str = "ed25519",
                   pq_algorithm: Union[Algorithm, str] = Algorithm.DILITHIUM_3) -> HybridSignatureResult:
        """
        Create a hybrid signature (classical + post-quantum)
        
        Args:
            message: Message to sign
            classical_algorithm: Classical signature algorithm
            pq_algorithm: Post-quantum signature algorithm
            
        Returns:
            HybridSignatureResult containing both signatures
        """
        if isinstance(pq_algorithm, Algorithm):
            pq_algorithm = pq_algorithm.value
            
        # Convert message to base64
        if isinstance(message, str):
            message_b64 = base64.b64encode(message.encode()).decode()
        else:
            message_b64 = base64.b64encode(message).decode()
        
        result = self._make_request(
            'POST',
            '/hybrid/sign',
            {
                'message': message_b64,
                'classical_algorithm': classical_algorithm,
                'pq_algorithm': pq_algorithm
            }
        )
        return HybridSignatureResult(
            classical_signature=result['classical_signature'],
            pq_signature=result['pq_signature'],
            classical_public_key=result['classical_public_key'],
            pq_public_key=result['pq_public_key'],
            combined_signature=result['combined_signature']
        )
    
    # Utility Methods
    
    def hash_message(self, message: Union[str, bytes], algorithm: str = "sha256") -> str:
        """
        Hash a message for signing (utility method)
        
        Args:
            message: Message to hash
            algorithm: Hash algorithm (sha256, sha384, sha512)
            
        Returns:
            Base64-encoded hash
        """
        if isinstance(message, str):
            message = message.encode()
        
        if algorithm == "sha256":
            hash_obj = hashlib.sha256(message)
        elif algorithm == "sha384":
            hash_obj = hashlib.sha384(message)
        elif algorithm == "sha512":
            hash_obj = hashlib.sha512(message)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        return base64.b64encode(hash_obj.digest()).decode()
    
    def get_algorithm_info(self, algorithm: Union[Algorithm, str]) -> Dict:
        """
        Get information about a specific algorithm
        
        Args:
            algorithm: Algorithm to get info for
            
        Returns:
            Dictionary with algorithm information
        """
        if isinstance(algorithm, Algorithm):
            algorithm = algorithm.value
        
        # Algorithm information lookup
        algorithm_info = {
            "kyber512": {
                "type": "KEM",
                "security_level": 1,
                "public_key_size": 800,
                "private_key_size": 1632,
                "ciphertext_size": 768,
                "shared_secret_size": 32
            },
            "kyber768": {
                "type": "KEM", 
                "security_level": 3,
                "public_key_size": 1184,
                "private_key_size": 2400,
                "ciphertext_size": 1088,
                "shared_secret_size": 32
            },
            "kyber1024": {
                "type": "KEM",
                "security_level": 5,
                "public_key_size": 1568,
                "private_key_size": 3168,
                "ciphertext_size": 1568,
                "shared_secret_size": 32
            },
            "dilithium2": {
                "type": "Signature",
                "security_level": 2,
                "public_key_size": 1312,
                "private_key_size": 2528,
                "signature_size": 2420
            },
            "dilithium3": {
                "type": "Signature",
                "security_level": 3,
                "public_key_size": 1952,
                "private_key_size": 4000,
                "signature_size": 3293
            },
            "dilithium5": {
                "type": "Signature",
                "security_level": 5,
                "public_key_size": 2592,
                "private_key_size": 4864,
                "signature_size": 4595
            },
            "falcon512": {
                "type": "Signature",
                "security_level": 1,
                "public_key_size": 897,
                "private_key_size": 1281,
                "signature_size": 690
            },
            "falcon1024": {
                "type": "Signature",
                "security_level": 5,
                "public_key_size": 1793,
                "private_key_size": 2305,
                "signature_size": 1330
            }
        }
        
        return algorithm_info.get(algorithm, {"error": "Unknown algorithm"})


# Usage Examples
def example_kem_workflow():
    """Example: Complete KEM workflow"""
    client = CypheronCoreClient("your_api_key_here")
    
    # Generate Bob's key pair
    bob_keys = client.kem_keygen(Algorithm.KYBER_768)
    print(f"Bob's public key: {bob_keys.public_key[:50]}...")
    
    # Alice encapsulates shared secret
    kem_result = client.kem_encapsulate(Algorithm.KYBER_768, bob_keys.public_key)
    print(f"Shared secret: {kem_result.shared_secret[:50]}...")
    print(f"Ciphertext: {kem_result.ciphertext[:50]}...")
    
    # Bob decapsulates shared secret
    bob_secret = client.kem_decapsulate(
        Algorithm.KYBER_768, 
        bob_keys.private_key, 
        kem_result.ciphertext
    )
    
    # Verify both parties have same secret
    assert kem_result.shared_secret == bob_secret
    print("KEM workflow successful!")


def example_signature_workflow():
    """Example: Complete signature workflow"""
    client = CypheronCoreClient("your_api_key_here")
    
    # Generate signing keys
    keys = client.sig_keygen(Algorithm.DILITHIUM_3)
    print(f"Signing keys generated: {keys.public_key[:50]}...")
    
    # Sign a message
    message = "This is an important document that needs to be signed."
    signature = client.sign_message(Algorithm.DILITHIUM_3, keys.private_key, message)
    print(f"Message signed: {signature.signature[:50]}...")
    
    # Verify signature
    verification = client.verify_signature(
        Algorithm.DILITHIUM_3,
        keys.public_key,
        message,
        signature.signature
    )
    
    print(f"Signature verification: {verification.valid}")


def example_hybrid_workflow():
    """Example: Hybrid cryptography workflow"""
    client = CypheronCoreClient("your_api_key_here")
    
    message = "Critical document requiring hybrid signatures for migration period."
    
    # Create hybrid signature
    hybrid_sig = client.hybrid_sign(
        message,
        classical_algorithm="ed25519",
        pq_algorithm=Algorithm.DILITHIUM_3
    )
    
    print("Hybrid signature created")
    print(f"Classical signature: {hybrid_sig.classical_signature[:50]}...")
    print(f"PQ signature: {hybrid_sig.pq_signature[:50]}...")
    print(f"Combined signature: {hybrid_sig.combined_signature[:50]}...")


if __name__ == "__main__":
    # Run examples (replace with your actual API key)
    example_kem_workflow()
    example_signature_workflow()
    example_hybrid_workflow()
```

### Installation

```bash
pip install requests
```

### Usage

```python
from cypheron_core_client import CypheronCoreClient, Algorithm

# Initialize client
client = CypheronCoreClient("your_api_key_here")

# Generate KEM keys
keys = client.kem_keygen(Algorithm.KYBER_768)

# Sign a message
signature = client.sign_message(
    Algorithm.DILITHIUM_3, 
    private_key, 
    "Hello, Post-Quantum World!"
)
```

## JavaScript/Node.js Client Library

### Complete Implementation

```javascript
/**
 * Cypheron-Core JavaScript Client Library
 * A complete client for interacting with the Cypheron-Core post-quantum cryptography API.
 */

const axios = require('axios');

class CypheronCoreError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CypheronCoreError';
    }
}

class AuthenticationError extends CypheronCoreError {
    constructor(message) {
        super(message);
        this.name = 'AuthenticationError';
    }
}

class ValidationError extends CypheronCoreError {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

class RateLimitError extends CypheronCoreError {
    constructor(message, retryAfter = null) {
        super(message);
        this.name = 'RateLimitError';
        this.retryAfter = retryAfter;
    }
}

const Algorithm = {
    // KEM algorithms
    KYBER_512: 'kyber512',
    KYBER_768: 'kyber768',
    KYBER_1024: 'kyber1024',
    
    // Signature algorithms
    DILITHIUM_2: 'dilithium2',
    DILITHIUM_3: 'dilithium3',
    DILITHIUM_5: 'dilithium5',
    FALCON_512: 'falcon512',
    FALCON_1024: 'falcon1024',
    SPHINCS_HARAKA_128F: 'sphincs_haraka_128f',
    SPHINCS_HARAKA_128S: 'sphincs_haraka_128s',
    SPHINCS_HARAKA_192F: 'sphincs_haraka_192f',
    SPHINCS_HARAKA_192S: 'sphincs_haraka_192s',
    SPHINCS_HARAKA_256F: 'sphincs_haraka_256f',
    SPHINCS_HARAKA_256S: 'sphincs_haraka_256s'
};

class CypheronCoreClient {
    /**
     * Initialize the Cypheron-Core client
     * 
     * @param {string} apiKey - Your Cypheron-Core API key
     * @param {string} baseUrl - Base URL of the Cypheron-Core API
     * @param {number} timeout - Request timeout in milliseconds
     * @param {number} maxRetries - Maximum number of retries for failed requests
     */
    constructor(apiKey, baseUrl = 'https://api.cypheronlabs.com', timeout = 30000, maxRetries = 3) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.timeout = timeout;
        this.maxRetries = maxRetries;
        
        this.axiosInstance = axios.create({
            baseURL: this.baseUrl,
            timeout: this.timeout,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json',
                'User-Agent': 'cypheron-core-js-client/1.0.0'
            }
        });
        
        this._setupInterceptors();
    }
    
    _setupInterceptors() {
        // Response interceptor for error handling
        this.axiosInstance.interceptors.response.use(
            response => response,
            async error => {
                const { response, config } = error;
                
                if (!response) {
                    throw new CypheronCoreError(`Network error: ${error.message}`);
                }
                
                switch (response.status) {
                    case 401:
                        throw new AuthenticationError('Invalid API key');
                    
                    case 400:
                        const errorData = response.data;
                        throw new ValidationError(`Validation error: ${errorData.message || 'Unknown error'}`);
                    
                    case 429:
                        const retryAfter = parseInt(response.headers['retry-after']) || 60;
                        
                        // Retry if we haven't exceeded max retries
                        if (!config._retryCount) config._retryCount = 0;
                        if (config._retryCount < this.maxRetries) {
                            config._retryCount++;
                            await this._sleep(Math.min(retryAfter * 1000, 60000));
                            return this.axiosInstance(config);
                        }
                        
                        throw new RateLimitError('Rate limit exceeded', retryAfter);
                    
                    default:
                        throw new PQCoreError(`HTTP ${response.status}: ${response.statusText}`);
                }
            }
        );
    }
    
    async _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    async _makeRequest(method, endpoint, data = null) {
        try {
            const response = await this.axiosInstance({
                method,
                url: endpoint,
                data
            });
            return response.data;
        } catch (error) {
            // Error handling is done in interceptors
            throw error;
        }
    }
    
    // KEM Operations
    
    /**
     * Generate a KEM key pair
     * 
     * @param {string} algorithm - KEM algorithm to use
     * @returns {Object} KeyPair object containing public and private keys
     */
    async kemKeygen(algorithm) {
        const result = await this._makeRequest('POST', `/kem/${algorithm}/keygen`);
        return {
            publicKey: result.pk,
            privateKey: result.sk,
            algorithm: algorithm
        };
    }
    
    /**
     * Encapsulate a shared secret using KEM
     * 
     * @param {string} algorithm - KEM algorithm to use
     * @param {string} publicKey - Base64-encoded public key
     * @returns {Object} KEMResult containing shared secret and ciphertext
     */
    async kemEncapsulate(algorithm, publicKey) {
        const result = await this._makeRequest('POST', `/kem/${algorithm}/encapsulate`, {
            public_key: publicKey
        });
        return {
            sharedSecret: result.shared_secret,
            ciphertext: result.ciphertext
        };
    }
    
    /**
     * Decapsulate a shared secret using KEM
     * 
     * @param {string} algorithm - KEM algorithm to use
     * @param {string} privateKey - Base64-encoded private key
     * @param {string} ciphertext - Base64-encoded ciphertext
     * @returns {string} Base64-encoded shared secret
     */
    async kemDecapsulate(algorithm, privateKey, ciphertext) {
        const result = await this._makeRequest('POST', `/kem/${algorithm}/decapsulate`, {
            private_key: privateKey,
            ciphertext: ciphertext
        });
        return result.shared_secret;
    }
    
    // Digital Signature Operations
    
    /**
     * Generate a signature key pair
     * 
     * @param {string} algorithm - Signature algorithm to use
     * @returns {Object} KeyPair object containing public and private keys
     */
    async sigKeygen(algorithm) {
        const result = await this._makeRequest('POST', `/sig/${algorithm}/keygen`);
        return {
            publicKey: result.pk,
            privateKey: result.sk,
            algorithm: algorithm
        };
    }
    
    /**
     * Sign a message
     * 
     * @param {string} algorithm - Signature algorithm to use
     * @param {string} privateKey - Base64-encoded private key
     * @param {string|Buffer} message - Message to sign
     * @returns {Object} SignatureResult containing the signature
     */
    async signMessage(algorithm, privateKey, message) {
        // Convert message to base64
        let messageB64;
        if (typeof message === 'string') {
            messageB64 = Buffer.from(message).toString('base64');
        } else {
            messageB64 = message.toString('base64');
        }
        
        const result = await this._makeRequest('POST', `/sig/${algorithm}/sign`, {
            private_key: privateKey,
            message: messageB64
        });
        
        return {
            signature: result.signature,
            algorithm: result.algorithm
        };
    }
    
    /**
     * Verify a digital signature
     * 
     * @param {string} algorithm - Signature algorithm to use
     * @param {string} publicKey - Base64-encoded public key
     * @param {string|Buffer} message - Original message
     * @param {string} signature - Base64-encoded signature
     * @returns {Object} VerificationResult indicating if signature is valid
     */
    async verifySignature(algorithm, publicKey, message, signature) {
        // Convert message to base64
        let messageB64;
        if (typeof message === 'string') {
            messageB64 = Buffer.from(message).toString('base64');
        } else {
            messageB64 = message.toString('base64');
        }
        
        const result = await this._makeRequest('POST', `/sig/${algorithm}/verify`, {
            public_key: publicKey,
            message: messageB64,
            signature: signature
        });
        
        return {
            valid: result.valid,
            algorithm: result.algorithm
        };
    }
    
    // Hybrid Cryptography Operations
    
    /**
     * Create a hybrid signature (classical + post-quantum)
     * 
     * @param {string|Buffer} message - Message to sign
     * @param {string} classicalAlgorithm - Classical signature algorithm
     * @param {string} pqAlgorithm - Post-quantum signature algorithm
     * @returns {Object} HybridSignatureResult containing both signatures
     */
    async hybridSign(message, classicalAlgorithm = 'ed25519', pqAlgorithm = Algorithm.DILITHIUM_3) {
        // Convert message to base64
        let messageB64;
        if (typeof message === 'string') {
            messageB64 = Buffer.from(message).toString('base64');
        } else {
            messageB64 = message.toString('base64');
        }
        
        const result = await this._makeRequest('POST', '/hybrid/sign', {
            message: messageB64,
            classical_algorithm: classicalAlgorithm,
            pq_algorithm: pqAlgorithm
        });
        
        return {
            classicalSignature: result.classical_signature,
            pqSignature: result.pq_signature,
            classicalPublicKey: result.classical_public_key,
            pqPublicKey: result.pq_public_key,
            combinedSignature: result.combined_signature
        };
    }
    
    // Utility Methods
    
    /**
     * Get information about a specific algorithm
     * 
     * @param {string} algorithm - Algorithm to get info for
     * @returns {Object} Dictionary with algorithm information
     */
    getAlgorithmInfo(algorithm) {
        const algorithmInfo = {
            [Algorithm.KYBER_512]: {
                type: 'KEM',
                securityLevel: 1,
                publicKeySize: 800,
                privateKeySize: 1632,
                ciphertextSize: 768,
                sharedSecretSize: 32
            },
            [Algorithm.KYBER_768]: {
                type: 'KEM',
                securityLevel: 3,
                publicKeySize: 1184,
                privateKeySize: 2400,
                ciphertextSize: 1088,
                sharedSecretSize: 32
            },
            [Algorithm.KYBER_1024]: {
                type: 'KEM',
                securityLevel: 5,
                publicKeySize: 1568,
                privateKeySize: 3168,
                ciphertextSize: 1568,
                sharedSecretSize: 32
            },
            [Algorithm.DILITHIUM_2]: {
                type: 'Signature',
                securityLevel: 2,
                publicKeySize: 1312,
                privateKeySize: 2528,
                signatureSize: 2420
            },
            [Algorithm.DILITHIUM_3]: {
                type: 'Signature',
                securityLevel: 3,
                publicKeySize: 1952,
                privateKeySize: 4000,
                signatureSize: 3293
            },
            [Algorithm.DILITHIUM_5]: {
                type: 'Signature',
                securityLevel: 5,
                publicKeySize: 2592,
                privateKeySize: 4864,
                signatureSize: 4595
            },
            [Algorithm.FALCON_512]: {
                type: 'Signature',
                securityLevel: 1,
                publicKeySize: 897,
                privateKeySize: 1281,
                signatureSize: 690
            },
            [Algorithm.FALCON_1024]: {
                type: 'Signature',
                securityLevel: 5,
                publicKeySize: 1793,
                privateKeySize: 2305,
                signatureSize: 1330
            }
        };
        
        return algorithmInfo[algorithm] || { error: 'Unknown algorithm' };
    }
}

// Usage Examples

async function exampleKEMWorkflow() {
    const client = new PQCoreClient('your_api_key_here');
    
    try {
        // Generate Bob's key pair
        const bobKeys = await client.kemKeygen(Algorithm.KYBER_768);
        console.log(`Bob's public key: ${bobKeys.publicKey.substring(0, 50)}...`);
        
        // Alice encapsulates shared secret
        const kemResult = await client.kemEncapsulate(Algorithm.KYBER_768, bobKeys.publicKey);
        console.log(`Shared secret: ${kemResult.sharedSecret.substring(0, 50)}...`);
        console.log(`Ciphertext: ${kemResult.ciphertext.substring(0, 50)}...`);
        
        // Bob decapsulates shared secret
        const bobSecret = await client.kemDecapsulate(
            Algorithm.KYBER_768,
            bobKeys.privateKey,
            kemResult.ciphertext
        );
        
        // Verify both parties have same secret
        if (kemResult.sharedSecret === bobSecret) {
            console.log('KEM workflow successful!');
        } else {
            console.log('KEM workflow failed!');
        }
        
    } catch (error) {
        console.error('KEM workflow error:', error.message);
    }
}

async function exampleSignatureWorkflow() {
    const client = new PQCoreClient('your_api_key_here');
    
    try {
        // Generate signing keys
        const keys = await client.sigKeygen(Algorithm.DILITHIUM_3);
        console.log(`Signing keys generated: ${keys.publicKey.substring(0, 50)}...`);
        
        // Sign a message
        const message = 'This is an important document that needs to be signed.';
        const signature = await client.signMessage(Algorithm.DILITHIUM_3, keys.privateKey, message);
        console.log(`Message signed: ${signature.signature.substring(0, 50)}...`);
        
        // Verify signature
        const verification = await client.verifySignature(
            Algorithm.DILITHIUM_3,
            keys.publicKey,
            message,
            signature.signature
        );
        
        console.log(`Signature verification: ${verification.valid}`);
        
    } catch (error) {
        console.error('Signature workflow error:', error.message);
    }
}

async function exampleHybridWorkflow() {
    const client = new PQCoreClient('your_api_key_here');
    
    try {
        const message = 'Critical document requiring hybrid signatures for migration period.';
        
        // Create hybrid signature
        const hybridSig = await client.hybridSign(
            message,
            'ed25519',
            Algorithm.DILITHIUM_3
        );
        
        console.log('Hybrid signature created');
        console.log(`Classical signature: ${hybridSig.classicalSignature.substring(0, 50)}...`);
        console.log(`PQ signature: ${hybridSig.pqSignature.substring(0, 50)}...`);
        console.log(`Combined signature: ${hybridSig.combinedSignature.substring(0, 50)}...`);
        
    } catch (error) {
        console.error('Hybrid workflow error:', error.message);
    }
}

// Export for use in other modules
module.exports = {
    PQCoreClient,
    Algorithm,
    PQCoreError,
    AuthenticationError,
    ValidationError,
    RateLimitError
};

// Run examples if this file is executed directly
if (require.main === module) {
    (async () => {
        await exampleKEMWorkflow();
        await exampleSignatureWorkflow();
        await exampleHybridWorkflow();
    })();
}
```

### Installation

```bash
npm install axios
```

### Usage

```javascript
const { PQCoreClient, Algorithm } = require('./cypheron-core-client');

// Initialize client
const client = new PQCoreClient('your_api_key_here');

// Generate KEM keys
const keys = await client.kemKeygen(Algorithm.KYBER_768);

// Sign a message
const signature = await client.signMessage(
    Algorithm.DILITHIUM_3,
    privateKey,
    'Hello, Post-Quantum World!'
);
```

## Go Client Library

### Basic Implementation

```go
package pqcore

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "time"
)

type Algorithm string

const (
    // KEM algorithms
    Kyber512  Algorithm = "kyber512"
    Kyber768  Algorithm = "kyber768"
    Kyber1024 Algorithm = "kyber1024"
    
    // Signature algorithms
    Dilithium2 Algorithm = "dilithium2"
    Dilithium3 Algorithm = "dilithium3"
    Dilithium5 Algorithm = "dilithium5"
    Falcon512  Algorithm = "falcon512"
    Falcon1024 Algorithm = "falcon1024"
)

type Client struct {
    APIKey     string
    BaseURL    string
    HTTPClient *http.Client
}

type KeyPair struct {
    PublicKey  string `json:"pk"`
    PrivateKey string `json:"sk"`
    Algorithm  string
}

type KEMResult struct {
    SharedSecret string `json:"shared_secret"`
    Ciphertext   string `json:"ciphertext"`
}

type SignatureResult struct {
    Signature string `json:"signature"`
    Algorithm string `json:"algorithm"`
}

type VerificationResult struct {
    Valid     bool   `json:"valid"`
    Algorithm string `json:"algorithm"`
}

func NewClient(apiKey, baseURL string) *Client {
    return &Client{
        APIKey:  apiKey,
        BaseURL: baseURL,
        HTTPClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *Client) makeRequest(method, endpoint string, payload interface{}) ([]byte, error) {
    var body io.Reader
    if payload != nil {
        jsonData, err := json.Marshal(payload)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal payload: %w", err)
        }
        body = bytes.NewBuffer(jsonData)
    }
    
    req, err := http.NewRequest(method, c.BaseURL+endpoint, body)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    req.Header.Set("X-API-Key", c.APIKey)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "cypheron-core-go-client/1.0.0")
    
    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    responseBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(responseBody))
    }
    
    return responseBody, nil
}

// KEMKeygen generates a KEM key pair
func (c *Client) KEMKeygen(algorithm Algorithm) (*KeyPair, error) {
    endpoint := fmt.Sprintf("/kem/%s/keygen", string(algorithm))
    
    responseBody, err := c.makeRequest("POST", endpoint, nil)
    if err != nil {
        return nil, err
    }
    
    var keyPair KeyPair
    if err := json.Unmarshal(responseBody, &keyPair); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    keyPair.Algorithm = string(algorithm)
    return &keyPair, nil
}

// KEMEncapsulate performs KEM encapsulation
func (c *Client) KEMEncapsulate(algorithm Algorithm, publicKey string) (*KEMResult, error) {
    endpoint := fmt.Sprintf("/kem/%s/encapsulate", string(algorithm))
    payload := map[string]string{"public_key": publicKey}
    
    responseBody, err := c.makeRequest("POST", endpoint, payload)
    if err != nil {
        return nil, err
    }
    
    var result KEMResult
    if err := json.Unmarshal(responseBody, &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    return &result, nil
}

// KEMDecapsulate performs KEM decapsulation
func (c *Client) KEMDecapsulate(algorithm Algorithm, privateKey, ciphertext string) (string, error) {
    endpoint := fmt.Sprintf("/kem/%s/decapsulate", string(algorithm))
    payload := map[string]string{
        "private_key": privateKey,
        "ciphertext":  ciphertext,
    }
    
    responseBody, err := c.makeRequest("POST", endpoint, payload)
    if err != nil {
        return "", err
    }
    
    var result struct {
        SharedSecret string `json:"shared_secret"`
    }
    if err := json.Unmarshal(responseBody, &result); err != nil {
        return "", fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    return result.SharedSecret, nil
}

// SigKeygen generates a signature key pair
func (c *Client) SigKeygen(algorithm Algorithm) (*KeyPair, error) {
    endpoint := fmt.Sprintf("/sig/%s/keygen", string(algorithm))
    
    responseBody, err := c.makeRequest("POST", endpoint, nil)
    if err != nil {
        return nil, err
    }
    
    var keyPair KeyPair
    if err := json.Unmarshal(responseBody, &keyPair); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    keyPair.Algorithm = string(algorithm)
    return &keyPair, nil
}

// SignMessage signs a message
func (c *Client) SignMessage(algorithm Algorithm, privateKey string, message []byte) (*SignatureResult, error) {
    endpoint := fmt.Sprintf("/sig/%s/sign", string(algorithm))
    messageB64 := base64.StdEncoding.EncodeToString(message)
    payload := map[string]string{
        "private_key": privateKey,
        "message":     messageB64,
    }
    
    responseBody, err := c.makeRequest("POST", endpoint, payload)
    if err != nil {
        return nil, err
    }
    
    var result SignatureResult
    if err := json.Unmarshal(responseBody, &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    return &result, nil
}

// VerifySignature verifies a digital signature
func (c *Client) VerifySignature(algorithm Algorithm, publicKey string, message []byte, signature string) (*VerificationResult, error) {
    endpoint := fmt.Sprintf("/sig/%s/verify", string(algorithm))
    messageB64 := base64.StdEncoding.EncodeToString(message)
    payload := map[string]string{
        "public_key": publicKey,
        "message":    messageB64,
        "signature":  signature,
    }
    
    responseBody, err := c.makeRequest("POST", endpoint, payload)
    if err != nil {
        return nil, err
    }
    
    var result VerificationResult
    if err := json.Unmarshal(responseBody, &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %w", err)
    }
    
    return &result, nil
}
```

### Usage

```go
package main

import (
    "fmt"
    "log"
)

func main() {
    client := pqcore.NewClient("your_api_key_here", "https://api.cypheronlabs.com")
    
    // Generate KEM keys
    keys, err := client.KEMKeygen(pqcore.Kyber768)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Generated KEM keys: %s...\n", keys.PublicKey[:50])
    
    // Sign a message
    message := []byte("Hello, Post-Quantum World!")
    signature, err := client.SignMessage(pqcore.Dilithium3, privateKey, message)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Message signed: %s...\n", signature.Signature[:50])
}
```

## Language Comparison

| Feature | Python | JavaScript | Go | Java | C# |
|---------|--------|------------|----|----- |----|
| **Ease of Use** | Excellent | Excellent | Good | Fair | Fair |
| **Performance** | Fair | Fair | Excellent | Good | Good |
| **Type Safety** | Basic | Basic | Excellent | Excellent | Excellent |
| **Community** | Excellent | Excellent | Good | Good | Fair |
| **Documentation** | Excellent | Excellent | Good | Planned | Planned |

## Next Steps

- **Integration Patterns**: Learn [Integration Patterns](integration-patterns.md) for production use
- **API Reference**: Review complete [API Reference](../api-reference/)
- **Security**: Implement [Security Best Practices](../security/best-practices.md)
- **Examples**: See more [Basic Usage Examples](basic-usage.md)

---

*Ready to integrate these clients into your application? Continue to [Integration Patterns](integration-patterns.md) for production deployment strategies.*
