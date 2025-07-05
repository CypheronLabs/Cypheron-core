# Algorithm Selection Guide

Choosing the right post-quantum cryptographic algorithm is crucial for balancing security, performance, and implementation constraints. This guide provides comprehensive recommendations for different use cases and requirements.

## Quick Recommendation Matrix

| Use Case | KEM Algorithm | Signature Algorithm | Rationale |
|----------|---------------|-------------------|-----------|
| **Web Applications** | Kyber-768 | Dilithium-3 | Best balance of security and performance |
| **IoT Devices** | Kyber-512 | Falcon-512 | Smallest keys and signatures |
| **High Security** | Kyber-1024 | Dilithium-5 | Maximum security level |
| **Conservative Choice** | Kyber-768 | SPHINCS+-128f | Hash-based signatures for long-term trust |
| **Hybrid Migration** | Kyber-768 | Dilithium-3 + Ed25519 | Gradual migration path |
| **Real-time Systems** | Kyber-512 | Falcon-512 | Fastest operations |
| **Bandwidth Constrained** | Kyber-512 | Falcon-512 | Smallest data sizes |
| **Government/Military** | Kyber-1024 | Dilithium-5 | Highest standardized security |

## Algorithm Families Overview

### Key Encapsulation Mechanisms (KEMs)

#### Kyber Family (Lattice-Based)

**Mathematical Foundation**: Module Learning With Errors (MLWE)
**Standardization**: NIST FIPS 203 (ML-KEM)
**Security Basis**: Hardness of lattice problems

| Variant | Security Level | Public Key | Private Key | Ciphertext | Shared Secret |
|---------|----------------|------------|-------------|------------|---------------|
| Kyber-512 | NIST Level 1 | 800 B | 1,632 B | 768 B | 32 B |
| Kyber-768 | NIST Level 3 | 1,184 B | 2,400 B | 1,088 B | 32 B |
| Kyber-1024 | NIST Level 5 | 1,568 B | 3,168 B | 1,568 B | 32 B |

**Advantages**:

- Well-studied and trusted by cryptographic community
- Good performance across all security levels
- Reasonable key and ciphertext sizes
- NIST standardized with broad adoption
- Suitable for most applications

**Disadvantages**:

- Larger than classical ECC keys
- Based on relatively new mathematical assumptions
- Some implementation complexity

**Best For**: General-purpose applications, web services, mobile apps

### Digital Signature Algorithms

#### Dilithium Family (Lattice-Based)

**Mathematical Foundation**: Module Learning With Errors (MLWE) and Short Integer Solution (SIS)
**Standardization**: NIST FIPS 204 (ML-DSA)
**Security Basis**: Hardness of lattice problems

| Variant | Security Level | Public Key | Private Key | Signature | Performance |
|---------|----------------|------------|-------------|-----------|-------------|
| Dilithium-2 | NIST Level 2 | 1,312 B | 2,528 B | ~2,420 B | Fast |
| Dilithium-3 | NIST Level 3 | 1,952 B | 4,000 B | ~3,293 B | Medium |
| Dilithium-5 | NIST Level 5 | 2,592 B | 4,864 B | ~4,595 B | Slower |

**Advantages**:

- NIST standardized and widely adopted
- Good performance for signing and verification
- Strong security foundation
- Deterministic signatures available
- No state management required

**Disadvantages**:

- Large signature sizes compared to classical algorithms
- Moderate key sizes
- Some bandwidth overhead

**Best For**: Most signature applications, document signing, authentication

#### Falcon Family (Lattice-Based, Compact)

**Mathematical Foundation**: NTRU lattices and Gaussian sampling
**Standardization**: NIST FN-DSA (additional standard)
**Security Basis**: Short Integer Solution over NTRU lattices

| Variant | Security Level | Public Key | Private Key | Signature | Performance |
|---------|----------------|------------|-------------|-----------|-------------|
| Falcon-512 | NIST Level 1 | 897 B | 1,281 B | ~690 B | Very Fast |
| Falcon-1024 | NIST Level 5 | 1,793 B | 2,305 B | ~1,330 B | Fast |

**Advantages**:

- Smallest signature sizes among standardized algorithms
- Compact public keys
- Very fast verification
- Good for bandwidth-constrained environments
- No state management required

**Disadvantages**:

- Complex implementation (floating-point arithmetic)
- Larger private keys relative to signature size
- More recent standardization

**Best For**: IoT devices, real-time systems, bandwidth-constrained applications

#### SPHINCS+ Family (Hash-Based)

**Mathematical Foundation**: Hash function security
**Standardization**: NIST FIPS 205 (SLH-DSA)
**Security Basis**: Collision and preimage resistance of hash functions

| Variant | Security Level | Public Key | Private Key | Signature | Performance |
|---------|----------------|------------|-------------|-----------|-------------|
| SPHINCS+-128f | 128-bit | 32 B | 64 B | ~17,088 B | Slow |
| SPHINCS+-128s | 128-bit | 32 B | 64 B | ~7,856 B | Very Slow |
| SPHINCS+-192f | 192-bit | 48 B | 96 B | ~35,664 B | Slow |
| SPHINCS+-256f | 256-bit | 64 B | 128 B | ~49,856 B | Slow |

*f = fast variant, s = small variant*

**Advantages**:

- Very conservative security assumptions (hash functions)
- Tiny key sizes
- No quantum algorithm threatens hash functions
- Simple to understand and implement correctly
- Long-term confidence in security

**Disadvantages**:

- Very large signature sizes
- Slow signing and verification
- High bandwidth requirements
- Not suitable for real-time applications

**Best For**: Long-term archival, high-value signatures, conservative deployments

## Security Level Analysis

### NIST Security Levels

NIST defines security levels based on the computational effort required to break them:

| Level | Classical Security | Quantum Security | Equivalent Classical |
|-------|-------------------|------------------|---------------------|
| 1 | 2^143 operations | 2^85 operations | AES-128 |
| 2 | 2^207 operations | 2^104 operations | SHA-256 collision |
| 3 | 2^272 operations | 2^136 operations | AES-192 |
| 5 | 2^384 operations | 2^192 operations | AES-256 |

*Note: Level 4 was not defined in the original NIST framework*

### Security Considerations by Level

**Level 1 (Kyber-512, Falcon-512)**:

- **Use Cases**: IoT, embedded systems, non-critical applications
- **Timeline**: Secure against current and near-term quantum computers
- **Risk**: May be vulnerable to advanced quantum computers (2030s+)
- **Recommendation**: Only for applications with short data lifetime

**Level 3 (Kyber-768, Dilithium-3)**:

- **Use Cases**: Most web applications, mobile apps, general enterprise use
- **Timeline**: Secure against quantum computers for decades
- **Risk**: Conservative choice for most applications
- **Recommendation**: Default choice for new deployments

**Level 5 (Kyber-1024, Dilithium-5, Falcon-1024)**:

- **Use Cases**: Government, military, financial institutions, long-term secrets
- **Timeline**: Secure against quantum computers for 50+ years
- **Risk**: Very low risk, maximum standardized security
- **Recommendation**: When security is paramount and performance is secondary

## Performance Characteristics

### Benchmarks (Typical Hardware)

**Key Generation Performance** (operations per second):

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Kyber | 10,000/s | 7,000/s | 5,000/s |
| Dilithium | 8,000/s | 5,000/s | 3,000/s |
| Falcon | 15,000/s | - | 8,000/s |
| SPHINCS+ | 200/s | 100/s | 50/s |

**Signing Performance** (operations per second):

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Dilithium | 5,000/s | 3,000/s | 2,000/s |
| Falcon | 20,000/s | - | 10,000/s |
| SPHINCS+ | 50/s | 25/s | 15/s |

**Verification Performance** (operations per second):

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Dilithium | 15,000/s | 10,000/s | 7,000/s |
| Falcon | 25,000/s | - | 15,000/s |
| SPHINCS+ | 100/s | 50/s | 30/s |

### Memory Usage

**Peak Memory Requirements**:

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Kyber | ~4 KB | ~6 KB | ~8 KB |
| Dilithium | ~8 KB | ~12 KB | ~16 KB |
| Falcon | ~20 KB | - | ~40 KB |
| SPHINCS+ | ~2 KB | ~3 KB | ~4 KB |

## Use Case Specific Recommendations

### Web Applications

**Recommended Configuration**:

- **KEM**: Kyber-768
- **Signatures**: Dilithium-3
- **Hybrid**: Dilithium-3 + Ed25519

**Rationale**:

- Excellent security-performance balance
- Reasonable bandwidth requirements
- Wide compatibility and support
- Good for TLS integration

**Implementation Considerations**:
```python
# Web application configuration
CRYPTO_CONFIG = {
    "kem_algorithm": "kyber768",
    "signature_algorithm": "dilithium3",
    "hybrid_classical": "ed25519",
    "security_level": 3
}
```

### Mobile Applications

**Recommended Configuration**:

- **KEM**: Kyber-768
- **Signatures**: Falcon-512 or Dilithium-2
- **Considerations**: Battery life, bandwidth costs

**Rationale**:

- Balance between security and resource consumption
- Falcon-512 for bandwidth-sensitive applications
- Dilithium-2 for better compatibility

**Implementation Example**:
```python
# Mobile-optimized configuration
if battery_level > 50 and wifi_connected:
    algorithm = "dilithium3"  # Higher security
else:
    algorithm = "falcon512"   # Lower resource usage
```

### IoT and Embedded Systems

**Recommended Configuration**:

- **KEM**: Kyber-512
- **Signatures**: Falcon-512
- **Constraints**: Memory, processing power, battery

**Rationale**:

- Minimal resource requirements
- Fast operations for real-time constraints
- Smallest key and signature sizes

**Implementation Considerations**:
```c
// Embedded system configuration
#define KEM_ALGORITHM "kyber512"
#define SIG_ALGORITHM "falcon512" 
#define MAX_SIGNATURE_SIZE 1024
#define MAX_PUBLIC_KEY_SIZE 1024
```

### High-Security Applications

**Recommended Configuration**:

- **KEM**: Kyber-1024
- **Signatures**: Dilithium-5 or SPHINCS+-256f
- **Additional**: Hardware security modules (HSMs)

**Rationale**:

- Maximum standardized security level
- Conservative cryptographic assumptions
- Long-term protection requirements

**Implementation Strategy**:
```python
# High-security configuration
SECURITY_CONFIG = {
    "kem_algorithm": "kyber1024",
    "signature_algorithm": "dilithium5",
    "backup_signature": "sphincs_haraka_256f",
    "key_storage": "hsm",
    "key_rotation_days": 30
}
```

### Financial Services

**Recommended Configuration**:

- **KEM**: Kyber-768 or Kyber-1024
- **Signatures**: Dilithium-3 + ECDSA (hybrid)
- **Requirements**: Regulatory compliance, audit trails

**Rationale**:

- Regulatory acceptance of hybrid approaches
- Strong audit and compliance requirements
- Balance security with transaction speed

**Compliance Considerations**:
```python
# Financial services configuration
FINTECH_CONFIG = {
    "primary_signature": "dilithium3",
    "backup_signature": "ecdsa_p256",
    "audit_logging": True,
    "regulatory_compliance": ["FIPS_140_2", "Common_Criteria"],
    "key_escrow": True
}
```

### Long-Term Archival

**Recommended Configuration**:

- **Signatures**: SPHINCS+-256f or SPHINCS+-192f
- **Storage**: Redundant signature verification
- **Timeline**: 50+ year protection

**Rationale**:

- Most conservative security assumptions
- Long-term confidence in hash functions
- Multiple signature verification for redundancy

**Archival Strategy**:
```python
# Long-term archival configuration
ARCHIVAL_CONFIG = {
    "primary_signature": "sphincs_haraka_256f",
    "secondary_signature": "dilithium5", 
    "verification_redundancy": 3,
    "hash_algorithm": "sha3_256",
    "timestamp_authority": True
}
```

## Migration Strategies

### Hybrid Deployment

**Phase 1: Hybrid Introduction**
```
Classical + Post-Quantum
├── ECDSA + Dilithium
├── ECDH + Kyber  
└── Verify both signatures
```

**Phase 2: PQ Preference**
```
Post-Quantum Primary
├── Dilithium (primary)
├── ECDSA (backup)
└── Prefer PQ verification
```

**Phase 3: PQ Only**
```
Post-Quantum Only
├── Dilithium
├── Kyber
└── Classical deprecated
```

### Algorithm Transition Planning

**Timeline Considerations**:

- **2024-2026**: Hybrid deployment phase
- **2026-2030**: Gradual PQ preference
- **2030+**: Post-quantum only

**Technical Debt Management**:
```python
# Algorithm transition framework
class CryptoProvider:
    def __init__(self):
        self.current_algorithms = ["ecdsa", "dilithium3"]
        self.deprecated_algorithms = ["rsa"]
        self.transition_date = "2026-01-01"
    
    def get_signature_algorithm(self, security_requirement):
        if datetime.now() > self.transition_date:
            return "dilithium3"  # PQ only
        else:
            return ["ecdsa", "dilithium3"]  # Hybrid
```

## Performance Optimization

### Algorithm Tuning

**Kyber Optimization**:
```python
# Kyber performance tuning
kyber_config = {
    "security_level": 3,  # Kyber-768
    "ntt_optimization": True,
    "memory_pool": True,
    "batch_operations": 8
}
```

**Dilithium Optimization**:
```python
# Dilithium performance tuning  
dilithium_config = {
    "security_level": 3,  # Dilithium-3
    "deterministic": False,  # Faster random signatures
    "batch_verification": True,
    "precompute_tables": True
}
```

**Falcon Optimization**:
```python
# Falcon performance tuning
falcon_config = {
    "security_level": 1,  # Falcon-512
    "fast_verification": True,
    "precompute_trees": True,
    "constant_time": True
}
```

### Caching Strategies

**Key Pair Caching**:
```python
# Cache frequently used key pairs
key_cache = {
    "dilithium3": LRUCache(maxsize=100),
    "kyber768": LRUCache(maxsize=100),
    "falcon512": LRUCache(maxsize=50)
}

def get_cached_keypair(algorithm, identifier):
    cache = key_cache[algorithm]
    if identifier not in cache:
        cache[identifier] = generate_keypair(algorithm)
    return cache[identifier]
```

**Signature Verification Caching**:
```python
# Cache signature verification results
verification_cache = TTLCache(maxsize=1000, ttl=300)

def cached_verify(message, signature, public_key, algorithm):
    cache_key = hashlib.sha256(
        message + signature + public_key + algorithm.encode()
    ).hexdigest()
    
    if cache_key in verification_cache:
        return verification_cache[cache_key]
    
    result = verify_signature(message, signature, public_key, algorithm)
    verification_cache[cache_key] = result
    return result
```

## Testing and Validation

### Algorithm Compatibility Testing

```python
# Cross-algorithm compatibility test
def test_algorithm_interoperability():
    algorithms = ["kyber512", "kyber768", "kyber1024"]
    
    for alg in algorithms:
        # Generate test vectors
        keys = generate_keypair(alg)
        
        # Test encapsulation/decapsulation
        result = test_kem_roundtrip(alg, keys)
        assert result.success
        
        # Test with different implementations
        test_cross_implementation(alg, keys)
```

### Performance Benchmarking

```python
# Performance benchmarking suite
def benchmark_algorithms():
    algorithms = {
        "kyber512": {"type": "kem", "level": 1},
        "kyber768": {"type": "kem", "level": 3},
        "dilithium2": {"type": "sig", "level": 2},
        "dilithium3": {"type": "sig", "level": 3},
        "falcon512": {"type": "sig", "level": 1}
    }
    
    results = {}
    for alg, config in algorithms.items():
        results[alg] = {
            "keygen_ops_per_sec": benchmark_keygen(alg),
            "operation_ops_per_sec": benchmark_operation(alg, config["type"]),
            "memory_usage_kb": measure_memory_usage(alg),
            "key_sizes": get_key_sizes(alg)
        }
    
    return results
```

## Decision Framework

### Selection Criteria Weights

```python
# Algorithm selection scoring system
def score_algorithm(algorithm, requirements):
    weights = {
        "security": requirements.get("security_weight", 0.3),
        "performance": requirements.get("performance_weight", 0.25),
        "size": requirements.get("size_weight", 0.2),
        "compatibility": requirements.get("compatibility_weight", 0.15),
        "maturity": requirements.get("maturity_weight", 0.1)
    }
    
    scores = get_algorithm_scores(algorithm)
    total_score = sum(scores[criteria] * weight 
                     for criteria, weight in weights.items())
    
    return total_score

# Example usage
requirements = {
    "security_weight": 0.4,    # High security requirement
    "performance_weight": 0.2,  # Moderate performance requirement
    "size_weight": 0.3,        # Important size constraint
    "compatibility_weight": 0.1 # Low compatibility requirement
}

best_algorithm = max(
    ["kyber512", "kyber768", "kyber1024"],
    key=lambda alg: score_algorithm(alg, requirements)
)
```

## Next Steps

- **Performance Guide**: Learn about [Performance Optimization](performance.md)
- **Deployment**: Review [Production Deployment](deployment.md) considerations
- **Security**: Understand [Security Best Practices](../security/best-practices.md)
- **Monitoring**: Set up [Monitoring & Observability](monitoring.md)

---

*Ready to optimize your algorithm choice? Continue to [Performance Optimization](performance.md) for detailed tuning strategies.*