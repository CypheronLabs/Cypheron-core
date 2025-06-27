# Introduction to Post-Quantum Cryptography

## What is Post-Quantum Cryptography?

Post-quantum cryptography (PQC) refers to cryptographic algorithms that are designed to be secure against both classical and quantum computer attacks. Unlike current public-key cryptographic systems (RSA, ECDSA, ECDH), post-quantum algorithms are based on mathematical problems that are believed to be hard for both classical and quantum computers to solve.

## The Quantum Threat

### Why Current Cryptography is Vulnerable

Most of today's public-key cryptography relies on mathematical problems that are easy to compute in one direction but hard to reverse:

- **RSA**: Based on the difficulty of factoring large integers
- **ECDSA/ECDH**: Based on the discrete logarithm problem over elliptic curves

### Quantum Computing Impact

Quantum computers pose a fundamental threat to these systems because:

1. **Shor's Algorithm (1994)**: Can efficiently factor integers and solve discrete logarithms
2. **Grover's Algorithm (1996)**: Provides quadratic speedup for searching, affecting symmetric cryptography
3. **Timeline**: NIST estimates cryptographically relevant quantum computers could emerge in the 2030s

### Real-World Implications

When cryptographically relevant quantum computers become available:
- **RSA-2048 keys**: Could be broken in hours instead of millions of years
- **ECDSA P-256**: Would provide no security
- **Current TLS/SSL**: Would be completely compromised
- **Bitcoin/Blockchain**: Current signature schemes would be vulnerable

## Post-Quantum Algorithm Families

### 1. Lattice-Based Cryptography

**Mathematical Foundation**: Based on problems in high-dimensional lattices, such as Learning With Errors (LWE) and Ring-LWE.

**Examples in PQ-Core**:
- **Kyber** (KEM): Key encapsulation mechanism
- **Dilithium** (Signatures): Digital signature algorithm

**Advantages**:
- Well-studied mathematical foundation
- Efficient implementations possible
- Versatile (supports both KEMs and signatures)

**Trade-offs**:
- Larger key sizes than classical algorithms
- Some parameter choices still being optimized

### 2. Hash-Based Cryptography

**Mathematical Foundation**: Security based on the collision resistance of cryptographic hash functions.

**Examples in PQ-Core**:
- **SPHINCS+**: Stateless hash-based signatures

**Advantages**:
- Very conservative security assumptions
- Well-understood security proofs
- Quantum-safe hash functions are straightforward

**Trade-offs**:
- Large signature sizes
- Slower signing compared to other PQ algorithms

### 3. Code-Based Cryptography

**Mathematical Foundation**: Based on error-correcting codes and the difficulty of decoding random linear codes.

**Status**: Not included in current NIST standards but actively researched.

### 4. Multivariate Cryptography

**Mathematical Foundation**: Based on solving systems of multivariate polynomial equations over finite fields.

**Status**: Some schemes broken, others still under evaluation.

### 5. Isogeny-Based Cryptography

**Mathematical Foundation**: Based on walks in supersingular isogeny graphs.

**Status**: SIKE was broken in 2022, but research continues on other approaches.

## NIST Standardization Process

### Timeline
- **2016**: NIST announced PQC standardization project
- **2017-2019**: First round evaluation (69 submissions)
- **2019-2021**: Second round (26 candidates)
- **2021-2022**: Third round (7 finalists + 8 alternates)
- **2022**: First standards published
- **2024**: Additional standards published

### Current NIST Standards

**Primary Standards (FIPS 203, 204, 205)**:
- **ML-KEM** (Kyber): Key encapsulation mechanism
- **ML-DSA** (Dilithium): Digital signature algorithm
- **SLH-DSA** (SPHINCS+): Hash-based digital signatures

**Additional Standards**:
- **FN-DSA** (Falcon): Compact digital signatures

### Security Levels

NIST defines security levels equivalent to classical algorithms:
- **Level 1**: Security equivalent to AES-128 (112-bit security)
- **Level 2**: Security equivalent to SHA-256 (128-bit security)
- **Level 3**: Security equivalent to AES-192 (168-bit security)
- **Level 5**: Security equivalent to AES-256 (224-bit security)

*Note: Level 4 was not defined in the original NIST framework*

## Key Concepts

### Key Encapsulation Mechanisms (KEMs)

**Purpose**: Establish shared secret keys between parties.

**How it works**:
1. **Key Generation**: Create public/private key pair
2. **Encapsulation**: Use public key to encapsulate a shared secret
3. **Decapsulation**: Use private key to recover the shared secret

**Classical Equivalent**: Diffie-Hellman key exchange, ECDH

**PQ-Core Implementation**: Kyber family (Kyber-512, Kyber-768, Kyber-1024)

### Digital Signatures

**Purpose**: Provide authentication, integrity, and non-repudiation.

**How it works**:
1. **Key Generation**: Create signing/verification key pair
2. **Signing**: Use private key to create signature on message
3. **Verification**: Use public key to verify signature

**Classical Equivalent**: RSA signatures, ECDSA

**PQ-Core Implementation**: Dilithium, Falcon, SPHINCS+

### Hybrid Cryptography

**Purpose**: Combine classical and post-quantum algorithms for gradual migration.

**Benefits**:
- **Security**: If either algorithm is broken, the other provides protection
- **Migration**: Allows gradual transition without breaking existing systems
- **Compliance**: Satisfies both current and future cryptographic requirements

**PQ-Core Implementation**: Combines Ed25519/ECDSA with post-quantum signatures

## Security Considerations

### Algorithm Selection Factors

1. **Security Level**: Choose appropriate level based on threat model
2. **Performance**: Consider computational and bandwidth requirements
3. **Key/Signature Sizes**: Balance security with storage/transmission costs
4. **Maturity**: Consider how long the algorithm has been studied
5. **Standardization**: Prefer NIST-standardized algorithms for compliance

### Implementation Security

1. **Side-Channel Resistance**: Protect against timing and power analysis
2. **Constant-Time Operations**: Prevent timing-based attacks
3. **Secure Random Number Generation**: Critical for key generation
4. **Memory Protection**: Securely handle private keys and secrets
5. **API Security**: Implement proper authentication and authorization

### Cryptographic Agility

**Design Principle**: Build systems that can easily upgrade algorithms.

**Benefits**:
- Rapid response to cryptographic breaks
- Seamless migration to new standards
- Support for multiple algorithms simultaneously

**PQ-Core Approach**: API supports multiple algorithms with unified interface

## Migration Strategy

### Phase 1: Hybrid Deployment
- Deploy hybrid algorithms alongside classical ones
- Maintain compatibility with existing systems
- Gain operational experience with PQ algorithms

### Phase 2: Gradual Transition
- Increase reliance on post-quantum algorithms
- Begin deprecating classical algorithms in new deployments
- Update legacy systems where feasible

### Phase 3: Post-Quantum Only
- Complete migration to post-quantum algorithms
- Deprecate classical algorithms in security-critical applications
- Maintain hybrid support for legacy compatibility

## Common Misconceptions

### "Post-quantum crypto is experimental"
**Reality**: NIST has standardized algorithms after years of analysis. While newer than classical crypto, they are ready for production use.

### "Key sizes are too large for practical use"
**Reality**: While larger than classical keys, modern systems can handle the increased sizes. Network bandwidth and storage costs are manageable.

### "Performance is too slow"
**Reality**: Modern implementations are optimized and often faster than RSA. Some operations may be slower than ECDSA but are still practical.

### "We can wait until quantum computers arrive"
**Reality**: "Store now, decrypt later" attacks mean sensitive data encrypted today could be vulnerable when quantum computers emerge.

## Getting Started with PQ-Core

Now that you understand the fundamentals, you're ready to start using PQ-Core:

1. **Next**: [Quick Start Guide](quickstart.md) - Get up and running in 5 minutes
2. **Or**: [Installation & Setup](installation.md) - Detailed setup instructions
3. **Or**: [API Reference](../api-reference/) - Dive into the technical details

## Further Reading

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [ENISA Post-Quantum Cryptography Guidelines](https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation)
- [NSA Quantum-Safe Migration Guide](https://www.nsa.gov/Cybersecurity/Post-Quantum-Cryptography-Resources/)
- [Open Quantum Safe Project](https://openquantumsafe.org/)

---

*Ready to start coding? Continue to the [Quick Start Guide](quickstart.md).*