# PQ-Core API Documentation

Welcome to the comprehensive documentation for PQ-Core, a production-ready post-quantum cryptography API. This documentation is designed to be your complete guide from basic concepts to advanced implementation patterns.

## 📚 Table of Contents

### Getting Started
- [Introduction to Post-Quantum Cryptography](getting-started/introduction.md)
- [Quick Start Guide](getting-started/quickstart.md)
- [Installation & Setup](getting-started/installation.md)
- [Cross-Platform Support](getting-started/cross-platform.md)
- [Your First API Call](getting-started/first-call.md)

### API Reference
- [Authentication](api-reference/authentication.md)
- [KEM Operations](api-reference/kem.md)
- [Digital Signatures](api-reference/signatures.md)
- [Hybrid Cryptography](api-reference/hybrid.md)
- [Admin Operations](api-reference/admin.md)
- [Error Handling](api-reference/errors.md)

### Examples & Tutorials
- [Basic Usage Examples](examples/basic-usage.md)
- [Language-Specific Clients](examples/client-libraries.md)
- [Integration Patterns](examples/integration-patterns.md)
- [Migration from Classical Crypto](examples/migration-guide.md)

### Security
- [Security Model](security/security-model.md)
- [API Security Features](security/api-security.md)
- [Best Practices](security/best-practices.md)
- [Threat Model](security/threat-model.md)

### Advanced Topics
- [Algorithm Selection Guide](advanced/algorithm-selection.md)
- [Performance Optimization](advanced/performance.md)
- [Monitoring & Observability](advanced/monitoring.md)
- [Production Deployment](advanced/deployment.md)

## 🚀 Quick Navigation

**New to Post-Quantum Crypto?** Start with [Introduction to Post-Quantum Cryptography](getting-started/introduction.md)

**Ready to Code?** Jump to the [Quick Start Guide](getting-started/quickstart.md)

**Need API Details?** Check the [API Reference](api-reference/)

**Looking for Examples?** Browse [Examples & Tutorials](examples/)

**Security Questions?** Read the [Security Documentation](security/)

## 🔧 What is PQ-Core?

PQ-Core is a comprehensive REST API that provides access to standardized post-quantum cryptographic algorithms. It offers:

- **Key Encapsulation Mechanisms (KEM)**: Kyber family algorithms
- **Digital Signatures**: Dilithium, Falcon, and SPHINCS+ families
- **Hybrid Cryptography**: Combining classical and post-quantum algorithms
- **Enterprise Security**: API key management, rate limiting, audit logging
- **Production Ready**: OWASP-compliant security, monitoring, and observability

## 🛡️ Why Post-Quantum Cryptography?

With the advent of quantum computers, traditional cryptographic algorithms (RSA, ECDSA, ECDH) become vulnerable to attack. Post-quantum cryptography provides algorithms that remain secure even against quantum adversaries.

PQ-Core implements NIST-standardized algorithms that are:
- **Quantum-resistant**: Secure against both classical and quantum attacks
- **Standardized**: Based on NIST Post-Quantum Cryptography standards
- **Battle-tested**: Extensively analyzed by the cryptographic community
- **Production-ready**: Optimized implementations with security hardening

## 📊 Supported Algorithms

### Key Encapsulation Mechanisms (KEM)
- **Kyber-512**: NIST security level 1, ~800 bytes public key
- **Kyber-768**: NIST security level 3, ~1,184 bytes public key  
- **Kyber-1024**: NIST security level 5, ~1,568 bytes public key

### Digital Signatures
- **Dilithium-2**: NIST security level 2, ~1,312 bytes public key
- **Dilithium-3**: NIST security level 3, ~1,952 bytes public key
- **Dilithium-5**: NIST security level 5, ~2,592 bytes public key
- **Falcon-512**: NIST security level 1, ~897 bytes public key
- **Falcon-1024**: NIST security level 5, ~1,793 bytes public key
- **SPHINCS+**: Hash-based signatures in multiple variants

### Hybrid Algorithms
- **Hybrid Signatures**: Combines classical (Ed25519, ECDSA) with post-quantum signatures
- **Migration-Friendly**: Gradual transition from classical to post-quantum

## 🎯 Who Should Use This Documentation?

- **Developers** integrating post-quantum cryptography into applications
- **Security Engineers** evaluating post-quantum security models
- **DevOps Teams** deploying quantum-resistant infrastructure
- **Researchers** experimenting with post-quantum algorithms
- **Organizations** planning quantum-safe migrations

## 💡 Documentation Philosophy

This documentation follows a progressive disclosure approach:

1. **Conceptual Understanding**: Start with why and what
2. **Practical Implementation**: Move to how and when
3. **Advanced Optimization**: Finish with performance and scale
4. **Real-World Examples**: Always include working code
5. **Security Focus**: Emphasize secure implementation patterns

## 🔗 External Resources

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [Post-Quantum Cryptography Alliance](https://pqcrypto.org/)

---

*Ready to get started? Begin with [Introduction to Post-Quantum Cryptography](getting-started/introduction.md) or jump straight to the [Quick Start Guide](getting-started/quickstart.md).*