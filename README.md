**Core** is the Post-Quantum Cryptographic Engine for the overall infrastructure. 
All Post-Quantum algorithms are implemented in this project, exposed in a secure way as a building block for the rest of the system (Vault, API's, Edge, etc)

## Core Infrastructure:
* Written in Rust for memory safety and performance
* Designed to be both a library and a micro-service
* Will focus on NIST Approved Post-Quantum algorithms
--- 
## Architecture
### Cryptographic Primitives
* Kyber (KEM)
* Dilithium (Signatures)
* Falcon (Signatures)
* SPHINCS+ (Extra Layer)
### Hybrid Layer (Post Quantum + Classical)
* X25519 + Kyber
* ECDSA + Dilithium
### Serialization & Key Encoding
- JSON, CBOR, Protobuf
- PEM/DER Wrappers
### Interface Layer
- Library API (Rust Crate)
- REST Microservice
