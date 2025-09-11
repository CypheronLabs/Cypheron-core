# System Architecture

This section provides an overview of Cypheron Core's architecture and design principles.

For complete technical details, see the full [Architecture Documentation](../../ARCHITECTURE.md).

## Overview

Cypheron Core is structured as a multi-layered system combining Rust-native implementations with NIST reference implementations through FFI bindings. The architecture ensures cross-platform compatibility while maintaining security and performance.

## Core Components

| Component | Module Path| Primary Types | Purpose |
|---|---|---|---|
| ML-KEM(Kyber) | `kem/` | `MlKem512`, `MlKem768`, `MlKem1024`| Key encapsulation mechanisms |
| Digital Signatures |`sig/` | `MlDsa44`, `MlDsa65`, `MlDsa87`, `Falcon512`, `Falcon1024`| Post-quantum digital signatures |
|Hybrid Cryptography | `hybrid/` | `P256mlKem768`, `EccDilithium`, `CompositeKeypair` | Classical + PQ combinations|

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                        │
│  • Safe Rust API                                           │  
│  • Type Safety Guaranteed                                   │
├─────────────────────────────────────────────────────────────┤
│                    CYPHERON CORE                            │
│  • Algorithm Wrappers                                       │
│  • Memory Management                                        │
│  • Error Handling                                           │
├═════════════════════════════════════════════════════════════┤
│                    FFI BOUNDARY                             │
│  • Input Validation                                         │
│  • Buffer Management                                        │
│  • Safety Enforcement                                       │
├═════════════════════════════════════════════════════════════┤
│                    NIST C IMPLEMENTATIONS                   │
│  • ML-KEM Reference Code                                    │
│  • ML-DSA Reference Code                                    │
│  • Falcon & SPHINCS+ Code                                   │
└─────────────────────────────────────────────────────────────┘
```

## Build System Architecture

The build system orchestrates compilation of NIST reference implementations and generates FFI bindings:
- **Vendor Code Integrity**: SHA-256 verification of all C source files
- **Secure Compilation**: Platform-specific optimization with security flags  
- **FFI Safety**: Automated binding generation with function allowlisting

## Platform Abstraction Layer

| Platform | Secure Random| Memory Protection | Key Features |
|---|---|---|---|
| Windows | `BCryptGenRandom` | `VirtualProtect` | BCrypt API, Windows Crypto |
| macOS |`SecRandom` | `mprotect` | Security Framework, Apple Silicon detection|
| Linux | `getrandom` syscall | `mprotect` | Hardware RNG detection, CPU affinity|

## Testing and Validation

The testing infrastructure includes:
1. **Known Answer Tests (KAT)** - NIST compliance validation
2. **Property Based Testing** - Cryptographic property verification  
3. **Security Analysis** - Timing attacks and memory safety
4. **Fuzzing Infrastructure** - Robustness testing
5. **Performance Benchmarking** - Regression detection

For detailed technical architecture including security analysis, see the complete [Architecture Documentation](../../ARCHITECTURE.md).