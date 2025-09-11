# Unsafe Code Guide

Cypheron Core contains unsafe Rust code required for FFI integration with NIST C reference implementations. This section provides an overview of our unsafe code usage and safety guarantees.

For complete documentation of all unsafe code blocks, see the comprehensive [Unsafe Code Guide](../../UNSAFE_GUIDE.md).

## Overview

The library contains **91 unsafe blocks** across **19 files**, each with detailed safety justifications. All unsafe code is:

- Documented with safety invariants
- Required for FFI with C vendor code  
- Minimized to essential operations
- Reviewed for memory safety

## Categories of Unsafe Code

### 1. FFI Function Calls
Direct calls to C cryptographic functions from NIST reference implementations.

**Safety Guarantee:** Buffer bounds validated before calls, return codes checked.

### 2. Pointer Dereferencing  
Converting Rust slices to raw pointers for C function parameters.

**Safety Guarantee:** Pointers derived from valid Rust references, lifetimes controlled.

### 3. Memory Operations
Buffer initialization and secure cleanup operations.

**Safety Guarantee:** All operations within allocated bounds, proper initialization verified.

### 4. Platform-Specific Code
OS-specific secure random number generation and memory protection.

**Safety Guarantee:** Platform APIs used according to documentation, error handling comprehensive.

## Security Audit Considerations

Each unsafe block is documented with:
- **Safety Invariant:** What conditions must hold for safety
- **Justification:** Why the unsafe operation is necessary  
- **Verification:** How safety is ensured in practice
- **Error Handling:** What happens when invariants are violated

## Complete Documentation

For detailed analysis of every unsafe block including line-by-line safety justifications, see:
- [**Complete Unsafe Code Guide (UNSAFE_GUIDE.md)**](../../UNSAFE_GUIDE.md)

This comprehensive guide provides security auditors with complete visibility into all potentially unsafe operations.