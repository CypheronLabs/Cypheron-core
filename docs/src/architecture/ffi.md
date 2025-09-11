# FFI Boundary Security

The Foreign Function Interface (FFI) boundary represents the most security-critical component of Cypheron Core, defining the transition between memory-safe Rust and potentially unsafe C implementations.

For complete technical analysis, see [Architecture Documentation](../../ARCHITECTURE.md#ffi-security-boundary-analysis).

## Trust Boundary Model

The FFI boundary creates a clear separation between trusted and untrusted zones:

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                             │
│  • Rust Application Code - Type & Memory Safe              │
│  • Cypheron Safe Wrappers - Input Validation               │  
│  • Buffer Management - Lifetime Control                     │
├═════════════════════════════════════════════════════════════┤
│                    FFI SECURITY BOUNDARY                    │
├═════════════════════════════════════════════════════════════┤
│                    UNTRUSTED ZONE                           │
│  • NIST C Reference Code - Manual Memory Management        │
│  • Potential Undefined Behavior - Platform Specific       │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow Security

### Inbound Path (Rust → C)
1. **Input Validation**: All parameters validated against algorithm specifications
2. **Buffer Preparation**: Memory allocated with exact required sizes  
3. **Pointer Safety**: Raw pointers derived only from valid Rust references
4. **Length Verification**: Buffer sizes cross-checked against C function expectations

### Outbound Path (C → Rust)  
1. **Return Code Verification**: All C function return values checked
2. **Output Validation**: Generated data verified for proper initialization
3. **Size Consistency**: Output lengths validated against expected algorithm outputs
4. **Memory Transfer**: C-generated data safely transferred to Rust ownership

## Memory Ownership Model

### Pre-Call State
- Rust allocates and owns all input and output buffers
- Buffer sizes calculated from algorithm-specific constants
- Pointers derived from valid Rust slice references

### During C Execution
- Temporary shared access granted via raw pointers
- Rust retains ownership but cannot access during execution
- C code operates within provided buffer boundaries

### Post-Call State  
- Full ownership returns to Rust immediately
- C-modified buffers validated for proper initialization
- Sensitive data securely zeroized via Drop traits

## Safety Guarantees

### Buffer Boundary Protection
- All buffer accesses validated before FFI calls
- C functions receive exact sizes via separate length parameters  
- No C function can access memory beyond provided boundaries

### Type Safety Maintenance
- Raw pointers used only for duration of C function calls
- All data marshalling preserves Rust type invariants
- No C pointers retained beyond function call scope

### Error Handling Isolation
- C function errors isolated and converted to Rust error types
- No C error state can compromise Rust memory safety
- Failed operations trigger secure cleanup of sensitive data

### Concurrency Safety
- FFI calls protected by appropriate synchronization primitives
- No shared mutable state accessible across FFI boundary  
- Thread-local storage used for algorithm-specific contexts

## Example: Safe FFI Pattern

```rust
pub fn ml_kem_keypair() -> Result<(PublicKey, SecretKey), Error> {
    // 1. Allocate buffers in Rust
    let mut pk = [0u8; ML_KEM_768_PUBLIC_KEY_BYTES];  
    let mut sk = [0u8; ML_KEM_768_SECRET_KEY_BYTES];
    
    // 2. Validate buffer sizes
    assert_eq!(pk.len(), ML_KEM_768_PUBLIC_KEY_BYTES);
    assert_eq!(sk.len(), ML_KEM_768_SECRET_KEY_BYTES);
    
    // 3. Call C function with temporary access
    let result = unsafe {
        pqcrystals_kyber768_ref_keypair(
            pk.as_mut_ptr(),    // Temporary pointer access
            sk.as_mut_ptr(),    // Rust maintains ownership
        )
    };
    
    // 4. Validate C function success
    if result != 0 {
        return Err(Error::KeygenFailed);
    }
    
    // 5. Verify output initialization (C code populated buffers)
    if pk.iter().all(|&b| b == 0) || sk.iter().all(|&b| b == 0) {
        return Err(Error::InvalidOutput);
    }
    
    // 6. Transfer ownership back to Rust types
    Ok((PublicKey::new(pk), SecretKey::new(sk)))
}
```

## Security Testing

The FFI boundary undergoes comprehensive testing:
- **Buffer Boundary Testing**: Verify no out-of-bounds access
- **Type Safety Validation**: Ensure proper data marshalling  
- **Error Injection**: Test error handling paths
- **Fuzzing**: Automated robustness testing with malformed inputs
- **Memory Safety Analysis**: AddressSanitizer and Valgrind testing

For detailed implementation analysis including specific safety invariants for each unsafe block, see the [Unsafe Code Guide](../security/unsafe-guide.md).