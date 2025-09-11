# Memory Safety Model

Cypheron Core's memory safety model defines how the library maintains safety guarantees while interfacing with potentially unsafe C vendor code.

For complete technical details, see [Architecture Documentation](../../ARCHITECTURE.md#memory-safety-model-and-trust-boundaries).

## Memory Management Architecture

### Buffer Ownership Pattern

**Rust-Owned Memory Model:**
```rust
// All cryptographic buffers allocated in Rust
let mut public_key = [0u8; ML_KEM_768_PUBLIC_KEY_BYTES];
let mut secret_key = [0u8; ML_KEM_768_SECRET_KEY_BYTES];

// Temporary access granted to C code
let result = unsafe {
    pqcrystals_kyber768_ref_keypair(
        public_key.as_mut_ptr(),    // Rust maintains ownership
        secret_key.as_mut_ptr(),    // C code gets temporary access
    )
};
// Ownership returns to Rust immediately
```

## Memory Lifecycle Management

### 1. Allocation Phase
- All buffers allocated by Rust with correct sizes
- Stack allocation preferred for fixed-size cryptographic parameters
- Heap allocation only when necessary, with explicit cleanup

### 2. Access Phase  
- C code receives raw pointers with length information
- Access duration limited to specific function call
- No C code pointer retention beyond function scope

### 3. Cleanup Phase
- Sensitive data automatically zeroized by Drop implementations
- No manual cleanup required in normal operation
- Cleanup guaranteed even on panic conditions

## Safety Enforcement Mechanisms

### Pre-Call Validation
```rust
pub fn validate_buffer_for_ffi<T>(buffer: &[T], expected_len: usize) -> bool {
    buffer.len() == expected_len &&           // Length verification
    !buffer.as_ptr().is_null() &&            // Non-null pointer
    buffer.as_ptr().is_aligned() &&          // Proper alignment
    is_valid_memory_range(buffer)             // Address space validation
}
```

### Buffer Bounds Protection
```rust
trait FfiSafe {
    fn is_valid_for_ffi(&self) -> bool;
}

impl FfiSafe for &[u8] {
    fn is_valid_for_ffi(&self) -> bool {
        !self.is_empty() &&                   // Non-empty buffer
        self.len() <= isize::MAX as usize &&  // Size limits
        // Proper alignment
        self.as_ptr() as usize % std::mem::align_of::<u8>() == 0  
    }
}
```

### Post-Call Validation
```rust
fn verify_buffer_initialized(buffer: &[u8], expected_len: usize) -> bool {
    // Verify C code properly initialized buffer
    buffer.len() == expected_len &&
    // Additional cryptographic output validation
    verify_crypto_output_validity(buffer)
}
```

## Secure Memory Management

### Secret Key Protection
```rust
use secrecy::{SecretBox, ExposeSecret, Zeroize};

pub struct SecretKey(SecretBox<[u8; ML_DSA_SECRET_KEY_BYTES]>);

impl SecretKey {
    pub fn expose_for_ffi<F, R>(&self, f: F) -> R 
    where 
        F: FnOnce(&[u8]) -> R 
    {
        // Controlled access to secret material
        self.0.expose_secret(f)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Automatic secure cleanup
        self.0.expose_secret_mut(|s| s.zeroize());
    }
}
```

### Memory Protection
- **Stack Protection**: Fixed-size buffers on stack when possible
- **Heap Isolation**: Dynamic allocation with secure cleanup  
- **Zeroization**: All sensitive data cleared on drop
- **ASLR Support**: Position-independent code generation

## Trust Zone Classification

### Fully Trusted Zone
- **Rust Application Code**: Memory safety guaranteed by compiler
- **Safe API Layer**: Type safety enforced automatically
- **Standard Library**: Rust std library safety guarantees

### Conditionally Trusted Zone
- **Unsafe Wrappers**: Manual safety verification through code review
- **FFI Management**: Comprehensive testing and validation
- **Platform Code**: OS-specific implementations with error handling

### Untrusted Zone  
- **C Reference Code**: Manual memory management, potential UB
- **Vendor Libraries**: Trust through testing and verification
- **System Interfaces**: OS APIs with proper error handling

## Memory Safety Testing

### Validation Methods
1. **Static Analysis**: Rust compiler checks and Clippy lints
2. **Dynamic Testing**: AddressSanitizer and MemorySanitizer  
3. **Fuzzing**: Automated testing with malformed inputs
4. **Property Testing**: Cryptographic property verification
5. **Manual Review**: Code review of all unsafe blocks

### Continuous Validation
- **CI/CD Integration**: Memory safety testing on all commits
- **Platform Testing**: Validation across Linux, macOS, Windows
- **Regression Prevention**: Automated detection of safety violations
- **Documentation**: All unsafe code documented with safety invariants

## Safety Guarantees

### What We Guarantee
- **No Buffer Overflows**: All C function calls bounds-checked
- **No Use-After-Free**: Rust ownership model prevents dangling pointers
- **No Double-Free**: Single ownership prevents multiple deallocation  
- **Secure Cleanup**: All sensitive data zeroized on drop

### What We Don't Guarantee  
- **C Code Internal Safety**: Reliant on NIST reference quality
- **Side-Channel Resistance**: Depends on C implementation properties
- **Perfect Forward Secrecy**: Application-level concern
- **Quantum Resistance**: Depends on algorithm security assumptions

For complete technical analysis including specific memory management patterns and safety invariants, see the full [Architecture Documentation](../../ARCHITECTURE.md).