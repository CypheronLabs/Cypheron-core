// Example: Linux Seccomp-BPF Sandboxing
//
// This example demonstrates how to enable production security hardening
// on Linux using seccomp-BPF syscall filtering.
//
// Build with: cargo build --example linux_sandboxing --features seccomp-bpf
// Run with: cargo run --example linux_sandboxing --features seccomp-bpf

#[cfg(all(target_os = "linux", feature = "seccomp-bpf"))]
fn main() {
    use cypheron_core::platform::linux::enable_production_security;
    use cypheron_core::kem::{MlKem768, Kem};

    println!("Enabling production security hardening with seccomp-BPF...");
    
    // Enable seccomp-BPF sandboxing before performing cryptographic operations
    if let Err(e) = enable_production_security() {
        eprintln!("Failed to enable sandboxing: {}", e);
        return;
    }
    
    println!("Sandboxing enabled successfully!");
    println!("Only whitelisted syscalls are now permitted.");
    
    // Demonstrate that cryptographic operations work within the sandbox
    println!("\nPerforming ML-KEM-768 operations within sandbox...");
    
    let (public_key, secret_key) = MlKem768::keypair();
    println!("Generated keypair");
    
    let (ciphertext, shared_secret_1) = MlKem768::encapsulate(&public_key);
    println!("Encapsulated shared secret");
    
    let shared_secret_2 = MlKem768::decapsulate(&ciphertext, &secret_key);
    println!("Decapsulated shared secret");
    
    assert_eq!(shared_secret_1, shared_secret_2);
    println!("\nSuccess! All operations completed within the secure sandbox.");
    
    // Note: After sandboxing is enabled, attempting to perform
    // non-whitelisted syscalls (like fork, exec, etc.) will fail
}

#[cfg(not(all(target_os = "linux", feature = "seccomp-bpf")))]
fn main() {
    println!("This example requires Linux and the 'seccomp-bpf' feature.");
    println!("Build with: cargo run --example linux_sandboxing --features seccomp-bpf");
}
