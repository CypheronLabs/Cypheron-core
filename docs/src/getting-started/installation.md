# Installation

## System Requirements

- **Rust**: 1.80 or higher
- **Operating System**: Linux, macOS, or Windows
- **Architecture**: x86_64, aarch64

## Cargo Installation

Add Cypheron Core to your `Cargo.toml`:

```toml
[dependencies]
cypheron-core = "0.1.0"
```

Then run:

```bash
cargo build
```

## Feature Flags

Cypheron Core supports optional features:

```toml
[dependencies]
cypheron-core = { version = "0.1.0", features = ["std", "alloc"] }
```

Available features:
- `std` (default): Standard library support
- `alloc`: Allocation support for `no_std` environments  
- `hybrid`: Hybrid cryptography algorithms
- `serialize`: Serde serialization support

## No-std Support

For embedded and constrained environments:

```toml
[dependencies]
cypheron-core = { version = "0.1.0", default-features = false, features = ["alloc"] }
```

## Development Dependencies

For testing and benchmarking:

```toml
[dev-dependencies]
cypheron-core = { version = "0.1.0", features = ["test-utils"] }
criterion = "0.5"
```

## Platform-Specific Notes

### Linux
No additional dependencies required.

### macOS
Ensure Xcode command line tools are installed:
```bash
xcode-select --install
```

### Windows
Requires Visual Studio Build Tools or MSVC.

## Verification

Verify your installation:

```rust
use cypheron_core::kem::{MlKem768, Kem};

fn main() {
    match MlKem768::keypair() {
        Ok(_) => println!("Installation successful!"),
        Err(e) => eprintln!("Installation issue: {}", e),
    }
}
```

## Next Steps

- [Quick Start Guide](quick-start.md) - Basic usage examples
- [API Reference](../api/types.md) - Complete API documentation