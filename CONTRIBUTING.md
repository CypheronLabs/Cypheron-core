# Contributing to Cypheron Core

Thank you for your interest in contributing to Cypheron Core! This document provides guidelines for contributing to our post-quantum cryptography library.

## Getting Started

### Prerequisites

- Rust 1.70+ with Cargo
- C compiler (GCC, Clang, or MSVC)
- Git

### Setting Up the Development Environment

```bash
git clone https://github.com/CypheronLabs/Cypheron-core.git
cd Cypheron-core/core-lib
cargo build
cargo test
```

## How to Contribute

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce, expected vs actual behavior
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `cargo test`
6. Run benchmarks if performance-related: `cargo bench`
7. Submit a pull request

### Code Guidelines

#### Rust Code Style
- Follow `rustfmt` formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy`
- Write documentation comments for public APIs
- Include unit tests for new functionality

#### Security Requirements
- All cryptographic code must be constant-time
- Use `zeroize` for sensitive data cleanup
- No unsafe code without explicit review and justification
- Follow secure coding practices for memory management

#### Testing Requirements
- Unit tests for all public APIs
- Integration tests for complete workflows
- Property-based tests for cryptographic properties
- Known Answer Tests (KAT) for algorithm compliance

### Commit Message Format

```
type(scope): brief description

Longer explanation if needed

- List any breaking changes
- Reference issues: Fixes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

## Development Workflow

### Testing

```bash
# Run all tests
cargo test

# Run security tests
cargo test --test security

# Run benchmarks
cargo bench

# Fuzz testing
cd tests/fuzz
cargo fuzz run fuzz_ml_kem_512
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Check documentation
cargo doc --no-deps --open
```

## Areas for Contribution

### Algorithm Implementations
- Performance optimizations
- Platform-specific optimizations
- Additional NIST algorithms

### Testing & Security
- Fuzzing targets
- Side-channel analysis
- Memory safety testing
- Known Answer Test vectors

### Documentation
- API documentation
- Usage examples
- Algorithm explanations
- Security considerations

### Platform Support
- Build system improvements
- Cross-compilation support
- Platform-specific optimizations

## Code Review Process

1. All changes require review from maintainers
2. Security-related changes require additional review
3. Performance changes should include benchmark results
4. Breaking changes require RFC discussion

## Community Guidelines

- Be respectful and professional
- Focus on technical merit
- Provide constructive feedback
- Help others learn and grow

## Questions?

- Open a GitHub Discussion for general questions
- Join our community channels (links on [cypheronlabs.com](https://cypheronlabs.com/))
- Contact maintainers for sensitive issues

Thank you for contributing to the future of post-quantum cryptography!