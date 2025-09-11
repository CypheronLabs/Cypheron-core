# Contributing Guidelines

We welcome contributions to Cypheron Core! This project implements post-quantum cryptography with a focus on security and reliability.

## Development Status

**Current Phase:** Seeking community audit and validation (Q4 2025)
**Status:** v0.1.1 - Foundation complete, documentation finished

## Areas for Contribution

### High Priority
1. **Security Analysis** - Review FFI boundary implementations
2. **Code Review** - Examine unsafe code blocks and safety justifications  
3. **Testing** - Add test cases, fuzzing, property-based testing
4. **Documentation** - Improve API docs and usage examples

### Standard Contributions
- Bug fixes and error handling improvements
- Performance optimizations
- Platform compatibility enhancements
- Build system improvements

## Security-Focused Development

### Required Reading
Before contributing, please review:
- [Security Policy](../../SECURITY.md) - Vulnerability reporting process
- [Unsafe Code Guide](../../UNSAFE_GUIDE.md) - All unsafe code documentation
- [Architecture](../../ARCHITECTURE.md) - Complete security architecture

### Security Requirements
- All unsafe code must include detailed safety justifications
- FFI boundary changes require comprehensive testing
- Memory safety must be preserved across all changes
- Security properties must be validated

## Development Process

### 1. Setup
```bash
git clone https://github.com/CypheronLabs/Cypheron-core.git
cd Cypheron-core
cargo build
cargo test
```

### 2. Code Standards
- Follow Rust standard formatting with `cargo fmt`
- Pass all lints with `cargo clippy`
- Maintain comprehensive test coverage
- Document all public APIs

### 3. Testing Requirements
- Unit tests for all new functionality
- Integration tests for algorithm implementations
- Known Answer Tests (KAT) for NIST compliance
- Property-based testing for cryptographic properties

### 4. Submission Process
- Fork the repository
- Create feature branch from main
- Implement changes with tests
- Run full test suite
- Submit pull request with detailed description

## Pull Request Guidelines

### Required Information
- **Purpose**: Clear description of changes and motivation
- **Testing**: Evidence of comprehensive testing
- **Security Impact**: Analysis of security implications  
- **Documentation**: Updates to relevant documentation

### Review Process
- **Code Review**: Technical implementation review
- **Security Review**: Security implications analysis
- **Testing Validation**: Comprehensive test execution
- **Documentation Check**: Accuracy and completeness

## Unsafe Code Contributions

Changes to unsafe code require additional scrutiny:

### Documentation Requirements
- **Safety Invariant**: What conditions ensure safety
- **Justification**: Why unsafe code is necessary
- **Verification**: How safety is validated
- **Error Handling**: Behavior when invariants are violated

### Review Process
- Manual code review by multiple contributors
- Comprehensive testing including edge cases
- Memory safety validation with sanitizers
- Documentation accuracy verification

## Community Standards

### Communication
- Respectful and professional interaction
- Constructive feedback and suggestions
- Focus on technical merit and security

### Quality Standards  
- High-quality implementations
- Comprehensive testing
- Clear documentation
- Security-first mindset

## Getting Help

### Questions and Support
- **GitHub Discussions**: Technical questions and design discussions
- **GitHub Issues**: Bug reports and feature requests (non-security)
- **Security Issues**: Private disclosure via [Security Policy](../../SECURITY.md)

### Resources
- [Architecture Overview](../architecture/overview.md)
- [Security Model](../security/model.md)
- [FFI Boundary Analysis](../architecture/ffi.md)
- [Development Roadmap](../getting-started/roadmap.md)

## Recognition

Contributors will be acknowledged in:
- Release notes for significant contributions
- Project documentation for major features
- Security credits for vulnerability reports

Thank you for helping make post-quantum cryptography accessible and secure!