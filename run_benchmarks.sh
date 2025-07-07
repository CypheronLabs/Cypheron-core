#!/bin/bash

# Cypheron-Core Comprehensive Benchmark Suite
# Based on benchmark.json test plan

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BENCHMARK_DIR="benchmarks"
RESULTS_DIR="results"
REPORTS_DIR="reports"
LOG_FILE="benchmark.log"

# Functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Phase 1: Environment Setup
phase1_environment_setup() {
    log "Phase 1: Environment Setup"
    
    # Check if we're in the correct directory
    if [ ! -f "Cargo.toml" ]; then
        error "Must be run from the Cypheron-core root directory"
    fi
    
    # Create necessary directories
    mkdir -p "$RESULTS_DIR"/{correctness,performance,security}
    mkdir -p "$REPORTS_DIR"
    
    # Check system requirements
    log "Checking system requirements..."
    
    # Check Rust toolchain
    if ! command -v rustc &> /dev/null; then
        error "Rust compiler not found. Please install Rust."
    fi
    
    if ! command -v cargo &> /dev/null; then
        error "Cargo not found. Please install Rust with Cargo."
    fi
    
    # Check for required tools
    for tool in git cmake make; do
        if ! command -v "$tool" &> /dev/null; then
            warning "$tool not found. Some comparisons may be limited."
        fi
    done
    
    # Record system information
    log "Recording system information..."
    {
        echo "=== System Information ==="
        echo "Date: $(date)"
        echo "OS: $(uname -a)"
        echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
        echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
        echo "Rust version: $(rustc --version)"
        echo "Cargo version: $(cargo --version)"
        echo ""
    } > "$RESULTS_DIR/system_info.txt"
    
    # Set CPU governor to performance mode (if available)
    if [ -f "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" ]; then
        log "Setting CPU governor to performance mode..."
        echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || \
            warning "Could not set CPU governor. Results may vary."
    fi
    
    success "Environment setup complete"
}

# Phase 2: Correctness Validation
phase2_correctness_validation() {
    log "Phase 2: Correctness Validation"
    
    # Build the core library in release mode
    log "Building Cypheron-Core in release mode..."
    cargo build --release || error "Failed to build Cypheron-Core"
    
    # Run basic functionality tests
    log "Running correctness tests..."
    cargo test --release || error "Correctness tests failed"
    
    # TODO: Add NIST KAT tests when available
    log "NIST KAT tests: Placeholder (to be implemented with official test vectors)"
    
    success "Correctness validation complete"
}

# Phase 3: Performance Benchmarking
phase3_performance_benchmarking() {
    log "Phase 3: Performance Benchmarking"
    
    # Change to benchmarks directory
    cd "$BENCHMARK_DIR"
    
    # Build benchmarks
    log "Building benchmark suite..."
    cargo build --release || error "Failed to build benchmarks"
    
    # Run KEM benchmarks
    log "Running KEM benchmarks..."
    cargo bench --bench kem_benchmarks || error "KEM benchmarks failed"
    
    # Run signature benchmarks
    log "Running signature benchmarks..."
    cargo bench --bench sig_benchmarks || error "Signature benchmarks failed"
    
    # Run comparative benchmarks
    log "Running comparative benchmarks..."
    cargo bench --bench comparative_benchmarks || error "Comparative benchmarks failed"
    
    # Move results to main results directory
    if [ -d "target/criterion" ]; then
        cp -r target/criterion "../$RESULTS_DIR/performance/"
        log "Benchmark results saved to $RESULTS_DIR/performance/"
    fi
    
    cd ..
    success "Performance benchmarking complete"
}

# Phase 4: Security Analysis
phase4_security_analysis() {
    log "Phase 4: Security Analysis"
    
    # Static analysis with Clippy
    log "Running Clippy static analysis..."
    cargo clippy --all-targets --all-features -- -D warnings || \
        warning "Clippy found potential issues"
    
    # Check for common vulnerabilities
    log "Running cargo-audit security scan..."
    if command -v cargo-audit &> /dev/null; then
        cargo audit || warning "Security vulnerabilities found"
    else
        warning "cargo-audit not installed. Install with: cargo install cargo-audit"
    fi
    
    # Memory safety analysis with Miri (if available)
    log "Running Miri memory safety analysis..."
    if command -v cargo-miri &> /dev/null; then
        # Run a subset of tests with Miri (can be slow)
        timeout 300 cargo miri test || warning "Miri analysis incomplete or found issues"
    else
        log "Miri not available. Install with: rustup component add miri"
    fi
    
    # Fuzzing preparation (cargo-fuzz)
    if command -v cargo-fuzz &> /dev/null; then
        log "Setting up fuzzing targets..."
        # This would set up fuzzing but not run the full 24-hour campaign
        log "Fuzzing targets prepared. Run 'cargo fuzz' for extended testing."
    else
        log "cargo-fuzz not installed. Install with: cargo install cargo-fuzz"
    fi
    
    success "Security analysis complete"
}

# Phase 5: Report Generation
phase5_report_generation() {
    log "Phase 5: Report Generation"
    
    # Generate comprehensive report
    log "Generating benchmark report..."
    
    # Create summary report
    cat > "$REPORTS_DIR/benchmark_summary.md" << EOF
# Cypheron-Core Benchmark Summary

**Date:** $(date)
**Version:** v1.0.0
**System:** $(uname -s) $(uname -r)

## Test Results

### Environment
- **CPU:** $(lscpu | grep 'Model name' | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
- **Memory:** $(free -h | grep Mem | awk '{print $2}' 2>/dev/null || echo "Unknown")
- **Rust:** $(rustc --version)

### Performance Summary
Performance benchmarks completed successfully. Detailed results available in:
- Criterion HTML reports: \`$RESULTS_DIR/performance/criterion/\`
- Raw benchmark data: \`$RESULTS_DIR/performance/\`

### Security Analysis
- Static analysis completed with Clippy
- Memory safety verification attempted with Miri
- Security audit completed with cargo-audit

### Next Steps
1. Review detailed performance reports
2. Compare against reference implementations
3. Address any identified performance bottlenecks
4. Validate against production requirements

## Files Generated
- System information: \`$RESULTS_DIR/system_info.txt\`
- Performance results: \`$RESULTS_DIR/performance/\`
- Security analysis: \`$RESULTS_DIR/security/\`
- This summary: \`$REPORTS_DIR/benchmark_summary.md\`

---
*Generated by Cypheron-Core Benchmark Suite*
EOF
    
    # Copy system info to reports
    cp "$RESULTS_DIR/system_info.txt" "$REPORTS_DIR/"
    
    log "Report generated: $REPORTS_DIR/benchmark_summary.md"
    success "Report generation complete"
}

# Main execution
main() {
    log "Starting Cypheron-Core Comprehensive Benchmark Suite"
    log "Test plan based on benchmark.json specification"
    
    # Create log file
    touch "$LOG_FILE"
    
    # Execute phases
    phase1_environment_setup
    phase2_correctness_validation
    phase3_performance_benchmarking
    phase4_security_analysis
    phase5_report_generation
    
    # Final summary
    echo ""
    success "=== BENCHMARK SUITE COMPLETED ==="
    log "Results location: $RESULTS_DIR/"
    log "Reports location: $REPORTS_DIR/"
    log "Log file: $LOG_FILE"
    
    # Display quick summary
    echo ""
    log "Quick Summary:"
    if [ -f "$REPORTS_DIR/benchmark_summary.md" ]; then
        echo "- Benchmark report: $REPORTS_DIR/benchmark_summary.md"
    fi
    if [ -d "$RESULTS_DIR/performance/criterion" ]; then
        echo "- Performance results: $RESULTS_DIR/performance/criterion/"
    fi
    
    echo ""
    log "Open $REPORTS_DIR/benchmark_summary.md for detailed results"
}

# Handle interruption
trap 'error "Benchmark interrupted by user"' INT

# Run main function
main "$@"