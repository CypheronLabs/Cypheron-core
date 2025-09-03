#!/usr/bin/env python3
"""
Cypheron-Core Security Audit Framework
Automated security analysis for post-quantum cryptography library
"""

import os
import re
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
from enum import Enum

class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class SecurityFinding:
    severity: SeverityLevel
    category: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str

class SecurityAuditor:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.findings: List[SecurityFinding] = []
        self.rust_files: List[Path] = []
        self.ffi_patterns = []
        self.unsafe_patterns = []
        self._load_patterns()
        
    def _load_patterns(self):
        """Load security vulnerability patterns"""
        self.ffi_patterns = [
            (r'unsafe\s*{[^}]*libc::', "Direct libc calls in unsafe blocks"),
            (r'\.as_ptr\(\)', "Raw pointer access"),
            (r'\.as_mut_ptr\(\)', "Mutable raw pointer access"),
            (r'std::mem::transmute', "Memory transmutation"),
            (r'std::ptr::', "Raw pointer manipulation"),
            (r'\.offset\(', "Pointer arithmetic"),
            (r'from_raw', "Raw pointer construction"),
            (r'slice::from_raw_parts', "Unsafe slice construction"),
        ]
        
        self.unsafe_patterns = [
            (r'panic!\s*\(', "Panic in library code"),
            (r'unwrap\(\)', "Unwrap without error handling"),
            (r'expect\([^)]*\)', "Expect without proper context"),
            (r'\.len\(\)\s*-\s*1', "Potential underflow"),
            (r'as\s+u\d+', "Unchecked integer casting"),
            (r'buffer\[\s*\w+\s*\]', "Array indexing without bounds check"),
        ]

    def scan_rust_files(self):
        """Find all Rust source files"""
        patterns = ["**/*.rs"]
        for pattern in patterns:
            self.rust_files.extend(self.project_root.glob(pattern))
        
        # Filter out target directory and vendor code
        self.rust_files = [f for f in self.rust_files 
                          if 'target/' not in str(f) and 'vendor/' not in str(f)]

    def analyze_ffi_safety(self):
        """Analyze FFI boundary safety"""
        print("[INFO] Analyzing FFI safety patterns...")
        
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                # Check for unsafe FFI patterns
                for i, line in enumerate(lines, 1):
                    for pattern, desc in self.ffi_patterns:
                        if re.search(pattern, line):
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.HIGH,
                                category="FFI_SAFETY",
                                title=f"Unsafe FFI Pattern: {desc}",
                                description=f"Found potentially unsafe FFI pattern: {pattern}",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Review FFI safety, add validation"
                            ))
                            
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def analyze_memory_safety(self):
        """Analyze memory safety issues"""
        print("[INFO] Analyzing memory safety patterns...")
        
        critical_functions = [
            'mprotect', 'malloc', 'free', 'memcpy', 'memset',
            'explicit_bzero', 'getrandom', 'syscall'
        ]
        
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    # Check for critical system calls
                    for func in critical_functions:
                        if func in line and 'unsafe' in line:
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.CRITICAL,
                                category="MEMORY_SAFETY",
                                title=f"Unsafe system call: {func}",
                                description=f"Direct system call {func} in unsafe block without validation",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Add comprehensive input validation and error handling"
                            ))
                    
                    # Check for buffer operations
                    if re.search(r'buffer\s*\[\s*.*\s*\]', line):
                        self.findings.append(SecurityFinding(
                            severity=SeverityLevel.MEDIUM,
                            category="MEMORY_SAFETY", 
                            title="Unchecked buffer access",
                            description="Array/buffer access without explicit bounds checking",
                            file_path=str(rust_file),
                            line_number=i,
                            code_snippet=line.strip(),
                            recommendation="Add bounds checking before array access"
                        ))
                        
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def analyze_error_handling(self):
        """Analyze error handling patterns"""
        print("[INFO] Analyzing error handling...")
        
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    # Check for unsafe error handling
                    for pattern, desc in self.unsafe_patterns:
                        if re.search(pattern, line):
                            severity = SeverityLevel.HIGH if 'panic' in pattern else SeverityLevel.MEDIUM
                            self.findings.append(SecurityFinding(
                                severity=severity,
                                category="ERROR_HANDLING",
                                title=f"Unsafe error handling: {desc}",
                                description=f"Found potentially unsafe error handling pattern",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Replace with proper error handling"
                            ))
                            
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def analyze_crypto_constructions(self):
        """Analyze cryptographic constructions"""
        print("[INFO] Analyzing cryptographic constructions...")
        
        # Check hybrid key derivation
        hybrid_files = list(self.project_root.glob("**/hybrid/*.rs"))
        
        for rust_file in hybrid_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    
                # Check for weak key derivation
                if 'Hkdf' in content and 'None' in content:
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if 'Hkdf' in line and 'None' in line:
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.HIGH,
                                category="CRYPTOGRAPHY",
                                title="Weak key derivation",
                                description="HKDF used without salt (None parameter)",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Use proper salt for HKDF key derivation"
                            ))
                
                # Check for hardcoded context strings
                context_matches = re.finditer(r'b"([^"]*)"', content)
                for match in context_matches:
                    if any(word in match.group(1).lower() for word in ['cypheron', 'hybrid', 'kem']):
                        line_num = content[:match.start()].count('\n') + 1
                        self.findings.append(SecurityFinding(
                            severity=SeverityLevel.MEDIUM,
                            category="CRYPTOGRAPHY",
                            title="Hardcoded cryptographic context",
                            description="Fixed context string may enable collision attacks",
                            file_path=str(rust_file),
                            line_number=line_num,
                            code_snippet=match.group(0),
                            recommendation="Use domain-separated, versioned contexts"
                        ))
                        
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def analyze_timing_vulnerabilities(self):
        """Check for timing attack vulnerabilities"""
        print("[INFO] Analyzing timing vulnerabilities...")
        
        timing_vulnerable_patterns = [
            (r'if.*==.*{', "Conditional branching on secrets"),
            (r'match.*{', "Pattern matching on sensitive data"),
            (r'for.*in.*{', "Variable-time loops"),
            (r'while.*{', "Variable-time loops"),
        ]
        
        crypto_files = []
        for pattern in ["**/kem/*.rs", "**/sig/*.rs", "**/hybrid/*.rs"]:
            crypto_files.extend(self.project_root.glob(pattern))
            
        for rust_file in crypto_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    for pattern, desc in timing_vulnerable_patterns:
                        if re.search(pattern, line.lower()):
                            # Check if this is in a crypto-sensitive context
                            surrounding_lines = lines[max(0, i-3):i+3]
                            context = ' '.join(surrounding_lines).lower()
                            
                            if any(word in context for word in ['key', 'secret', 'signature', 'decrypt', 'sign']):
                                self.findings.append(SecurityFinding(
                                    severity=SeverityLevel.HIGH,
                                    category="TIMING_ATTACKS",
                                    title=f"Potential timing vulnerability: {desc}",
                                    description="Conditional execution on sensitive data may leak timing information",
                                    file_path=str(rust_file),
                                    line_number=i,
                                    code_snippet=line.strip(),
                                    recommendation="Use constant-time operations for sensitive data"
                                ))
                                
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def test_build_security(self):
        """Test build system security"""
        print("[INFO] Testing build system security...")
        
        try:
            # Check for reproducible builds
            result = subprocess.run(['cargo', 'build', '--release'], 
                                  cwd=self.project_root / 'core-lib',
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="BUILD_SECURITY",
                    title="Build system failure",
                    description=f"Build failed: {result.stderr}",
                    file_path="Cargo.toml",
                    line_number=1,
                    code_snippet="",
                    recommendation="Fix build errors before security analysis"
                ))
                
            # Check for compiler warnings
            if 'warning:' in result.stderr:
                warning_count = result.stderr.count('warning:')
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.MEDIUM,
                    category="BUILD_SECURITY",
                    title=f"Compiler warnings ({warning_count} found)",
                    description="Compiler warnings may indicate underlying issues",
                    file_path="build output",
                    line_number=0,
                    code_snippet=result.stderr[:200] + "...",
                    recommendation="Address all compiler warnings"
                ))
                
        except subprocess.TimeoutExpired:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="BUILD_SECURITY",
                title="Build timeout",
                description="Build process took longer than expected",
                file_path="build system",
                line_number=0,
                code_snippet="",
                recommendation="Investigate build performance issues"
            ))
        except Exception as e:
            print(f"[ERROR] Build test failed: {e}")

    def test_dependency_security(self):
        """Analyze dependency security"""
        print("[INFO] Analyzing dependency security...")
        
        try:
            # Check Cargo.lock for known vulnerabilities
            cargo_lock = self.project_root / 'core-lib' / 'Cargo.lock'
            if cargo_lock.exists():
                result = subprocess.run(['cargo', 'audit'], 
                                      cwd=self.project_root / 'core-lib',
                                      capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="DEPENDENCY_SECURITY",
                        title="Known vulnerabilities in dependencies",
                        description=f"cargo audit found issues: {result.stdout}",
                        file_path="Cargo.lock",
                        line_number=1,
                        code_snippet="",
                        recommendation="Update vulnerable dependencies immediately"
                    ))
                    
        except FileNotFoundError:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="DEPENDENCY_SECURITY", 
                title="cargo-audit not installed",
                description="Cannot check for known vulnerabilities",
                file_path="build system",
                line_number=0,
                code_snippet="",
                recommendation="Install cargo-audit for vulnerability scanning"
            ))
        except Exception as e:
            print(f"[WARN] Dependency analysis failed: {e}")

    def analyze_secret_handling(self):
        """Analyze how secrets are handled"""
        print("[INFO] Analyzing secret handling...")
        
        secret_patterns = [
            (r'println!\s*\(.*secret', "Potential secret logging"),
            (r'eprintln!\s*\(.*secret', "Potential secret logging"),
            (r'dbg!\s*\(.*secret', "Debug printing secrets"),
            (r'format!\s*\(.*secret', "String formatting secrets"),
            (r'\.clone\(\).*secret', "Secret cloning"),
        ]
        
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    for pattern, desc in secret_patterns:
                        if re.search(pattern, line.lower()):
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.CRITICAL,
                                category="SECRET_HANDLING",
                                title=f"Secret exposure: {desc}",
                                description="Potential exposure of cryptographic secrets",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Remove secret exposure, use secure logging"
                            ))
                            
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def test_constant_time_violations(self):
        """Test for constant-time violations"""
        print("[INFO] Testing for constant-time violations...")
        
        # Patterns that typically violate constant-time
        ct_violations = [
            (r'if\s+.*\.len\(\)', "Length-dependent branching"),
            (r'if\s+.*\[.*\]\s*==', "Data-dependent branching"),
            (r'match\s+.*\{', "Pattern matching on data"),
            (r'for\s+.*in.*\.iter\(\)', "Variable iteration over data"),
            (r'\.find\(', "Search operations on secrets"),
            (r'\.contains\(', "Contains check on secrets"),
        ]
        
        crypto_sensitive_files = []
        for pattern in ["**/kem/*.rs", "**/sig/*.rs", "**/hybrid/*.rs"]:
            crypto_sensitive_files.extend(self.project_root.glob(pattern))
            
        for rust_file in crypto_sensitive_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    for pattern, desc in ct_violations:
                        if re.search(pattern, line):
                            # Check context for crypto operations
                            context_lines = lines[max(0, i-5):i+5]
                            context = ' '.join(context_lines).lower()
                            
                            if any(word in context for word in ['secret', 'key', 'decrypt', 'sign']):
                                self.findings.append(SecurityFinding(
                                    severity=SeverityLevel.HIGH,
                                    category="CONSTANT_TIME",
                                    title=f"Constant-time violation: {desc}",
                                    description="Operation may leak timing information about secrets",
                                    file_path=str(rust_file),
                                    line_number=i,
                                    code_snippet=line.strip(),
                                    recommendation="Use constant-time operations for sensitive data"
                                ))
                                
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def check_input_validation(self):
        """Check input validation patterns"""
        print("[INFO] Checking input validation...")
        
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    # Look for functions that take external input
                    if re.search(r'pub\s+fn.*\(.*&\[u8\]', line):
                        # Check if validation exists in next few lines
                        validation_lines = lines[i:i+10]
                        has_validation = any(
                            any(check in vline.lower() for check in 
                                ['len()', 'is_empty()', 'bounds', 'validate', 'check'])
                            for vline in validation_lines
                        )
                        
                        if not has_validation:
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.HIGH,
                                category="INPUT_VALIDATION",
                                title="Missing input validation",
                                description="Public function accepts byte arrays without validation",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Add input validation for public APIs"
                            ))
                            
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def run_fuzzing_tests(self):
        """Check if fuzzing reveals crashes"""
        print("[INFO] Running fuzzing tests...")
        
        fuzz_dir = self.project_root / 'core-lib' / 'tests' / 'fuzz'
        if not fuzz_dir.exists():
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="TESTING",
                title="No fuzzing infrastructure",
                description="Project lacks fuzzing tests for input validation",
                file_path="tests/",
                line_number=0,
                code_snippet="",
                recommendation="Implement fuzzing tests for all public APIs"
            ))
            return
            
        try:
            # Try to run existing fuzz tests
            result = subprocess.run(['cargo', 'fuzz', 'list'], 
                                  cwd=fuzz_dir, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                fuzz_targets = result.stdout.strip().split('\n')
                print(f"[INFO] Found fuzz targets: {fuzz_targets}")
                
                # Run quick fuzz test
                for target in fuzz_targets[:2]:  # Limit to first 2 targets
                    try:
                        fuzz_result = subprocess.run(
                            ['cargo', 'fuzz', 'run', target, '--', '-max_total_time=10'],
                            cwd=fuzz_dir, capture_output=True, text=True, timeout=15
                        )
                        
                        if fuzz_result.returncode != 0:
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.CRITICAL,
                                category="FUZZING",
                                title=f"Fuzz target {target} crashes",
                                description=f"Fuzzing revealed crashes: {fuzz_result.stderr[:200]}",
                                file_path=f"fuzz/{target}",
                                line_number=0,
                                code_snippet="",
                                recommendation="Fix crash-inducing inputs"
                            ))
                            
                    except subprocess.TimeoutExpired:
                        pass  # Timeout is expected for fuzzing
                        
        except Exception as e:
            print(f"[WARN] Fuzzing analysis failed: {e}")

    def check_side_channel_resistance(self):
        """Basic side-channel analysis"""
        print("[INFO] Checking side-channel resistance...")
        
        # Look for obvious side-channel issues
        for rust_file in self.rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    
                # Check for conditional secret operations
                if re.search(r'if.*secret.*{|if.*key.*{', content, re.IGNORECASE):
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if re.search(r'if.*secret.*{|if.*key.*{', line, re.IGNORECASE):
                            self.findings.append(SecurityFinding(
                                severity=SeverityLevel.HIGH,
                                category="SIDE_CHANNELS",
                                title="Secret-dependent branching",
                                description="Conditional execution based on secret data",
                                file_path=str(rust_file),
                                line_number=i,
                                code_snippet=line.strip(),
                                recommendation="Use constant-time conditional operations"
                            ))
                            
            except Exception as e:
                print(f"[WARN] Could not analyze {rust_file}: {e}")

    def run_full_audit(self):
        """Run complete security audit"""
        print("[INFO] Starting comprehensive security audit...")
        
        self.scan_rust_files()
        print(f"[INFO] Analyzing {len(self.rust_files)} Rust files...")
        
        # Run all analysis modules
        self.analyze_ffi_safety()
        self.analyze_memory_safety()
        self.analyze_error_handling()
        self.analyze_crypto_constructions()
        self.analyze_timing_vulnerabilities()
        self.check_input_validation()
        self.test_constant_time_violations()
        self.check_side_channel_resistance()
        self.test_build_security()
        self.test_dependency_security()
        self.run_fuzzing_tests()
        
        return self.generate_report()

    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("CYPHERON-CORE SECURITY AUDIT REPORT")
        print("="*80)
        
        # Count by severity
        severity_counts = {s: 0 for s in SeverityLevel}
        for finding in self.findings:
            severity_counts[finding.severity] += 1
            
        print(f"\nFINDINGS SUMMARY:")
        print(f"CRITICAL: {severity_counts[SeverityLevel.CRITICAL]}")
        print(f"HIGH:     {severity_counts[SeverityLevel.HIGH]}")
        print(f"MEDIUM:   {severity_counts[SeverityLevel.MEDIUM]}")
        print(f"LOW:      {severity_counts[SeverityLevel.LOW]}")
        print(f"INFO:     {severity_counts[SeverityLevel.INFO]}")
        print(f"TOTAL:    {len(self.findings)}")
        
        # Group by category
        by_category = {}
        for finding in self.findings:
            if finding.category not in by_category:
                by_category[finding.category] = []
            by_category[finding.category].append(finding)
            
        print(f"\nFINDINGS BY CATEGORY:")
        for category, findings in by_category.items():
            print(f"{category}: {len(findings)} issues")
            
        # Show critical and high severity findings
        critical_high = [f for f in self.findings 
                        if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        if critical_high:
            print(f"\nCRITICAL & HIGH SEVERITY ISSUES ({len(critical_high)}):")
            print("-" * 60)
            
            for i, finding in enumerate(critical_high[:10], 1):  # Limit to first 10
                print(f"\n{i}. [{finding.severity.value}] {finding.title}")
                print(f"   File: {finding.file_path}:{finding.line_number}")
                print(f"   Code: {finding.code_snippet}")
                print(f"   Issue: {finding.description}")
                print(f"   Fix: {finding.recommendation}")
                
        # Security score calculation
        score = self._calculate_security_score(severity_counts)
        print(f"\nSECURITY SCORE: {score}/10")
        print(self._get_security_recommendation(score))
        
        return {
            'score': score,
            'findings': len(self.findings),
            'critical': severity_counts[SeverityLevel.CRITICAL],
            'high': severity_counts[SeverityLevel.HIGH],
            'categories': list(by_category.keys())
        }

    def _calculate_security_score(self, counts):
        """Calculate security score based on findings"""
        score = 10.0
        score -= counts[SeverityLevel.CRITICAL] * 3.0
        score -= counts[SeverityLevel.HIGH] * 1.5
        score -= counts[SeverityLevel.MEDIUM] * 0.5
        score -= counts[SeverityLevel.LOW] * 0.1
        return max(0, min(10, score))

    def _get_security_recommendation(self, score):
        """Get recommendation based on security score"""
        if score >= 8.0:
            return "RECOMMENDATION: Suitable for production with security review"
        elif score >= 6.0:
            return "RECOMMENDATION: Suitable for staging/testing, needs security fixes"
        elif score >= 4.0:
            return "RECOMMENDATION: Development use only, significant security issues"
        elif score >= 2.0:
            return "RECOMMENDATION: Research/prototype only, major security flaws"
        else:
            return "RECOMMENDATION: UNSAFE - Do not use, fundamental security problems"

def main():
    project_root = "/home/mluna030/Project/CypheronLabs/Cypheron-core"
    
    print("Cypheron-Core Security Audit")
    print("===========================")
    
    auditor = SecurityAuditor(project_root)
    results = auditor.run_full_audit()
    
    print(f"\nAudit completed. Results summary:")
    print(f"- Total findings: {results['findings']}")
    print(f"- Critical issues: {results['critical']}")
    print(f"- High severity: {results['high']}")
    print(f"- Security score: {results['score']}/10")

if __name__ == "__main__":
    main()