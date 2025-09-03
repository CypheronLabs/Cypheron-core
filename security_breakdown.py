#!/usr/bin/env python3
"""
Detailed Security Issue Breakdown
Generates specific, actionable tasks for security remediation
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass 
class SpecificIssue:
    file_path: str
    line_number: int
    issue_type: str
    code_snippet: str
    specific_fix: str
    priority: str

class SecurityBreakdown:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.issues: List[SpecificIssue] = []
        
    def analyze_ffi_validation_gaps(self):
        """Find specific FFI calls missing validation"""
        print("[INFO] Analyzing FFI validation gaps...")
        
        rust_files = list(self.project_root.glob("**/*.rs"))
        rust_files = [f for f in rust_files if 'target/' not in str(f) and 'vendor/' not in str(f)]
        
        for rust_file in rust_files:
            try:
                with open(rust_file, 'r') as f:
                    lines = f.readlines()
                    
                for i, line in enumerate(lines, 1):
                    # Find FFI calls without validation
                    if re.search(r'unsafe.*\{.*pqcrystals_.*\(', line):
                        # Check if there's validation before this line
                        prev_lines = lines[max(0, i-5):i-1]
                        has_validation = any(
                            any(check in pline.lower() for check in 
                                ['validate', 'check', 'len()', 'is_empty()', 'bounds'])
                            for pline in prev_lines
                        )
                        
                        if not has_validation:
                            self.issues.append(SpecificIssue(
                                file_path=str(rust_file.relative_to(self.project_root)),
                                line_number=i,
                                issue_type="FFI_NO_VALIDATION",
                                code_snippet=line.strip(),
                                specific_fix=f"Add buffer validation before line {i}",
                                priority="HIGH"
                            ))
                            
            except Exception as e:
                continue

    def find_unwrap_instances(self):
        """Find all unwrap/expect instances that need fixing"""
        print("[INFO] Finding unwrap/expect instances...")
        
        rust_files = list(self.project_root.glob("**/*.rs"))
        rust_files = [f for f in rust_files if 'target/' not in str(f) and 'vendor/' not in str(f)]
        
        for rust_file in rust_files:
            try:
                with open(rust_file, 'r') as f:
                    lines = f.readlines()
                    
                for i, line in enumerate(lines, 1):
                    if '.unwrap()' in line or '.expect(' in line:
                        # Determine if this is in a crypto-critical path
                        context = ''.join(lines[max(0, i-3):i+3]).lower()
                        
                        is_crypto_critical = any(word in context for word in [
                            'keypair', 'sign', 'verify', 'encrypt', 'decrypt', 
                            'encapsulate', 'decapsulate', 'secret', 'key'
                        ])
                        
                        priority = "HIGH" if is_crypto_critical else "MEDIUM"
                        
                        self.issues.append(SpecificIssue(
                            file_path=str(rust_file.relative_to(self.project_root)),
                            line_number=i,
                            issue_type="ERROR_HANDLING",
                            code_snippet=line.strip(),
                            specific_fix="Replace with proper Result propagation",
                            priority=priority
                        ))
                        
            except Exception as e:
                continue

    def find_timing_vulnerabilities(self):
        """Find specific timing attack vulnerabilities"""
        print("[INFO] Finding timing vulnerabilities...")
        
        crypto_files = []
        for pattern in ["**/kem/*.rs", "**/sig/*.rs", "**/hybrid/*.rs"]:
            crypto_files.extend(self.project_root.glob(pattern))
            
        for rust_file in crypto_files:
            try:
                with open(rust_file, 'r') as f:
                    lines = f.readlines()
                    
                for i, line in enumerate(lines, 1):
                    # Check for secret-dependent operations
                    if re.search(r'if.*secret|if.*key|match.*key', line.lower()):
                        self.issues.append(SpecificIssue(
                            file_path=str(rust_file.relative_to(self.project_root)),
                            line_number=i,
                            issue_type="TIMING_ATTACK",
                            code_snippet=line.strip(),
                            specific_fix="Replace with constant-time conditional",
                            priority="HIGH"
                        ))
                        
                    # Check for variable-time operations on secrets
                    if re.search(r'\.find\(|\.contains\(|\.iter\(\)', line):
                        context = ''.join(lines[max(0, i-2):i+2]).lower()
                        if any(word in context for word in ['secret', 'key', 'signature']):
                            self.issues.append(SpecificIssue(
                                file_path=str(rust_file.relative_to(self.project_root)),
                                line_number=i,
                                issue_type="TIMING_ATTACK",
                                code_snippet=line.strip(),
                                specific_fix="Use constant-time algorithm",
                                priority="HIGH"
                            ))
                            
            except Exception as e:
                continue

    def find_input_validation_gaps(self):
        """Find specific input validation gaps"""
        print("[INFO] Finding input validation gaps...")
        
        rust_files = list(self.project_root.glob("**/*.rs"))
        rust_files = [f for f in rust_files if 'target/' not in str(f) and 'vendor/' not in str(f)]
        
        for rust_file in rust_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    # Find public functions taking byte arrays
                    if re.search(r'pub\s+fn.*\([^)]*&\[u8\]', line):
                        func_name = re.search(r'fn\s+(\w+)', line)
                        if func_name:
                            # Check for validation in function body
                            func_lines = lines[i:i+20]  # Next 20 lines
                            has_validation = any(
                                any(check in fline.lower() for check in 
                                    ['validate', 'len()', 'is_empty()', 'bounds', 'size'])
                                for fline in func_lines
                            )
                            
                            if not has_validation:
                                self.issues.append(SpecificIssue(
                                    file_path=str(rust_file.relative_to(self.project_root)),
                                    line_number=i,
                                    issue_type="INPUT_VALIDATION",
                                    code_snippet=line.strip(),
                                    specific_fix=f"Add input validation to {func_name.group(1)}()",
                                    priority="HIGH"
                                ))
                                
            except Exception as e:
                continue

    def analyze_memory_operations(self):
        """Find specific unsafe memory operations"""
        print("[INFO] Analyzing unsafe memory operations...")
        
        dangerous_ops = [
            ('mprotect', 'Add alignment validation'),
            ('syscall', 'Add syscall parameter validation'),  
            ('explicit_bzero', 'Verify buffer validity'),
            ('transmute', 'Replace with safe alternative'),
            ('from_raw', 'Add null pointer checks'),
        ]
        
        rust_files = list(self.project_root.glob("**/*.rs"))
        rust_files = [f for f in rust_files if 'target/' not in str(f) and 'vendor/' not in str(f)]
        
        for rust_file in rust_files:
            try:
                with open(rust_file, 'r') as f:
                    lines = f.readlines()
                    
                for i, line in enumerate(lines, 1):
                    for op, fix in dangerous_ops:
                        if op in line and 'unsafe' in line:
                            self.issues.append(SpecificIssue(
                                file_path=str(rust_file.relative_to(self.project_root)),
                                line_number=i,
                                issue_type="MEMORY_SAFETY",
                                code_snippet=line.strip(),
                                specific_fix=fix,
                                priority="CRITICAL" if op in ['mprotect', 'syscall'] else "HIGH"
                            ))
                            
            except Exception as e:
                continue

    def find_crypto_construction_issues(self):
        """Find cryptographic construction problems"""
        print("[INFO] Finding crypto construction issues...")
        
        hybrid_files = list(self.project_root.glob("**/hybrid/*.rs"))
        
        for rust_file in hybrid_files:
            try:
                with open(rust_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for i, line in enumerate(lines, 1):
                    # Check for weak HKDF usage
                    if 'Hkdf' in line and 'None' in line:
                        self.issues.append(SpecificIssue(
                            file_path=str(rust_file.relative_to(self.project_root)),
                            line_number=i,
                            issue_type="CRYPTO_CONSTRUCTION",
                            code_snippet=line.strip(),
                            specific_fix="Use proper random salt for HKDF",
                            priority="HIGH"
                        ))
                        
                    # Check for hardcoded context strings
                    if re.search(r'b".*Cypheron.*"', line):
                        self.issues.append(SpecificIssue(
                            file_path=str(rust_file.relative_to(self.project_root)),
                            line_number=i,
                            issue_type="CRYPTO_CONSTRUCTION", 
                            code_snippet=line.strip(),
                            specific_fix="Use versioned, domain-separated context",
                            priority="MEDIUM"
                        ))
                        
            except Exception as e:
                continue

    def generate_actionable_todos(self):
        """Generate prioritized, actionable todo list"""
        
        # Collect all issues
        self.analyze_ffi_validation_gaps()
        self.find_unwrap_instances() 
        self.find_timing_vulnerabilities()
        self.find_input_validation_gaps()
        self.analyze_memory_operations()
        self.find_crypto_construction_issues()
        
        # Group by priority and type
        critical_issues = [i for i in self.issues if i.priority == "CRITICAL"]
        high_issues = [i for i in self.issues if i.priority == "HIGH"]
        medium_issues = [i for i in self.issues if i.priority == "MEDIUM"]
        
        print("\n" + "="*80)
        print("COMPREHENSIVE SECURITY TODO LIST")
        print("="*80)
        
        print(f"\nPRIORITY BREAKDOWN:")
        print(f"CRITICAL: {len(critical_issues)} issues")
        print(f"HIGH:     {len(high_issues)} issues") 
        print(f"MEDIUM:   {len(medium_issues)} issues")
        print(f"TOTAL:    {len(self.issues)} specific issues")
        
        # Generate top 50 most critical fixes
        all_issues = critical_issues + high_issues + medium_issues
        
        print(f"\nTOP 50 SPECIFIC FIXES NEEDED:")
        print("-" * 50)
        
        for i, issue in enumerate(all_issues[:50], 1):
            print(f"{i}. [{issue.priority}] {issue.file_path}:{issue.line_number}")
            print(f"   Issue: {issue.issue_type}")
            print(f"   Code: {issue.code_snippet}")
            print(f"   Fix: {issue.specific_fix}")
            print()
        
        # Group by file for easier fixing
        by_file = {}
        for issue in all_issues:
            if issue.file_path not in by_file:
                by_file[issue.file_path] = []
            by_file[issue.file_path].append(issue)
            
        print(f"\nFILES NEEDING IMMEDIATE ATTENTION:")
        print("-" * 40)
        
        # Sort files by number of critical/high issues
        sorted_files = sorted(by_file.items(), 
                            key=lambda x: len([i for i in x[1] if i.priority in ["CRITICAL", "HIGH"]]),
                            reverse=True)
        
        for file_path, file_issues in sorted_files[:10]:
            critical_high = len([i for i in file_issues if i.priority in ["CRITICAL", "HIGH"]])
            if critical_high > 0:
                print(f"{file_path}: {critical_high} critical/high issues")
                
        return {
            'total_issues': len(self.issues),
            'critical': len(critical_issues),
            'high': len(high_issues), 
            'medium': len(medium_issues),
            'files_affected': len(by_file),
            'top_files': [f[0] for f in sorted_files[:10]]
        }

def main():
    project_root = "/home/mluna030/Project/CypheronLabs/Cypheron-core"
    
    breakdown = SecurityBreakdown(project_root)
    results = breakdown.generate_actionable_todos()
    
    print(f"\n{'='*80}")
    print("SUMMARY FOR IMMEDIATE ACTION")
    print(f"{'='*80}")
    print(f"Total specific issues found: {results['total_issues']}")
    print(f"Files requiring immediate attention: {results['files_affected']}")
    print(f"Critical issues: {results['critical']}")
    print(f"High severity issues: {results['high']}")
    print(f"\nStart with these files: {', '.join(results['top_files'][:3])}")

if __name__ == "__main__":
    main()