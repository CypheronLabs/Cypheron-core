// Copyright 2025 Cypheron Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::process::Command;
use std::time::Instant;

pub enum TestCategory {
    KnownAnswerTests,
    PropertyBasedTests,
    TimingAnalysis,
    MemorySafety,
    SideChannelAnalysis,
    FuzzTesting,
    PerformanceBenchmarks,
}

pub struct TestResult {
    pub category: TestCategory,
    pub name: String,
    pub passed: bool,
    pub duration: std::time::Duration,
    pub details: String,
}

pub struct SecurityTestRunner {
    pub results: Vec<TestResult>,
    pub start_time: Instant,
}

impl SecurityTestRunner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            start_time: Instant::now(),
        }
    }
    
    pub fn run_all_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting Comprehensive Security Test Suite");
        println!("================================================");
        
        self.run_known_answer_tests()?;
        self.run_property_based_tests()?;
        self.run_timing_analysis_tests()?;
        self.run_memory_safety_tests()?;
        self.run_sidechannel_tests()?;
        self.run_performance_benchmarks()?;
        
        self.generate_report();
        
        Ok(())
    }
    
    fn run_known_answer_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\nRunning NIST Known Answer Tests...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["test", "--test", "kat_tests", "--", "--nocapture"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::KnownAnswerTests,
            name: "NIST KAT Tests".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("NIST Known Answer Tests: PASSED");
        } else {
            println!("NIST Known Answer Tests: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn run_property_based_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🎲 Running Property-Based Tests...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["test", "--test", "crypto_properties", "--", "--nocapture"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::PropertyBasedTests,
            name: "Cryptographic Property Tests".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("Property-Based Tests: PASSED");
        } else {
            println!("Property-Based Tests: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn run_timing_analysis_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\nRunning Timing Analysis Tests...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["test", "--test", "timing_tests", "--", "--nocapture"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::TimingAnalysis,
            name: "Timing Attack Detection".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("Timing Analysis Tests: PASSED");
        } else {
            println!("Timing Analysis Tests: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn run_memory_safety_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\nRunning Memory Safety Tests...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["test", "--test", "memory_safety_tests", "--", "--nocapture"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::MemorySafety,
            name: "Memory Safety Validation".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("Memory Safety Tests: PASSED");
        } else {
            println!("Memory Safety Tests: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn run_sidechannel_tests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n📡 Running Side-Channel Analysis Tests...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["test", "--test", "sidechannel_tests", "--", "--nocapture"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::SideChannelAnalysis,
            name: "Side-Channel Resistance".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("Side-Channel Analysis Tests: PASSED");
        } else {
            println!("Side-Channel Analysis Tests: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn run_performance_benchmarks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\nRunning Performance Benchmarks...");
        
        let start = Instant::now();
        let output = Command::new("cargo")
            .args(&["bench", "--bench", "crypto_benchmarks"])
            .output()?;
        
        let passed = output.status.success();
        let details = String::from_utf8_lossy(&output.stdout).to_string();
        
        self.results.push(TestResult {
            category: TestCategory::PerformanceBenchmarks,
            name: "Performance Regression Detection".to_string(),
            passed,
            duration: start.elapsed(),
            details,
        });
        
        if passed {
            println!("Performance Benchmarks: COMPLETED");
        } else {
            println!("Performance Benchmarks: FAILED");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    fn generate_report(&self) {
        println!("\nSecurity Test Report");
        println!("========================");
        
        let total_tests = self.results.len();
        let passed_tests = self.results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;
        
        println!("Test Summary:");
        println!("  Total Tests: {}", total_tests);
        println!("  Passed: {}", passed_tests);
        println!("  Failed: {}", failed_tests);
        println!("  Success Rate: {:.1}%", (passed_tests as f64 / total_tests as f64) * 100.0);
        println!("  Total Duration: {:?}", self.start_time.elapsed());
        
        println!("\nDetailed Results:");
        for result in &self.results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            println!("  {} {} ({:?})", status, result.name, result.duration);
            
            if !result.passed {
                println!("    Error details available in full output");
            }
        }
        
        println!("\nSecurity Assessment:");
        if failed_tests == 0 {
            println!("  STATUS: ALL SECURITY TESTS PASSED");
            println!("  The cryptographic implementation meets security requirements.");
        } else {
            println!("  STATUS: SECURITY ISSUES DETECTED");
            println!("  {} security test(s) failed. Review and fix before production use.", failed_tests);
        }
        
        println!("\nRecommendations:");
        println!("  1. Run security tests regularly in CI/CD pipeline");
        println!("  2. Monitor performance benchmarks for regressions");
        println!("  3. Update test vectors when NIST releases new versions");
        println!("  4. Consider additional fuzzing with external tools");
        println!("  5. Perform professional security audit before production");
        
        println!("\n🏁 Security test suite completed!");
    }
}

#[cfg(test)]
mod test_runner {
    use super::*;

    #[test]
    fn run_comprehensive_security_tests() {
        let mut runner = SecurityTestRunner::new();
        
        runner.run_all_tests().expect("Failed to run security tests");
        
        let failed_tests: Vec<_> = runner.results.iter()
            .filter(|r| !r.passed)
            .collect();
        
        if !failed_tests.is_empty() {
            panic!("Security tests failed: {:?}", failed_tests);
        }
    }
}
