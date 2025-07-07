pub mod analysis;
pub mod report;
pub mod utils;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub algorithm: String,
    pub operation: String,
    pub implementation: String,
    pub mean_time_ns: f64,
    pub std_dev_ns: f64,
    pub min_time_ns: f64,
    pub max_time_ns: f64,
    pub ops_per_second: f64,
    pub iterations: usize,
    pub measurement_time_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub cypheron_result: BenchmarkResult,
    pub reference_result: Option<BenchmarkResult>,
    pub performance_ratio: f64,
    pub performance_grade: PerformanceGrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceGrade {
    Excellent,  // >= 100% of reference
    Good,       // 80-99% of reference
    Acceptable, // 67-79% of reference
    Poor,       // < 67% of reference
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuite {
    pub metadata: BenchmarkMetadata,
    pub results: Vec<ComparisonResult>,
    pub summary: BenchmarkSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    pub library_name: String,
    pub version: String,
    pub test_date: String,
    pub environment: SystemEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEnvironment {
    pub cpu: String,
    pub memory_gb: f64,
    pub rust_version: String,
    pub compiler_flags: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub average_performance_ratio: f64,
    pub grade_distribution: HashMap<String, usize>,
}

impl PerformanceGrade {
    pub fn from_ratio(ratio: f64) -> Self {
        if ratio >= 1.0 {
            PerformanceGrade::Excellent
        } else if ratio >= 0.8 {
            PerformanceGrade::Good
        } else if ratio >= 0.67 {
            PerformanceGrade::Acceptable
        } else {
            PerformanceGrade::Poor
        }
    }
    
    pub fn to_string(&self) -> &'static str {
        match self {
            PerformanceGrade::Excellent => "Excellent",
            PerformanceGrade::Good => "Good",
            PerformanceGrade::Acceptable => "Acceptable",
            PerformanceGrade::Poor => "Poor",
        }
    }
}

pub fn calculate_ops_per_second(mean_time_ns: f64) -> f64 {
    if mean_time_ns > 0.0 {
        1_000_000_000.0 / mean_time_ns
    } else {
        0.0
    }
}

pub fn calculate_performance_ratio(cypheron_ops: f64, reference_ops: f64) -> f64 {
    if reference_ops > 0.0 {
        cypheron_ops / reference_ops
    } else {
        0.0
    }
}