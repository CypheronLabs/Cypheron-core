use crate::{BenchmarkResult, ComparisonResult, PerformanceGrade, calculate_performance_ratio};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalAnalysis {
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub coefficient_of_variation: f64,
    pub confidence_interval_95: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub algorithm: String,
    pub security_level: u8,
    pub key_size_bytes: usize,
    pub signature_size_bytes: Option<usize>,
    pub ciphertext_size_bytes: Option<usize>,
    pub performance_per_security_level: f64,
    pub performance_per_key_byte: f64,
}

pub fn analyze_performance_distribution(results: &[ComparisonResult]) -> HashMap<String, StatisticalAnalysis> {
    let mut analysis = HashMap::new();
    
    // Group results by algorithm
    let mut algorithm_groups: HashMap<String, Vec<f64>> = HashMap::new();
    
    for result in results {
        let key = format!("{}_{}", result.cypheron_result.algorithm, result.cypheron_result.operation);
        algorithm_groups.entry(key).or_insert_with(Vec::new).push(result.cypheron_result.ops_per_second);
    }
    
    // Calculate statistics for each algorithm group
    for (algorithm, ops_data) in algorithm_groups {
        if !ops_data.is_empty() {
            let stats = calculate_statistics(&ops_data);
            analysis.insert(algorithm, stats);
        }
    }
    
    analysis
}

pub fn calculate_statistics(data: &[f64]) -> StatisticalAnalysis {
    if data.is_empty() {
        return StatisticalAnalysis {
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
            min: 0.0,
            max: 0.0,
            coefficient_of_variation: 0.0,
            confidence_interval_95: (0.0, 0.0),
        };
    }
    
    let mut sorted_data = data.to_vec();
    sorted_data.sort_by(|a, b| a.partial_cmp(b).unwrap());
    
    let n = sorted_data.len();
    let mean = sorted_data.iter().sum::<f64>() / n as f64;
    
    let median = if n % 2 == 0 {
        (sorted_data[n/2 - 1] + sorted_data[n/2]) / 2.0
    } else {
        sorted_data[n/2]
    };
    
    let variance = sorted_data.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>() / (n - 1) as f64;
    
    let std_dev = variance.sqrt();
    
    let coefficient_of_variation = if mean != 0.0 {
        (std_dev / mean) * 100.0
    } else {
        0.0
    };
    
    // 95% confidence interval (assuming normal distribution)
    let margin_of_error = 1.96 * (std_dev / (n as f64).sqrt());
    let confidence_interval_95 = (mean - margin_of_error, mean + margin_of_error);
    
    StatisticalAnalysis {
        mean,
        median,
        std_dev,
        min: sorted_data[0],
        max: sorted_data[n - 1],
        coefficient_of_variation,
        confidence_interval_95,
    }
}

pub fn analyze_security_performance_trends(results: &[ComparisonResult]) -> Vec<TrendAnalysis> {
    let mut trends = Vec::new();
    
    // Define algorithm metadata
    let algorithm_metadata = get_algorithm_metadata();
    
    for result in results {
        if let Some(metadata) = algorithm_metadata.get(&result.cypheron_result.algorithm) {
            let performance_per_security_level = result.cypheron_result.ops_per_second / metadata.security_level as f64;
            let performance_per_key_byte = result.cypheron_result.ops_per_second / metadata.key_size_bytes as f64;
            
            trends.push(TrendAnalysis {
                algorithm: result.cypheron_result.algorithm.clone(),
                security_level: metadata.security_level,
                key_size_bytes: metadata.key_size_bytes,
                signature_size_bytes: metadata.signature_size_bytes,
                ciphertext_size_bytes: metadata.ciphertext_size_bytes,
                performance_per_security_level,
                performance_per_key_byte,
            });
        }
    }
    
    trends
}

#[derive(Debug, Clone)]
struct AlgorithmMetadata {
    security_level: u8,
    key_size_bytes: usize,
    signature_size_bytes: Option<usize>,
    ciphertext_size_bytes: Option<usize>,
}

fn get_algorithm_metadata() -> HashMap<String, AlgorithmMetadata> {
    let mut metadata = HashMap::new();
    
    // ML-KEM (Kyber) metadata
    metadata.insert("ML-KEM-512".to_string(), AlgorithmMetadata {
        security_level: 1,
        key_size_bytes: 800,
        signature_size_bytes: None,
        ciphertext_size_bytes: Some(768),
    });
    
    metadata.insert("ML-KEM-768".to_string(), AlgorithmMetadata {
        security_level: 3,
        key_size_bytes: 1184,
        signature_size_bytes: None,
        ciphertext_size_bytes: Some(1088),
    });
    
    metadata.insert("ML-KEM-1024".to_string(), AlgorithmMetadata {
        security_level: 5,
        key_size_bytes: 1568,
        signature_size_bytes: None,
        ciphertext_size_bytes: Some(1568),
    });
    
    // ML-DSA (Dilithium) metadata
    metadata.insert("ML-DSA-44".to_string(), AlgorithmMetadata {
        security_level: 2,
        key_size_bytes: 1312,
        signature_size_bytes: Some(2420),
        ciphertext_size_bytes: None,
    });
    
    metadata.insert("ML-DSA-65".to_string(), AlgorithmMetadata {
        security_level: 3,
        key_size_bytes: 1952,
        signature_size_bytes: Some(3293),
        ciphertext_size_bytes: None,
    });
    
    metadata.insert("ML-DSA-87".to_string(), AlgorithmMetadata {
        security_level: 5,
        key_size_bytes: 2592,
        signature_size_bytes: Some(4595),
        ciphertext_size_bytes: None,
    });
    
    metadata
}

pub fn identify_performance_outliers(results: &[ComparisonResult], threshold: f64) -> Vec<&ComparisonResult> {
    let ratios: Vec<f64> = results.iter().map(|r| r.performance_ratio).collect();
    
    if ratios.is_empty() {
        return Vec::new();
    }
    
    let stats = calculate_statistics(&ratios);
    let outlier_threshold = stats.mean - (threshold * stats.std_dev);
    
    results.iter()
        .filter(|r| r.performance_ratio < outlier_threshold)
        .collect()
}

pub fn calculate_confidence_scores(results: &[ComparisonResult]) -> HashMap<String, f64> {
    let mut confidence_scores = HashMap::new();
    
    for result in results {
        let cv = (result.cypheron_result.std_dev_ns / result.cypheron_result.mean_time_ns) * 100.0;
        
        // Confidence score based on coefficient of variation
        let confidence = if cv < 1.0 {
            100.0
        } else if cv < 5.0 {
            90.0
        } else if cv < 10.0 {
            75.0
        } else if cv < 20.0 {
            60.0
        } else {
            40.0
        };
        
        let key = format!("{}_{}", result.cypheron_result.algorithm, result.cypheron_result.operation);
        confidence_scores.insert(key, confidence);
    }
    
    confidence_scores
}