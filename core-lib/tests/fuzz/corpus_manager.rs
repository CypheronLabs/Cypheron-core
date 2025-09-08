use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde_json;

pub struct CorpusManager {
    pub base_path: PathBuf,
    pub algorithms: Vec<String>,
    pub corpus_stats: HashMap<String, CorpusStats>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CorpusStats {
    pub total_inputs: usize,
    pub unique_crashes: usize,
    pub coverage_percentage: f64,
    pub last_updated: SystemTime,
    pub input_categories: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct FuzzTarget {
    pub name: String,
    pub algorithm: String,
    pub priority: FuzzPriority,
    pub expected_input_sizes: Vec<usize>,
    pub corpus_path: PathBuf,
    pub crashes_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FuzzPriority {
    Critical,   // Core crypto operations
    High,       // Edge cases, malformed inputs
    Medium,     // Performance stress tests
    Low,        // Compatibility tests
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrashType {
    BufferOverflow,
    OutOfBounds,
    NullPointer,
    EmptyInput,
    SingleByte,
    AllZeros,
    AllOnes,
    LargeInput,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub enum CrashSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct CrashAnalysis {
    pub file_name: String,
    pub algorithm: String,
    pub crash_type: CrashType,
    pub severity: CrashSeverity,
    pub input_size: usize,
    pub description: String,
    pub discovered_at: SystemTime,
}

impl CorpusManager {
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let base_path = base_path.as_ref().to_path_buf();
        let algorithms = vec![
            "ml_kem_512".to_string(),
            "ml_kem_768".to_string(), 
            "ml_kem_1024".to_string(),
            "ml_dsa_44".to_string(),
            "ml_dsa_65".to_string(),
            "ml_dsa_87".to_string(),
            "hybrid_ecc_dilithium".to_string(),
        ];
        
        Self {
            base_path,
            algorithms,
            corpus_stats: HashMap::new(),
        }
    }
    
    pub fn initialize_corpus_structure(&mut self) -> Result<(), std::io::Error> {
        println!("Initializing corpus directory structure...");
        
        // Create base directories
        fs::create_dir_all(&self.base_path)?;
        fs::create_dir_all(self.base_path.join("corpus"))?;
        fs::create_dir_all(self.base_path.join("crashes"))?;
        fs::create_dir_all(self.base_path.join("coverage"))?;
        fs::create_dir_all(self.base_path.join("artifacts"))?;
        fs::create_dir_all(self.base_path.join("logs"))?;
        
        // Create algorithm-specific directories
        for algorithm in &self.algorithms {
            let corpus_dir = self.base_path.join("corpus").join(algorithm);
            let crashes_dir = self.base_path.join("crashes").join(algorithm);
            let coverage_dir = self.base_path.join("coverage").join(algorithm);
            
            fs::create_dir_all(&corpus_dir)?;
            fs::create_dir_all(&crashes_dir)?;
            fs::create_dir_all(&coverage_dir)?;
            
            // Create input category subdirectories
            let categories = [
                "valid_inputs",      // Valid cryptographic inputs
                "malformed_inputs",  // Invalid/corrupted inputs  
                "edge_cases",        // Boundary conditions
                "stress_tests",      // Resource exhaustion
                "regression_tests",  // Previously found issues
            ];
            
            for category in &categories {
                fs::create_dir_all(corpus_dir.join(category))?;
            }
        }
        
        println!("[SUCCESS] Corpus structure initialized for {} algorithms", self.algorithms.len());
        Ok(())
    }
    
    pub fn generate_seed_corpus(&mut self) -> Result<(), std::io::Error> {
        println!("Generating seed corpus for all algorithms...");
        
        for algorithm in &self.algorithms.clone() {
            self.generate_algorithm_seeds(algorithm)?;
        }
        
        Ok(())
    }
    
    fn generate_algorithm_seeds(&mut self, algorithm: &str) -> Result<(), std::io::Error> {
        let corpus_base = self.base_path.join("corpus").join(algorithm);
        
        match algorithm {
            "ml_kem_512" => self.generate_kem_seeds(&corpus_base, 800, 1632, 768)?,
            "ml_kem_768" => self.generate_kem_seeds(&corpus_base, 1184, 2400, 1088)?,
            "ml_kem_1024" => self.generate_kem_seeds(&corpus_base, 1568, 3168, 1568)?,
            "ml_dsa_44" => self.generate_dsa_seeds(&corpus_base, 1312, 2528, 2420)?,
            "ml_dsa_65" => self.generate_dsa_seeds(&corpus_base, 1952, 4000, 3309)?,
            "ml_dsa_87" => self.generate_dsa_seeds(&corpus_base, 2592, 4896, 4627)?,
            "hybrid_ecc_dilithium" => self.generate_hybrid_seeds(&corpus_base)?,
            _ => println!("[WARNING]  Unknown algorithm: {}", algorithm),
        }
        
        Ok(())
    }
    
    fn generate_kem_seeds(&self, base_path: &Path, pk_size: usize, sk_size: usize, ct_size: usize) -> Result<(), std::io::Error> {
        // Valid inputs
        self.write_seed(base_path.join("valid_inputs/empty.bin"), &[])?;
        self.write_seed(base_path.join("valid_inputs/single_byte.bin"), &[0x42])?;
        
        // Public key seeds  
        self.write_seed(base_path.join("valid_inputs/pk_zeros.bin"), &vec![0u8; pk_size])?;
        self.write_seed(base_path.join("valid_inputs/pk_ones.bin"), &vec![0xFFu8; pk_size])?;
        self.write_seed(base_path.join("valid_inputs/pk_sequential.bin"), 
                       &(0..pk_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>())?;
        
        // Ciphertext seeds
        self.write_seed(base_path.join("valid_inputs/ct_zeros.bin"), &vec![0u8; ct_size])?;
        self.write_seed(base_path.join("valid_inputs/ct_ones.bin"), &vec![0xFFu8; ct_size])?;
        
        // Malformed inputs
        self.write_seed(base_path.join("malformed_inputs/ct_short.bin"), &vec![0u8; ct_size - 1])?;
        self.write_seed(base_path.join("malformed_inputs/ct_long.bin"), &vec![0u8; ct_size + 1])?;
        self.write_seed(base_path.join("malformed_inputs/pk_short.bin"), &vec![0u8; pk_size - 1])?;
        self.write_seed(base_path.join("malformed_inputs/pk_long.bin"), &vec![0u8; pk_size + 1])?;
        
        // Edge cases
        self.write_seed(base_path.join("edge_cases/boundary_minus_1.bin"), &vec![0u8; ct_size - 1])?;
        self.write_seed(base_path.join("edge_cases/boundary_plus_1.bin"), &vec![0u8; ct_size + 1])?;
        
        // Stress tests
        self.write_seed(base_path.join("stress_tests/large_input.bin"), &vec![0x5A; 65536])?;
        
        Ok(())
    }
    
    fn generate_dsa_seeds(&self, base_path: &Path, pk_size: usize, sk_size: usize, sig_size: usize) -> Result<(), std::io::Error> {
        // Message seeds of various sizes
        let message_sizes = [0, 1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
        
        for &size in &message_sizes {
            self.write_seed(base_path.join(format!("valid_inputs/msg_{}_bytes.bin", size)), 
                           &vec![0x42u8; size])?;
        }
        
        // Signature seeds
        self.write_seed(base_path.join("valid_inputs/sig_zeros.bin"), &vec![0u8; sig_size])?;
        self.write_seed(base_path.join("valid_inputs/sig_ones.bin"), &vec![0xFFu8; sig_size])?;
        
        // Public key seeds
        self.write_seed(base_path.join("valid_inputs/pk_zeros.bin"), &vec![0u8; pk_size])?;
        self.write_seed(base_path.join("valid_inputs/pk_pattern.bin"), 
                       &(0..pk_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>())?;
        
        // Malformed inputs
        self.write_seed(base_path.join("malformed_inputs/sig_short.bin"), &vec![0u8; sig_size - 1])?;
        self.write_seed(base_path.join("malformed_inputs/sig_long.bin"), &vec![0u8; sig_size + 1])?;
        
        // Edge cases with special message patterns
        self.write_seed(base_path.join("edge_cases/null_bytes.bin"), &vec![0u8; 256])?;
        self.write_seed(base_path.join("edge_cases/high_bytes.bin"), &vec![0xFFu8; 256])?;
        self.write_seed(base_path.join("edge_cases/alternating.bin"), 
                       &(0..256).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect::<Vec<u8>>())?;
        
        Ok(())
    }
    
    fn generate_hybrid_seeds(&self, base_path: &Path) -> Result<(), std::io::Error> {
        // Hybrid scheme combines ECC and Dilithium
        let message_sizes = [0, 1, 32, 64, 128, 256, 512, 1024, 2048, 4096];
        
        for &size in &message_sizes {
            self.write_seed(base_path.join(format!("valid_inputs/hybrid_msg_{}.bin", size)), 
                           &vec![0x33u8; size])?;
        }
        
        // Stress tests with large messages
        self.write_seed(base_path.join("stress_tests/hybrid_large.bin"), &vec![0x77u8; 32768])?;
        
        // Edge cases specific to hybrid schemes
        self.write_seed(base_path.join("edge_cases/hybrid_empty.bin"), &[])?;
        self.write_seed(base_path.join("edge_cases/hybrid_single.bin"), &[0x99])?;
        
        Ok(())
    }
    
    fn write_seed(&self, path: PathBuf, data: &[u8]) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)
    }
    
    pub fn get_fuzz_targets(&self) -> Vec<FuzzTarget> {
        vec![
            FuzzTarget {
                name: "fuzz_ml_kem_512".to_string(),
                algorithm: "ml_kem_512".to_string(),
                priority: FuzzPriority::Critical,
                expected_input_sizes: vec![800, 1632, 768],
                corpus_path: self.base_path.join("corpus/ml_kem_512"),
                crashes_path: self.base_path.join("crashes/ml_kem_512"),
            },
            FuzzTarget {
                name: "fuzz_ml_kem_768".to_string(),
                algorithm: "ml_kem_768".to_string(),
                priority: FuzzPriority::Critical,
                expected_input_sizes: vec![1184, 2400, 1088],
                corpus_path: self.base_path.join("corpus/ml_kem_768"),
                crashes_path: self.base_path.join("crashes/ml_kem_768"),
            },
            FuzzTarget {
                name: "fuzz_ml_kem_1024".to_string(),
                algorithm: "ml_kem_1024".to_string(),
                priority: FuzzPriority::Critical,
                expected_input_sizes: vec![1568, 3168, 1568],
                corpus_path: self.base_path.join("corpus/ml_kem_1024"),
                crashes_path: self.base_path.join("crashes/ml_kem_1024"),
            },
            FuzzTarget {
                name: "fuzz_ml_dsa_44".to_string(),
                algorithm: "ml_dsa_44".to_string(),
                priority: FuzzPriority::Critical,
                expected_input_sizes: vec![1312, 2528, 2420],
                corpus_path: self.base_path.join("corpus/ml_dsa_44"),
                crashes_path: self.base_path.join("crashes/ml_dsa_44"),
            },
            FuzzTarget {
                name: "fuzz_ml_dsa_65".to_string(),
                algorithm: "ml_dsa_65".to_string(),
                priority: FuzzPriority::High,
                expected_input_sizes: vec![1952, 4000, 3309],
                corpus_path: self.base_path.join("corpus/ml_dsa_65"),
                crashes_path: self.base_path.join("crashes/ml_dsa_65"),
            },
            FuzzTarget {
                name: "fuzz_ml_dsa_87".to_string(),
                algorithm: "ml_dsa_87".to_string(),
                priority: FuzzPriority::High,
                expected_input_sizes: vec![2592, 4896, 4627],
                corpus_path: self.base_path.join("corpus/ml_dsa_87"),
                crashes_path: self.base_path.join("crashes/ml_dsa_87"),
            },
            FuzzTarget {
                name: "fuzz_hybrid_ecc_dilithium".to_string(),
                algorithm: "hybrid_ecc_dilithium".to_string(),
                priority: FuzzPriority::Medium,
                expected_input_sizes: vec![32, 64, 128, 256, 512, 1024],
                corpus_path: self.base_path.join("corpus/hybrid_ecc_dilithium"),
                crashes_path: self.base_path.join("crashes/hybrid_ecc_dilithium"),
            },
        ]
    }
    
    pub fn update_corpus_stats(&mut self, algorithm: &str) -> Result<(), std::io::Error> {
        let corpus_path = self.base_path.join("corpus").join(algorithm);
        let crashes_path = self.base_path.join("crashes").join(algorithm);
        
        let mut total_inputs = 0;
        let mut input_categories = HashMap::new();
        
        // Count inputs by category
        for category in ["valid_inputs", "malformed_inputs", "edge_cases", "stress_tests", "regression_tests"] {
            let category_path = corpus_path.join(category);
            if category_path.exists() {
                let count = fs::read_dir(category_path)?.count();
                input_categories.insert(category.to_string(), count);
                total_inputs += count;
            }
        }
        
        // Count crashes
        let unique_crashes = if crashes_path.exists() {
            fs::read_dir(crashes_path)?.count()
        } else {
            0
        };
        
        // Calculate basic coverage percentage (placeholder for now)
        let coverage_percentage = self.estimate_coverage_percentage(algorithm, total_inputs);
        
        let stats = CorpusStats {
            total_inputs,
            unique_crashes,
            coverage_percentage,
            last_updated: SystemTime::now(),
            input_categories,
        };
        
        self.corpus_stats.insert(algorithm.to_string(), stats);
        Ok(())
    }
    
    /// Estimate coverage percentage based on input diversity and algorithm complexity
    fn estimate_coverage_percentage(&self, algorithm: &str, total_inputs: usize) -> f64 {
        if total_inputs == 0 {
            return 0.0;
        }
        
        // Base coverage estimation based on input count and algorithm complexity
        let base_coverage = match algorithm {
            "ml_kem_512" | "ml_kem_768" | "ml_kem_1024" => {
                // KEM algorithms have encapsulation/decapsulation paths
                (total_inputs as f64 * 0.15).min(85.0)
            },
            "ml_dsa_44" | "ml_dsa_65" | "ml_dsa_87" => {
                // DSA algorithms have signing/verification paths  
                (total_inputs as f64 * 0.12).min(80.0)
            },
            "hybrid_ecc_dilithium" => {
                // Hybrid schemes have more complex paths
                (total_inputs as f64 * 0.10).min(75.0)
            },
            _ => (total_inputs as f64 * 0.08).min(70.0),
        };
        
        base_coverage
    }
    
    pub fn run_fuzzing_campaign(&mut self, algorithm: &str, duration_minutes: u32) -> Result<(), std::io::Error> {
        println!("Starting fuzzing campaign for {} (duration: {} minutes)", algorithm, duration_minutes);
        
        // Ensure corpus exists and is up to date
        self.initialize_corpus_structure()?;
        self.generate_algorithm_seeds(algorithm)?;
        
        let target = self.get_fuzz_targets().into_iter()
            .find(|t| t.algorithm == algorithm)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound, 
                format!("No fuzz target found for algorithm: {}", algorithm)
            ))?;
        
        println!("[INFO] Target: {} (Priority: {:?})", target.name, target.priority);
        println!("Corpus: {}", target.corpus_path.display());
        println!("Crashes: {}", target.crashes_path.display());
        
        // Update stats before starting
        self.update_corpus_stats(algorithm)?;
        
        if let Some(stats) = self.corpus_stats.get(algorithm) {
            println!("Initial corpus: {} inputs, {} crashes", stats.total_inputs, stats.unique_crashes);
        }
        
        println!("Campaign would run for {} minutes with libfuzzer", duration_minutes);
        println!("[NOTE] To actually run fuzzing, execute:");
        println!("   cargo fuzz run {} -- -max_total_time={}", target.name, duration_minutes * 60);
        
        Ok(())
    }
    
    pub fn analyze_crashes(&mut self, algorithm: &str) -> Result<Vec<CrashAnalysis>, std::io::Error> {
        let crashes_path = self.base_path.join("crashes").join(algorithm);
        let mut analyses = Vec::new();
        
        if !crashes_path.exists() {
            return Ok(analyses);
        }
        
        for entry in fs::read_dir(crashes_path)? {
            let entry = entry?;
            let crash_file = entry.path();
            
            if crash_file.is_file() {
                let crash_data = fs::read(&crash_file)?;
                let analysis = self.analyze_single_crash(algorithm, &crash_file, &crash_data);
                analyses.push(analysis);
            }
        }
        
        analyses.sort_by(|a, b| b.severity.cmp(&a.severity));
        Ok(analyses)
    }
    
    fn analyze_single_crash(&self, algorithm: &str, crash_file: &std::path::Path, crash_data: &[u8]) -> CrashAnalysis {
        let file_name = crash_file.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
            
        // Basic crash analysis based on data characteristics
        let mut severity = CrashSeverity::Medium;
        let mut crash_type = CrashType::Unknown;
        let mut description = String::new();
        
        // Analyze crash data patterns
        if crash_data.is_empty() {
            crash_type = CrashType::EmptyInput;
            description = "Crash triggered by empty input".to_string();
            severity = CrashSeverity::Low;
        } else if crash_data.len() == 1 {
            crash_type = CrashType::SingleByte;
            description = format!("Crash triggered by single byte: 0x{:02X}", crash_data[0]);
            severity = CrashSeverity::Medium;
        } else if crash_data.iter().all(|&b| b == 0) {
            crash_type = CrashType::AllZeros;
            description = "Crash triggered by all-zero input".to_string();
            severity = CrashSeverity::Medium;
        } else if crash_data.iter().all(|&b| b == 0xFF) {
            crash_type = CrashType::AllOnes;
            description = "Crash triggered by all-ones input".to_string();
            severity = CrashSeverity::Medium;
        } else {
            // Check for buffer overflow indicators
            let expected_sizes = self.get_expected_sizes_for_algorithm(algorithm);
            if expected_sizes.iter().any(|&size| crash_data.len() == size + 1) {
                crash_type = CrashType::BufferOverflow;
                description = "Potential buffer overflow - input size off by one".to_string();
                severity = CrashSeverity::High;
            } else if crash_data.len() > 100000 {
                crash_type = CrashType::LargeInput;
                description = "Crash triggered by unexpectedly large input".to_string();
                severity = CrashSeverity::High;
            } else {
                crash_type = CrashType::Unknown;
                description = format!("Crash with {} byte input", crash_data.len());
            }
        }
        
        CrashAnalysis {
            file_name,
            algorithm: algorithm.to_string(),
            crash_type,
            severity,
            input_size: crash_data.len(),
            description,
            discovered_at: SystemTime::now(),
        }
    }
    
    fn get_expected_sizes_for_algorithm(&self, algorithm: &str) -> Vec<usize> {
        match algorithm {
            "ml_kem_512" => vec![800, 1632, 768],
            "ml_kem_768" => vec![1184, 2400, 1088], 
            "ml_kem_1024" => vec![1568, 3168, 1568],
            "ml_dsa_44" => vec![1312, 2528, 2420],
            "ml_dsa_65" => vec![1952, 4000, 3309],
            "ml_dsa_87" => vec![2592, 4896, 4627],
            _ => vec![32, 64, 128, 256, 512, 1024],
        }
    }
    
    pub fn generate_coverage_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# Fuzzing Coverage Report\n\n");
        
        let total_algorithms = self.corpus_stats.len();
        let total_inputs: usize = self.corpus_stats.values().map(|s| s.total_inputs).sum();
        let total_crashes: usize = self.corpus_stats.values().map(|s| s.unique_crashes).sum();
        let avg_coverage: f64 = if total_algorithms > 0 {
            self.corpus_stats.values().map(|s| s.coverage_percentage).sum::<f64>() / total_algorithms as f64
        } else {
            0.0
        };
        
        report.push_str(&format!("## Summary\n"));
        report.push_str(&format!("- Algorithms tested: {}\n", total_algorithms));
        report.push_str(&format!("- Total corpus inputs: {}\n", total_inputs));
        report.push_str(&format!("- Total unique crashes: {}\n", total_crashes));
        report.push_str(&format!("- Average coverage: {:.2}%\n\n", avg_coverage));
        
        for (algorithm, stats) in &self.corpus_stats {
            report.push_str(&format!("## {}\n", algorithm));
            report.push_str(&format!("- Total inputs: {}\n", stats.total_inputs));
            report.push_str(&format!("- Unique crashes: {}\n", stats.unique_crashes));
            report.push_str(&format!("- Coverage: {:.2}%\n", stats.coverage_percentage));
            report.push_str(&format!("- Last updated: {:?}\n\n", stats.last_updated));
            
            if !stats.input_categories.is_empty() {
                report.push_str("### Input Categories:\n");
                for (category, count) in &stats.input_categories {
                    report.push_str(&format!("- {}: {} inputs\n", category, count));
                }
                report.push_str("\n");
            }
        }
        
        report
    }
    
    pub fn export_corpus_metadata(&self, output_path: &std::path::Path) -> Result<(), std::io::Error> {
        let metadata = serde_json::json!({
            "corpus_manager": {
                "base_path": self.base_path,
                "algorithms": self.algorithms,
                "statistics": self.corpus_stats
            },
            "export_timestamp": SystemTime::now(),
            "format_version": "1.0"
        });
        
        fs::write(output_path, serde_json::to_string_pretty(&metadata)?)?;
        Ok(())
    }
}

impl Default for CorpusManager {
    fn default() -> Self {
        Self::new("./fuzz_corpus")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_corpus_manager_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CorpusManager::new(temp_dir.path());
        
        assert!(manager.initialize_corpus_structure().is_ok());
        assert!(temp_dir.path().join("corpus").exists());
        assert!(temp_dir.path().join("crashes").exists());
        assert!(temp_dir.path().join("coverage").exists());
    }
    
    #[test]
    fn test_seed_generation() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CorpusManager::new(temp_dir.path());
        
        manager.initialize_corpus_structure().unwrap();
        assert!(manager.generate_seed_corpus().is_ok());
        
        // Check that seeds were created
        let ml_kem_512_corpus = temp_dir.path().join("corpus/ml_kem_512/valid_inputs");
        assert!(ml_kem_512_corpus.join("empty.bin").exists());
        assert!(ml_kem_512_corpus.join("single_byte.bin").exists());
    }
}