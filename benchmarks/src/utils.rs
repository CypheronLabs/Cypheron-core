use std::process::Command;
use std::fs;
use std::path::Path;
use serde_json;
use crate::{BenchmarkSuite, SystemEnvironment, BenchmarkMetadata};

pub fn get_system_info() -> SystemEnvironment {
    SystemEnvironment {
        cpu: get_cpu_info(),
        memory_gb: get_memory_info(),
        rust_version: get_rust_version(),
        compiler_flags: get_compiler_flags(),
        os: get_os_info(),
    }
}

fn get_cpu_info() -> String {
    if cfg!(target_os = "linux") {
        Command::new("sh")
            .arg("-c")
            .arg("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown CPU".to_string())
    } else if cfg!(target_os = "macos") {
        Command::new("sysctl")
            .arg("-n")
            .arg("machdep.cpu.brand_string")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown CPU".to_string())
    } else {
        "Unknown CPU".to_string()
    }
}

fn get_memory_info() -> f64 {
    if cfg!(target_os = "linux") {
        Command::new("sh")
            .arg("-c")
            .arg("cat /proc/meminfo | grep MemTotal | awk '{print $2}'")
            .output()
            .map(|output| {
                let kb_str = String::from_utf8_lossy(&output.stdout).trim();
                kb_str.parse::<f64>().unwrap_or(0.0) / 1024.0 / 1024.0
            })
            .unwrap_or(0.0)
    } else if cfg!(target_os = "macos") {
        Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
            .map(|output| {
                let bytes_str = String::from_utf8_lossy(&output.stdout).trim();
                bytes_str.parse::<f64>().unwrap_or(0.0) / 1024.0 / 1024.0 / 1024.0
            })
            .unwrap_or(0.0)
    } else {
        0.0
    }
}

fn get_rust_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "Unknown Rust version".to_string())
}

fn get_compiler_flags() -> String {
    "-C opt-level=3 -C target-cpu=native".to_string()
}

fn get_os_info() -> String {
    if cfg!(target_os = "linux") {
        Command::new("sh")
            .arg("-c")
            .arg("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Linux".to_string())
    } else if cfg!(target_os = "macos") {
        Command::new("sw_vers")
            .arg("-productName")
            .output()
            .and_then(|output| {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                Command::new("sw_vers")
                    .arg("-productVersion")
                    .output()
                    .map(|version_output| {
                        let version = String::from_utf8_lossy(&version_output.stdout).trim();
                        format!("{} {}", name, version)
                    })
            })
            .unwrap_or_else(|_| "macOS".to_string())
    } else if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else {
        "Unknown OS".to_string()
    }
}

pub fn save_benchmark_results(suite: &BenchmarkSuite, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;
    
    // Save JSON results
    let json_path = output_dir.join("benchmark_results.json");
    let json_content = serde_json::to_string_pretty(suite)?;
    fs::write(json_path, json_content)?;
    
    // Save CSV summary
    let csv_path = output_dir.join("benchmark_summary.csv");
    save_csv_summary(suite, &csv_path)?;
    
    Ok(())
}

fn save_csv_summary(suite: &BenchmarkSuite, csv_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(csv_path)?;
    
    // Write CSV header
    wtr.write_record(&[
        "Algorithm",
        "Operation", 
        "Implementation",
        "Mean Time (ns)",
        "Ops per Second",
        "Performance Ratio",
        "Grade"
    ])?;
    
    // Write data rows
    for result in &suite.results {
        wtr.write_record(&[
            &result.cypheron_result.algorithm,
            &result.cypheron_result.operation,
            &result.cypheron_result.implementation,
            &result.cypheron_result.mean_time_ns.to_string(),
            &result.cypheron_result.ops_per_second.to_string(),
            &result.performance_ratio.to_string(),
            result.performance_grade.to_string(),
        ])?;
    }
    
    wtr.flush()?;
    Ok(())
}

pub fn generate_plots(suite: &BenchmarkSuite, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use plotters::prelude::*;
    
    let plot_path = output_dir.join("performance_comparison.png");
    let root = BitMapBackend::new(&plot_path, (1024, 768)).into_drawing_area();
    root.fill(&WHITE)?;
    
    let mut chart = ChartBuilder::on(&root)
        .caption("Cypheron-Core Performance vs Reference Implementations", ("sans-serif", 40))
        .margin(10)
        .x_label_area_size(60)
        .y_label_area_size(80)
        .build_cartesian_2d(0f64..suite.results.len() as f64, 0f64..2.0f64)?;
    
    chart
        .configure_mesh()
        .x_desc("Algorithms")
        .y_desc("Performance Ratio")
        .draw()?;
    
    // Plot performance ratios
    let data: Vec<(f64, f64)> = suite.results.iter()
        .enumerate()
        .map(|(i, result)| (i as f64, result.performance_ratio))
        .collect();
    
    chart.draw_series(
        data.iter().map(|&(x, y)| {
            let color = if y >= 1.0 {
                &GREEN
            } else if y >= 0.8 {
                &BLUE
            } else if y >= 0.67 {
                &YELLOW
            } else {
                &RED
            };
            Rectangle::new([(x - 0.4, 0.0), (x + 0.4, y)], color.filled())
        })
    )?
    .label("Performance Ratio")
    .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 10, y)], &BLUE));
    
    // Add reference line at 1.0 (100% performance)
    chart.draw_series(std::iter::once(PathElement::new(
        vec![(0.0, 1.0), (suite.results.len() as f64, 1.0)],
        &BLACK.stroke_width(2),
    )))?;
    
    chart.configure_series_labels().draw()?;
    root.present()?;
    
    Ok(())
}

pub fn create_benchmark_metadata() -> BenchmarkMetadata {
    BenchmarkMetadata {
        library_name: "Cypheron-Core".to_string(),
        version: "v1.0.0".to_string(),
        test_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        environment: get_system_info(),
    }
}

pub fn validate_test_environment() -> Result<(), String> {
    // Check if required tools are available
    let tools = ["rustc", "cargo"];
    
    for tool in &tools {
        if Command::new(tool).arg("--version").output().is_err() {
            return Err(format!("Required tool '{}' not found", tool));
        }
    }
    
    // Check if we're in release mode
    if cfg!(debug_assertions) {
        return Err("Benchmarks should be run in release mode".to_string());
    }
    
    Ok(())
}

pub fn setup_benchmark_environment() -> Result<(), Box<dyn std::error::Error>> {
    // Create necessary directories
    let dirs = ["results", "results/correctness", "results/performance", "results/security"];
    
    for dir in &dirs {
        fs::create_dir_all(dir)?;
    }
    
    // Validate environment
    validate_test_environment()?;
    
    println!("Benchmark environment setup complete");
    Ok(())
}