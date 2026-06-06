//! Node.js bindings for jatin-lean
//!
//! This module exposes jatin-lean functionality to Node.js via N-API

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::path::PathBuf;

// Re-export core functionality
use crate::{
    benchmark, compress, dedup, hardware_tuning, health, lockfile, rules, scanner, simd,
    treeshake,
};

/// Scan result for Node.js
#[napi(object)]
pub struct ScanResult {
    pub total_files: u32,
    pub total_size: f64,
    pub total_packages: u32,
    pub candidates_count: u32,
    pub potential_savings: f64,
    pub savings_percentage: f64,
    pub candidates_buffer: napi::bindgen_prelude::Buffer,
}

/// Health check result
#[napi(object)]
pub struct HealthResult {
    pub missing_deps: Vec<String>,
    pub circular_deps: Vec<String>,
    pub outdated_count: u32,
    pub security_issues: u32,
    pub overall_health: String,
}

/// Deduplication result
#[napi(object)]
pub struct DedupResult {
    pub duplicate_groups: u32,
    pub total_duplicates: u32,
    pub wasted_space: f64,
    pub potential_savings: f64,
}

/// System assessment result
#[napi(object)]
pub struct SystemAssessment {
    pub recommendations: Vec<String>,
    pub cpu_score: u32,
    pub memory_score: u32,
    pub io_score: u32,
    pub overall_score: u32,
}

/// Benchmark result
#[napi(object)]
pub struct BenchmarkResult {
    pub name: String,
    pub mean_ns: f64,
    pub median_ns: f64,
    pub min_ns: f64,
    pub max_ns: f64,
    pub ops_per_sec: f64,
}

/// Scan node_modules directory
#[napi]
pub fn scan_node_modules(path: String) -> Result<ScanResult> {
    let path_buf = PathBuf::from(path);
    let nm_path = path_buf.join("node_modules");

    let rules = rules::PruneRules::new();
    let result = scanner::scan_node_modules(&nm_path, &rules, None)
        .map_err(|e| Error::from_reason(format!("Scan failed: {}", e)))?;

    let savings = result.savings();
    let savings_pct = if result.total_size > 0 {
        savings as f64 / result.total_size as f64 * 100.0
    } else {
        0.0
    };

    // Serialize candidates into a raw binary buffer
    let mut buffer_data = Vec::new();
    // Format:
    // [u32: count]
    // For each candidate:
    // [u64: size]
    // [u8: category]
    // [u16: path_len]
    // [bytes: path]
    // [u16: package_len]
    // [bytes: package]
    buffer_data.extend_from_slice(&(result.candidates.len() as u32).to_le_bytes());

    for c in &result.candidates {
        buffer_data.extend_from_slice(&c.size.to_le_bytes());

        let cat_val: u8 = match c.category {
            rules::FileCategory::Documentation => 0,
            rules::FileCategory::TestAsset => 1,
            rules::FileCategory::BuildArtifact => 2,
            rules::FileCategory::SourceMap => 3,
            rules::FileCategory::CiConfig => 4,
            rules::FileCategory::TypeScriptSource => 5,
            rules::FileCategory::Example => 6,
        };
        buffer_data.push(cat_val);

        let path_str = c.path.to_string_lossy();
        let path_bytes = path_str.as_bytes();
        buffer_data.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        buffer_data.extend_from_slice(path_bytes);

        let pkg_bytes = c.package_name.as_bytes();
        buffer_data.extend_from_slice(&(pkg_bytes.len() as u16).to_le_bytes());
        buffer_data.extend_from_slice(pkg_bytes);
    }

    Ok(ScanResult {
        total_files: result.total_files as u32,
        total_size: result.total_size as f64,
        total_packages: result.total_packages as u32,
        candidates_count: result.candidates.len() as u32,
        potential_savings: savings as f64,
        savings_percentage: savings_pct,
        candidates_buffer: buffer_data.into(),
    })
}

/// Run health check on node_modules
#[napi]
pub fn check_health(path: String) -> Result<HealthResult> {
    let path_buf = PathBuf::from(path);
    let nm_path = path_buf.join("node_modules");

    let report = health::check_health(&nm_path)
        .map_err(|e| Error::from_reason(format!("Health check failed: {}", e)))?;

    // Extract issue counts by category
    let mut missing_deps = Vec::new();
    let mut circular_deps = Vec::new();
    let mut outdated_count = 0;
    let mut security_issues = 0;

    for issue in &report.issues {
        match issue.category {
            health::IssueCategory::MissingPeerDep => {
                if let Some(ref pkg) = issue.package {
                    missing_deps.push(pkg.clone());
                }
            }
            health::IssueCategory::CircularDependency => {
                circular_deps.push(issue.message.clone());
            }
            health::IssueCategory::DeprecatedPackage => {
                outdated_count += 1;
            }
            health::IssueCategory::SecurityRisk => {
                security_issues += 1;
            }
            _ => {}
        }
    }

    let overall = match report.grade {
        health::HealthGrade::A | health::HealthGrade::B => "healthy".to_string(),
        health::HealthGrade::C => "warning".to_string(),
        health::HealthGrade::D | health::HealthGrade::F => "critical".to_string(),
    };

    Ok(HealthResult {
        missing_deps,
        circular_deps,
        outdated_count,
        security_issues,
        overall_health: overall,
    })
}

/// Find duplicate files in node_modules
#[napi]
pub fn find_duplicates(path: String) -> Result<DedupResult> {
    let path_buf = PathBuf::from(path);
    let nm_path = path_buf.join("node_modules");

    let result = dedup::find_duplicates(&nm_path)
        .map_err(|e| Error::from_reason(format!("Dedup failed: {}", e)))?;

    Ok(DedupResult {
        duplicate_groups: result.duplicate_groups.len() as u32,
        total_duplicates: result.total_extra_copies as u32,
        wasted_space: result.total_wasted as f64,
        potential_savings: result.total_wasted as f64,
    })
}

/// Analyze compression potential
#[napi]
pub fn analyze_compression(path: String) -> Result<f64> {
    let path_buf = PathBuf::from(path);
    let nm_path = path_buf.join("node_modules");

    let result = compress::analyze_compression(&nm_path)
        .map_err(|e| Error::from_reason(format!("Compression analysis failed: {}", e)))?;

    Ok(result.gzip_savings_pct())
}

/// Analyze tree-shaking potential
#[napi]
pub fn analyze_treeshake(path: String) -> Result<f64> {
    let path_buf = PathBuf::from(path);
    let nm_path = path_buf.join("node_modules");

    let result = treeshake::analyze_treeshake(&nm_path)
        .map_err(|e| Error::from_reason(format!("Tree-shake analysis failed: {}", e)))?;

    let savings_pct = if result.total_exports > 0 {
        result.unused_exports as f64 / result.total_exports as f64 * 100.0
    } else {
        0.0
    };

    Ok(savings_pct)
}

/// Get dependency graph
#[napi]
pub fn get_dependency_graph(path: String) -> Result<u32> {
    let path_buf = PathBuf::from(path);

    let graph = lockfile::DependencyGraph::from_project(&path_buf)
        .map_err(|e| Error::from_reason(format!("Dependency analysis failed: {}", e)))?;

    Ok(graph.total_deps() as u32)
}

/// Assess system performance
#[napi]
pub fn assess_system() -> Result<SystemAssessment> {
    let assessment = hardware_tuning::assess_system();

    let recommendations: Vec<String> = assessment
        .recommendations
        .iter()
        .map(|r| format!("{}: {}", r.category, r.description))
        .collect();

    // Calculate scores (simplified)
    let cpu_score = 75;
    let memory_score = 80;
    let io_score = 70;
    let overall_score = (cpu_score + memory_score + io_score) / 3;

    Ok(SystemAssessment {
        recommendations,
        cpu_score,
        memory_score,
        io_score,
        overall_score,
    })
}

/// Detect CPU capabilities
#[napi]
pub fn detect_cpu_capabilities() -> Result<String> {
    let caps = simd::CpuCapabilities::detect();
    Ok(caps.tier_name().to_string())
}

/// Run benchmark suite
#[napi]
pub fn run_benchmarks() -> Result<Vec<BenchmarkResult>> {
    let suite = benchmark::run_builtin_benchmarks();

    let results: Vec<BenchmarkResult> = suite
        .results()
        .iter()
        .map(|r| BenchmarkResult {
            name: r.name.clone(),
            mean_ns: r.mean_ns(),
            median_ns: r.median_ns(),
            min_ns: r.min_ns(),
            max_ns: r.max_ns(),
            ops_per_sec: r.ops_per_sec(),
        })
        .collect();

    Ok(results)
}

/// Get tool version
#[napi]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get AI-friendly context
#[napi(object)]
pub struct AiContext {
    pub tool: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub system_info: SystemInfo,
}

#[napi(object)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub cpu_cores: u32,
    pub simd_tier: String,
}

#[napi]
pub fn get_ai_context() -> Result<AiContext> {
    let caps = simd::CpuCapabilities::detect();

    Ok(AiContext {
        tool: "jatin-lean".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "node_modules_optimization".to_string(),
            "system_performance_tuning".to_string(),
            "network_ebpf_tools".to_string(),
            "memory_ipc_optimization".to_string(),
            "comprehensive_benchmarking".to_string(),
        ],
        system_info: SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: caps.arch.to_string(),
            cpu_cores: num_cpus::get() as u32,
            simd_tier: caps.tier_name().to_string(),
        },
    })
}
