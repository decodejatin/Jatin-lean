//! Compress analyzer: identifies files that would benefit from compression.
//!
//! Analyzes text-based files in node_modules and estimates potential
//! savings if they were served compressed (gzip/brotli). Useful for
//! understanding the true transfer size of dependencies.

use anyhow::Result;
use console::style;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner::{format_number, format_size};

/// Compression statistics for an individual file.
#[derive(Debug, Clone)]
pub struct CompressionStat {
    pub path: PathBuf,
    pub original_size: u64,
    pub estimated_gzip_size: u64,
    pub estimated_brotli_size: u64,
    pub file_type: String,
    pub package: String,
}

impl CompressionStat {
    /// Gzip savings percentage.
    pub fn gzip_savings_pct(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        (1.0 - self.estimated_gzip_size as f64 / self.original_size as f64) * 100.0
    }

    /// Brotli savings percentage.
    pub fn brotli_savings_pct(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        (1.0 - self.estimated_brotli_size as f64 / self.original_size as f64) * 100.0
    }
}

/// Result of a compression analysis.
#[derive(Debug)]
pub struct CompressionResult {
    /// Total files analyzed
    pub files_analyzed: u64,
    /// Total original size of compressible files
    pub total_original_size: u64,
    /// Estimated total size after gzip
    pub total_gzip_size: u64,
    /// Estimated total size after brotli
    pub total_brotli_size: u64,
    /// Per-file-type breakdown
    pub type_breakdown: HashMap<String, TypeCompressionStats>,
    /// Top 20 files with best compression ratio
    pub top_compressible: Vec<CompressionStat>,
    /// Per-package totals
    pub package_sizes: Vec<(String, u64, u64)>, // (name, original, gzipped)
}

impl CompressionResult {
    /// Total gzip savings.
    pub fn gzip_savings(&self) -> u64 {
        self.total_original_size
            .saturating_sub(self.total_gzip_size)
    }

    /// Total brotli savings.
    pub fn brotli_savings(&self) -> u64 {
        self.total_original_size
            .saturating_sub(self.total_brotli_size)
    }

    /// Gzip savings percentage.
    pub fn gzip_savings_pct(&self) -> f64 {
        if self.total_original_size == 0 {
            return 0.0;
        }
        (1.0 - self.total_gzip_size as f64 / self.total_original_size as f64) * 100.0
    }

    /// Brotli savings percentage.
    pub fn brotli_savings_pct(&self) -> f64 {
        if self.total_original_size == 0 {
            return 0.0;
        }
        (1.0 - self.total_brotli_size as f64 / self.total_original_size as f64) * 100.0
    }
}

/// Compression stats for a file type category.
#[derive(Debug, Clone, Default)]
pub struct TypeCompressionStats {
    pub file_count: u64,
    pub original_size: u64,
    pub gzip_size: u64,
    pub brotli_size: u64,
}

/// Estimate gzip compression ratio for different file types.
/// These are empirical averages based on typical file contents.
fn estimate_gzip_ratio(extension: &str) -> f64 {
    match extension {
        // JavaScript — typically compresses very well
        "js" | "mjs" | "cjs" => 0.30,
        // TypeScript definitions
        "ts" | "d.ts" | "mts" | "cts" => 0.28,
        // JSON — excellent compression
        "json" => 0.20,
        // CSS
        "css" => 0.25,
        // HTML/XML/SVG
        "html" | "htm" | "xml" | "svg" => 0.22,
        // Markdown/text
        "md" | "txt" | "rst" => 0.35,
        // YAML/TOML
        "yml" | "yaml" | "toml" => 0.30,
        // Source maps
        "map" => 0.15,
        // WASM — already compact
        "wasm" => 0.85,
        // Images — already compressed
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" => 0.98,
        // Fonts
        "woff" | "woff2" => 0.99,
        "ttf" | "otf" | "eot" => 0.70,
        // Default for unknown text
        _ => 0.50,
    }
}

/// Estimate brotli compression ratio (typically 15-25% better than gzip).
fn estimate_brotli_ratio(extension: &str) -> f64 {
    let gzip = estimate_gzip_ratio(extension);
    // Brotli typically achieves 15-25% better compression than gzip
    (gzip * 0.80).max(0.05)
}

/// Check if a file extension is compressible.
fn is_compressible(extension: &str) -> bool {
    matches!(
        extension,
        "js" | "mjs"
            | "cjs"
            | "ts"
            | "mts"
            | "cts"
            | "json"
            | "css"
            | "html"
            | "htm"
            | "xml"
            | "svg"
            | "md"
            | "txt"
            | "rst"
            | "yml"
            | "yaml"
            | "toml"
            | "map"
            | "ttf"
            | "otf"
            | "eot"
    )
}

/// Analyze compression potential in node_modules.
pub fn analyze_compression(node_modules_path: &Path) -> Result<CompressionResult> {
    use indicatif::{ProgressBar, ProgressStyle};

    let pb = ProgressBar::new_spinner();
    if crate::display::is_silent() {
        pb.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message("Analyzing compression potential...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut files_analyzed: u64 = 0;
    let mut total_original: u64 = 0;
    let mut total_gzip: u64 = 0;
    let mut total_brotli: u64 = 0;
    let mut type_breakdown: HashMap<String, TypeCompressionStats> = HashMap::new();
    let mut all_stats: Vec<CompressionStat> = Vec::new();
    let mut pkg_sizes: HashMap<String, (u64, u64)> = HashMap::new(); // pkg -> (original, gzip)

    let walker = ignore::WalkBuilder::new(node_modules_path)
        .hidden(false)
        .git_ignore(false)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if !is_compressible(ext) {
            continue;
        }

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let size = metadata.len();
        if size < 100 {
            continue; // Skip tiny files
        }

        files_analyzed += 1;
        if files_analyzed.is_multiple_of(500) {
            pb.set_message(format!(
                "Analyzed {} files...",
                format_number(files_analyzed)
            ));
        }

        let gzip_ratio = estimate_gzip_ratio(ext);
        let brotli_ratio = estimate_brotli_ratio(ext);
        let gzip_size = (size as f64 * gzip_ratio) as u64;
        let brotli_size = (size as f64 * brotli_ratio) as u64;

        total_original += size;
        total_gzip += gzip_size;
        total_brotli += brotli_size;

        // Track by file type
        let type_entry = type_breakdown.entry(ext.to_string()).or_default();
        type_entry.file_count += 1;
        type_entry.original_size += size;
        type_entry.gzip_size += gzip_size;
        type_entry.brotli_size += brotli_size;

        // Track by package
        let pkg_name = path
            .strip_prefix(node_modules_path)
            .ok()
            .and_then(|rel| {
                let components: Vec<_> = rel.components().collect();
                if components.is_empty() {
                    None
                } else {
                    let first = components[0].as_os_str().to_str().unwrap_or("");
                    if first.starts_with('@') && components.len() > 1 {
                        Some(format!(
                            "{}/{}",
                            first,
                            components[1].as_os_str().to_str().unwrap_or("")
                        ))
                    } else {
                        Some(first.to_string())
                    }
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        let pkg_entry = pkg_sizes.entry(pkg_name.clone()).or_insert((0, 0));
        pkg_entry.0 += size;
        pkg_entry.1 += gzip_size;

        all_stats.push(CompressionStat {
            path: path.to_path_buf(),
            original_size: size,
            estimated_gzip_size: gzip_size,
            estimated_brotli_size: brotli_size,
            file_type: ext.to_string(),
            package: pkg_name,
        });
    }

    pb.finish_and_clear();

    // Sort by savings potential
    all_stats.sort_by(|a, b| {
        let savings_a = a.original_size.saturating_sub(a.estimated_gzip_size);
        let savings_b = b.original_size.saturating_sub(b.estimated_gzip_size);
        savings_b.cmp(&savings_a)
    });

    let top_compressible: Vec<CompressionStat> = all_stats.into_iter().take(20).collect();

    // Sort packages by savings
    let mut package_sizes: Vec<(String, u64, u64)> = pkg_sizes
        .into_iter()
        .map(|(name, (orig, gz))| (name, orig, gz))
        .collect();
    package_sizes.sort_by(|a, b| {
        let savings_a = a.1.saturating_sub(a.2);
        let savings_b = b.1.saturating_sub(b.2);
        savings_b.cmp(&savings_a)
    });

    Ok(CompressionResult {
        files_analyzed,
        total_original_size: total_original,
        total_gzip_size: total_gzip,
        total_brotli_size: total_brotli,
        type_breakdown,
        top_compressible,
        package_sizes,
    })
}

/// Print compression analysis results.
pub fn print_compression_results(result: &CompressionResult) {
    println!();
    println!(
        "  {} {}",
        style("Compression Analysis").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    println!(
        "  {} Compressible files: {}",
        style("◉").cyan(),
        style(format_number(result.files_analyzed)).white().bold()
    );
    println!(
        "  {} Original size: {}",
        style("◉").cyan(),
        style(format_size(result.total_original_size))
            .white()
            .bold()
    );
    println!();

    // Compression comparison
    println!(
        "  {} {}",
        style("Compression Estimates").white().bold(),
        style("──────────────────────────────").dim()
    );
    println!(
        "  {} Gzip:   {} → {} ({} saved, {:.1}%)",
        style("▸").dim(),
        format_size(result.total_original_size),
        style(format_size(result.total_gzip_size)).green().bold(),
        style(format_size(result.gzip_savings())).green(),
        result.gzip_savings_pct(),
    );
    println!(
        "  {} Brotli: {} → {} ({} saved, {:.1}%)",
        style("▸").dim(),
        format_size(result.total_original_size),
        style(format_size(result.total_brotli_size)).green().bold(),
        style(format_size(result.brotli_savings())).green(),
        result.brotli_savings_pct(),
    );

    // By file type
    if !result.type_breakdown.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("By File Type").white().bold(),
            style("─────────────────────────────────────").dim()
        );

        let mut types: Vec<_> = result.type_breakdown.iter().collect();
        types.sort_by(|a, b| b.1.original_size.cmp(&a.1.original_size));

        for (ext, stats) in types.iter().take(10) {
            let savings_pct = if stats.original_size > 0 {
                (1.0 - stats.gzip_size as f64 / stats.original_size as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "  {} .{:6} {:>5} files  {:>8} → {:>8} ({:.0}% gzip savings)",
                style("▸").dim(),
                ext,
                format_number(stats.file_count),
                format_size(stats.original_size),
                format_size(stats.gzip_size),
                savings_pct,
            );
        }
    }

    // Top packages
    if !result.package_sizes.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Top Packages by Transfer Size").white().bold(),
            style("──────────────────────────────").dim()
        );

        for (name, orig, gzip) in result.package_sizes.iter().take(10) {
            println!(
                "  {} {:30} {:>8} → {:>8}",
                style("▸").dim(),
                style(name).cyan(),
                format_size(*orig),
                style(format_size(*gzip)).green(),
            );
        }
    }

    println!();
    println!(
        "  {} These are estimated transfer sizes — actual results depend on content.",
        style("ℹ").blue(),
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_ratio_js() {
        let ratio = estimate_gzip_ratio("js");
        assert!(ratio > 0.0 && ratio < 1.0);
        assert_eq!(ratio, 0.30);
    }

    #[test]
    fn test_brotli_better_than_gzip() {
        let gzip = estimate_gzip_ratio("js");
        let brotli = estimate_brotli_ratio("js");
        assert!(brotli < gzip);
    }

    #[test]
    fn test_is_compressible() {
        assert!(is_compressible("js"));
        assert!(is_compressible("json"));
        assert!(is_compressible("css"));
        assert!(is_compressible("map"));
        assert!(!is_compressible("png"));
        assert!(!is_compressible("wasm"));
    }

    #[test]
    fn test_compression_stat_savings() {
        let stat = CompressionStat {
            path: PathBuf::from("test.js"),
            original_size: 1000,
            estimated_gzip_size: 300,
            estimated_brotli_size: 240,
            file_type: "js".to_string(),
            package: "test".to_string(),
        };
        assert!((stat.gzip_savings_pct() - 70.0).abs() < 0.01);
        assert!((stat.brotli_savings_pct() - 76.0).abs() < 0.01);
    }

    #[test]
    fn test_compression_result_totals() {
        let result = CompressionResult {
            files_analyzed: 100,
            total_original_size: 10000,
            total_gzip_size: 3000,
            total_brotli_size: 2400,
            type_breakdown: HashMap::new(),
            top_compressible: Vec::new(),
            package_sizes: Vec::new(),
        };
        assert_eq!(result.gzip_savings(), 7000);
        assert_eq!(result.brotli_savings(), 7600);
        assert!((result.gzip_savings_pct() - 70.0).abs() < 0.01);
    }
}
