//! Scanning engine: parallel file discovery using the `ignore` crate.
//!
//! Discovers node_modules directories and walks them in parallel,
//! collecting file metadata for the pruning engine.

use crate::allocator::ScanArena;
use crate::profiler::{PackageTiming, Profiler};
use crate::rules::{FileCategory, PruneRules};
use anyhow::{Context, Result};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};
use memmap2::Mmap;

/// Information about a file flagged for deletion.
#[derive(Debug, Clone)]
pub struct PruneCandidate {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// Category classification.
    pub category: FileCategory,
    /// The package this file belongs to (e.g., "lodash").
    pub package_name: String,
}

/// Results of scanning a node_modules directory.
#[derive(Debug)]
pub struct ScanResult {
    /// Root path that was scanned.
    pub root: PathBuf,
    /// Total number of files found.
    pub total_files: u64,
    /// Total size of all files.
    pub total_size: u64,
    /// Files flagged for deletion.
    pub candidates: Vec<PruneCandidate>,
    /// Total packages scanned.
    pub total_packages: usize,
    /// Whitelisted files (files that matched a rule but are runtime-required).
    pub whitelisted_count: u64,
}

impl ScanResult {
    /// Total savings in bytes.
    pub fn savings(&self) -> u64 {
        self.candidates.iter().map(|c| c.size).sum()
    }

    /// Breakdown by category.
    pub fn category_breakdown(&self) -> HashMap<FileCategory, (u64, u64)> {
        let mut map: HashMap<FileCategory, (u64, u64)> = HashMap::new();
        for c in &self.candidates {
            let entry = map.entry(c.category).or_insert((0, 0));
            entry.0 += 1; // count
            entry.1 += c.size; // size
        }
        map
    }

    /// Maximum risk level across all candidates.
    pub fn max_risk(&self) -> u8 {
        self.candidates
            .iter()
            .map(|c| c.category.risk_level())
            .max()
            .unwrap_or(0)
    }

    /// Risk label string.
    pub fn risk_label(&self) -> &'static str {
        match self.max_risk() {
            0 => "LOW — Only junk files targeted",
            1 => "MEDIUM — Source maps and build files included",
            2 => "HIGH — TypeScript sources included (declarations kept)",
            _ => "UNKNOWN",
        }
    }
}

/// Discover all `node_modules` directories under the given root.
pub fn find_node_modules(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .follow_links(false)
        .max_depth(Some(max_depth))
        .build();

    for entry in walker.flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_dir())
            && entry.file_name().to_str() == Some("node_modules")
        {
            results.push(entry.into_path());
        }
    }

    results
}

/// Get the last access time of a directory in days.
pub fn last_accessed_days(path: &Path) -> Option<u64> {
    let metadata = fs::metadata(path).ok()?;
    let accessed = metadata.accessed().ok()?;
    let duration = SystemTime::now().duration_since(accessed).ok()?;
    Some(duration.as_secs() / 86400)
}

/// Scan a single node_modules directory and identify prune candidates.
pub fn scan_node_modules(
    node_modules_path: &Path,
    rules: &PruneRules,
    profiler: Option<&mut Profiler>,
) -> Result<ScanResult> {
    let _scan_start = Instant::now();

    let total_files = AtomicU64::new(0);
    let total_size = AtomicU64::new(0);
    let whitelisted = AtomicU64::new(0);
    let candidates = Arc::new(Mutex::new(Vec::new()));

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message("Scanning files...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    // Phase 1: Discovery - find all packages
    let discovery_start = Instant::now();
    let mut packages: Vec<PathBuf> = Vec::new();
    if node_modules_path.is_dir() {
        if let Ok(entries) = fs::read_dir(node_modules_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name();
                    let name_str = name.to_str().unwrap_or("");

                    if name_str.starts_with('@') {
                        // Scoped packages: @scope/package
                        if let Ok(scoped_entries) = fs::read_dir(&path) {
                            for scoped_entry in scoped_entries.flatten() {
                                if scoped_entry.path().is_dir() {
                                    packages.push(scoped_entry.path());
                                }
                            }
                        }
                    } else if name_str != ".bin"
                        && name_str != ".cache"
                        && name_str != ".package-lock.json"
                    {
                        packages.push(path);
                    }
                }
            }
        }
    }
    let discovery_duration = discovery_start.elapsed();
    if let Some(_prof) = profiler.as_ref() {
        // Note: We can't mutate profiler here due to borrow checker
        // Will record at the end
    }

    let package_count = packages.len();

    // Phase 2: Parsing - extract entry points from package.json
    let parsing_start = Instant::now();
    let whitelisted_files: Arc<Mutex<std::collections::HashSet<PathBuf>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    // Store per-package timings
    let package_timings: Arc<Mutex<Vec<PackageTiming>>> = Arc::new(Mutex::new(Vec::new()));

    // Process packages in parallel
    packages.par_iter().for_each(|pkg_path| {
        let arena = ScanArena::new();
        let pkg_start = Instant::now();
        let pkg_name = extract_package_name(pkg_path, node_modules_path);
        let pkg_name_ref = arena.alloc_str(&pkg_name);
        // Parse package.json for entry points
        let pkg_json_path = pkg_path.join("package.json");
        if pkg_json_path.exists() {
            if let Ok(file) = std::fs::File::open(&pkg_json_path) {
    let parsed_json = match unsafe { Mmap::map(&file) } {
        Ok(mmap) => serde_json::from_slice::<serde_json::Value>(&mmap),

        Err(_) => {
            match fs::read_to_string(&pkg_json_path) {
                Ok(content) => serde_json::from_str::<serde_json::Value>(&content),

                Err(_) => return,
            }
        }
    };

    if let Ok(json) = parsed_json {
                    let entry_files = extract_entry_points(&json, pkg_path);
                    let mut wl = whitelisted_files.lock().unwrap();
                    for f in entry_files {
                        wl.insert(f);
                    }
                }
            }
        }

        // Phase 3: Walking - traverse all files in package
        let mut pkg_file_count = 0;
        let mut pkg_total_size = 0;
        let mut pkg_candidates = 0;

        let walker = WalkBuilder::new(pkg_path)
            .hidden(false)
            .git_ignore(false)
            .follow_links(false)
            .build();

        for entry in walker.flatten() {
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }

            let file_path = entry.into_path();
            let file_size = fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);

            pkg_file_count += 1;
            pkg_total_size += file_size;
            total_files.fetch_add(1, Ordering::Relaxed);
            total_size.fetch_add(file_size, Ordering::Relaxed);

            let current_files = total_files.load(Ordering::Relaxed);
            let current_size = total_size.load(Ordering::Relaxed);
            if current_files.is_multiple_of(500) {
                pb.set_message(format!(
                    "Scanning... {} files found | {} indexed",
                    format_number(current_files),
                    format_size(current_size)
                ));
            }

            // Phase 4: Classification - determine if file should be pruned
            if let Ok(rel_path) = file_path.strip_prefix(pkg_path) {
                if let Some(category) = rules.classify(rel_path) {
                    // Check if this file is whitelisted (runtime-required)
                    let wl = whitelisted_files.lock().unwrap();
                    if wl.contains(&file_path) {
                        whitelisted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        drop(wl);
                        pkg_candidates += 1;
                        let candidate = PruneCandidate {
                            path: file_path,
                            size: file_size,
                            category,
                            package_name: pkg_name_ref.to_string(),
                        };
                        candidates.lock().unwrap().push(candidate);
                    }
                }
            }
        }

        // Record package timing
        let pkg_duration = pkg_start.elapsed();
        let timing = PackageTiming {
            name: pkg_name,
            scan_time: pkg_duration,
            trace_time: std::time::Duration::ZERO, // Will be filled by tracer
            file_count: pkg_file_count,
            total_size: pkg_total_size,
            candidates_found: pkg_candidates,
        };
        package_timings.lock().unwrap().push(timing);
    });

    let parsing_duration = parsing_start.elapsed();

    pb.finish_and_clear();

    let candidates = Arc::try_unwrap(candidates)
        .map_err(|_| anyhow::anyhow!("Failed to unwrap candidates"))
        .context("Failed to collect candidates")?
        .into_inner()
        .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?;

    // Record metrics in profiler
    if let Some(prof) = profiler {
        prof.record_discovery(discovery_duration);
        prof.record_parsing(parsing_duration);

        // Add all package timings
        if let Ok(timings_mutex) = Arc::try_unwrap(package_timings) {
            let timings = timings_mutex.into_inner().unwrap_or_default();
            for timing in timings {
                prof.record_package(timing);
            }
        }
    }

    Ok(ScanResult {
        root: node_modules_path.to_path_buf(),
        total_files: total_files.load(Ordering::Relaxed),
        total_size: total_size.load(Ordering::Relaxed),
        candidates,
        total_packages: package_count,
        whitelisted_count: whitelisted.load(Ordering::Relaxed),
    })
}

/// Extract the package name from its path.
fn extract_package_name(pkg_path: &Path, node_modules_path: &Path) -> String {
    pkg_path
        .strip_prefix(node_modules_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            pkg_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

/// Extract runtime entry points from package.json.
///
/// Parses `main`, `module`, `browser`, `bin`, and `exports` fields.
fn extract_entry_points(json: &serde_json::Value, pkg_root: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();

    // "main" field
    if let Some(main) = json.get("main").and_then(|v| v.as_str()) {
        entries.push(pkg_root.join(main));
    }

    // "module" field
    if let Some(module) = json.get("module").and_then(|v| v.as_str()) {
        entries.push(pkg_root.join(module));
    }

    // "browser" field (can be string or object)
    if let Some(browser) = json.get("browser") {
        if let Some(s) = browser.as_str() {
            entries.push(pkg_root.join(s));
        } else if let Some(obj) = browser.as_object() {
            for value in obj.values() {
                if let Some(s) = value.as_str() {
                    entries.push(pkg_root.join(s));
                }
            }
        }
    }

    // "bin" field (can be string or object)
    if let Some(bin) = json.get("bin") {
        if let Some(s) = bin.as_str() {
            entries.push(pkg_root.join(s));
        } else if let Some(obj) = bin.as_object() {
            for value in obj.values() {
                if let Some(s) = value.as_str() {
                    entries.push(pkg_root.join(s));
                }
            }
        }
    }

    // "exports" field (can be string, object, or nested)
    if let Some(exports) = json.get("exports") {
        collect_export_paths(exports, pkg_root, &mut entries);
    }

    // "types" / "typings" field — keep type declaration entry points
    if let Some(types) = json
        .get("types")
        .or_else(|| json.get("typings"))
        .and_then(|v| v.as_str())
    {
        entries.push(pkg_root.join(types));
    }

    entries
}

/// Recursively collect file paths from the `exports` field.
fn collect_export_paths(value: &serde_json::Value, root: &Path, out: &mut Vec<PathBuf>) {
    match value {
        serde_json::Value::String(s)
            // Skip wildcard patterns
            if !s.contains('*') => {
                out.push(root.join(s));
            }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_export_paths(v, root, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_export_paths(v, root, out);
            }
        }
        _ => {}
    }
}

/// Format a number with comma separators.
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Get sizes of top-level packages in node_modules.
///
/// Returns a Vec of (package_name, total_size) sorted by size descending.
pub fn package_sizes(nm_path: &Path) -> Vec<(String, u64)> {
    use std::collections::HashMap;

    let mut sizes: HashMap<String, u64> = HashMap::new();

    let Ok(entries) = std::fs::read_dir(nm_path) else {
        return Vec::new();
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_str().unwrap_or("").to_string();
        if name.starts_with('.') {
            continue;
        }

        let path = entry.path();
        if name.starts_with('@') {
            // Scoped packages
            if let Ok(scoped) = std::fs::read_dir(&path) {
                for s in scoped.flatten() {
                    let scoped_name = format!("{}/{}", name, s.file_name().to_str().unwrap_or(""));
                    let size = dir_size(&s.path());
                    sizes.insert(scoped_name, size);
                }
            }
        } else if path.is_dir() {
            let size = dir_size(&path);
            sizes.insert(name, size);
        }
    }

    let mut result: Vec<(String, u64)> = sizes.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

/// Calculate total size of a directory recursively.
fn dir_size(path: &Path) -> u64 {
    let walker = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(false)
        .build();

    walker
        .flatten()
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// Format a size in bytes as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(1000000000), "1,000,000,000");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1024), "1.0KB");
        assert_eq!(format_size(1536), "1.5KB");
        assert_eq!(format_size(1048576), "1.0MB");
        assert_eq!(format_size(1572864), "1.5MB");
        assert_eq!(format_size(1073741824), "1.0GB");
        assert_eq!(format_size(1610612736), "1.5GB");
    }

    #[test]
    fn test_extract_package_name() {
        let nm_path = PathBuf::from("/project/node_modules");

        // Regular package
        let pkg_path = PathBuf::from("/project/node_modules/lodash");
        assert_eq!(extract_package_name(&pkg_path, &nm_path), "lodash");

        // Scoped package
        let scoped_path = PathBuf::from("/project/node_modules/@babel/core");
        assert_eq!(extract_package_name(&scoped_path, &nm_path), "@babel/core");
    }

    #[test]
    fn test_extract_entry_points_main_field() {
        use serde_json::json;

        let pkg_root = PathBuf::from("/test/pkg");
        let json = json!({
            "name": "test-pkg",
            "main": "index.js"
        });

        let entries = extract_entry_points(&json, &pkg_root);
        assert!(entries.contains(&pkg_root.join("index.js")));
    }

    #[test]
    fn test_extract_entry_points_multiple_fields() {
        use serde_json::json;

        let pkg_root = PathBuf::from("/test/pkg");
        let json = json!({
            "name": "test-pkg",
            "main": "index.js",
            "module": "index.mjs",
            "types": "index.d.ts"
        });

        let entries = extract_entry_points(&json, &pkg_root);
        assert!(entries.contains(&pkg_root.join("index.js")));
        assert!(entries.contains(&pkg_root.join("index.mjs")));
        assert!(entries.contains(&pkg_root.join("index.d.ts")));
    }

    #[test]
    fn test_extract_entry_points_bin_object() {
        use serde_json::json;

        let pkg_root = PathBuf::from("/test/pkg");
        let json = json!({
            "name": "test-pkg",
            "bin": {
                "cli": "bin/cli.js",
                "tool": "bin/tool.js"
            }
        });

        let entries = extract_entry_points(&json, &pkg_root);
        assert!(entries.contains(&pkg_root.join("bin/cli.js")));
        assert!(entries.contains(&pkg_root.join("bin/tool.js")));
    }

    #[test]
    fn test_extract_entry_points_exports_string() {
        use serde_json::json;

        let pkg_root = PathBuf::from("/test/pkg");
        let json = json!({
            "name": "test-pkg",
            "exports": "./dist/index.js"
        });

        let entries = extract_entry_points(&json, &pkg_root);
        assert!(entries.contains(&pkg_root.join("./dist/index.js")));
    }

    #[test]
    fn test_extract_entry_points_exports_object() {
        use serde_json::json;

        let pkg_root = PathBuf::from("/test/pkg");
        let json = json!({
            "name": "test-pkg",
            "exports": {
                ".": "./dist/index.js",
                "./utils": "./dist/utils.js"
            }
        });

        let entries = extract_entry_points(&json, &pkg_root);
        assert!(entries.contains(&pkg_root.join("./dist/index.js")));
        assert!(entries.contains(&pkg_root.join("./dist/utils.js")));
    }

    #[test]
    fn test_scan_result_savings() {
        let result = ScanResult {
            root: PathBuf::from("/test"),
            total_files: 100,
            total_size: 10000,
            candidates: vec![
                PruneCandidate {
                    path: PathBuf::from("/test/file1.js"),
                    size: 100,
                    category: FileCategory::Documentation,
                    package_name: "test".to_string(),
                },
                PruneCandidate {
                    path: PathBuf::from("/test/file2.js"),
                    size: 200,
                    category: FileCategory::TestAsset,
                    package_name: "test".to_string(),
                },
            ],
            total_packages: 1,
            whitelisted_count: 0,
        };

        assert_eq!(result.savings(), 300);
    }

    #[test]
    fn test_scan_result_risk_levels() {
        let low_risk = ScanResult {
            root: PathBuf::from("/test"),
            total_files: 10,
            total_size: 1000,
            candidates: vec![PruneCandidate {
                path: PathBuf::from("/test/README.md"),
                size: 100,
                category: FileCategory::Documentation,
                package_name: "test".to_string(),
            }],
            total_packages: 1,
            whitelisted_count: 0,
        };

        assert_eq!(low_risk.max_risk(), 0);
        assert_eq!(low_risk.risk_label(), "LOW — Only junk files targeted");

        let high_risk = ScanResult {
            root: PathBuf::from("/test"),
            total_files: 10,
            total_size: 1000,
            candidates: vec![PruneCandidate {
                path: PathBuf::from("/test/src/utils.ts"),
                size: 100,
                category: FileCategory::TypeScriptSource,
                package_name: "test".to_string(),
            }],
            total_packages: 1,
            whitelisted_count: 0,
        };

        assert_eq!(high_risk.max_risk(), 2);
        assert_eq!(
            high_risk.risk_label(),
            "HIGH — TypeScript sources included (declarations kept)"
        );
    }
}
