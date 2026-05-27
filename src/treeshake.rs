//! Tree-shaking analyzer: detect unused exports and dead code patterns.
//!
//! Performs static analysis on JavaScript/TypeScript files within packages
//! to identify modules that export code but are never imported by any
//! other package in the dependency tree.

use anyhow::Result;
use console::style;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner::{format_number, format_size};

/// Result of a tree-shaking analysis.
#[derive(Debug)]
pub struct TreeShakeResult {
    /// Total entry points analyzed
    pub entry_points_analyzed: u64,
    /// Total exports found
    pub total_exports: u64,
    /// Exports that appear unused
    pub unused_exports: u64,
    /// Estimated bytes from unused exports
    pub estimated_dead_code_bytes: u64,
    /// Packages with the most dead code
    pub top_dead_packages: Vec<DeadCodePackage>,
    /// Files containing only dead exports
    pub fully_dead_files: Vec<PathBuf>,
    /// Total packages with side-effect-free markers
    pub side_effect_free_count: u64,
}

/// A package with dead code information.
#[derive(Debug, Clone)]
pub struct DeadCodePackage {
    pub name: String,
    pub total_exports: u64,
    pub unused_exports: u64,
    pub estimated_dead_bytes: u64,
    pub has_side_effects: bool,
    pub entry_files: Vec<PathBuf>,
}

impl DeadCodePackage {
    /// Percentage of exports that are unused.
    pub fn dead_percentage(&self) -> f64 {
        if self.total_exports == 0 {
            return 0.0;
        }
        (self.unused_exports as f64 / self.total_exports as f64) * 100.0
    }
}

/// An export found in a module.
#[derive(Debug, Clone)]
struct ExportEntry {
    /// Name of the export
    name: String,
    /// File containing the export
    file: PathBuf,
    /// Package owning the file
    package: String,
    /// Whether this is a default export
    is_default: bool,
    /// Approximate size contribution (bytes)
    estimated_bytes: u64,
}

/// Analyze tree-shaking potential in node_modules.
pub fn analyze_treeshake(node_modules_path: &Path) -> Result<TreeShakeResult> {
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
    pb.set_message("Analyzing exports...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut all_exports: Vec<ExportEntry> = Vec::new();
    let mut all_imports: HashSet<String> = HashSet::new();
    let mut side_effect_free_count: u64 = 0;
    let mut entry_points_analyzed: u64 = 0;

    // Scan each package
    if let Ok(entries) = fs::read_dir(node_modules_path) {
        for entry in entries.flatten() {
            let pkg_path = entry.path();
            if !pkg_path.is_dir() {
                continue;
            }

            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or("");

            if name_str.starts_with('.') || name_str == ".bin" {
                continue;
            }

            let packages: Vec<(PathBuf, String)> = if name_str.starts_with('@') {
                fs::read_dir(&pkg_path)
                    .into_iter()
                    .flat_map(|rd| rd.flatten())
                    .filter(|e| e.path().is_dir())
                    .map(|e| {
                        let n = format!("{}/{}", name_str, e.file_name().to_str().unwrap_or(""));
                        (e.path(), n)
                    })
                    .collect()
            } else {
                vec![(pkg_path, name_str.to_string())]
            };

            for (dir, pkg_name) in packages {
                let pkg_json_path = dir.join("package.json");
                if !pkg_json_path.exists() {
                    continue;
                }

                // Check sideEffects field
                if let Ok(content) = fs::read_to_string(&pkg_json_path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(side_effects) = json.get("sideEffects") {
                            if side_effects == &serde_json::Value::Bool(false) {
                                side_effect_free_count += 1;
                            }
                        }
                    }
                }

                // Find entry points and scan for exports
                let entry_files = find_entry_points(&dir);
                entry_points_analyzed += entry_files.len() as u64;

                for entry_file in &entry_files {
                    if let Ok(content) = fs::read_to_string(entry_file) {
                        let exports = extract_exports(&content, entry_file, &pkg_name);
                        all_exports.extend(exports);

                        let imports = extract_imports(&content);
                        all_imports.extend(imports);
                    }
                }
            }
        }
    }

    pb.set_message("Cross-referencing imports and exports...");

    // Find unused exports (exports not referenced in any imports)
    let total_exports = all_exports.len() as u64;
    let mut unused: Vec<&ExportEntry> = Vec::new();
    let mut dead_bytes: u64 = 0;
    let mut fully_dead_files: Vec<PathBuf> = Vec::new();

    // Group exports by file
    let mut exports_by_file: HashMap<PathBuf, Vec<&ExportEntry>> = HashMap::new();
    for export in &all_exports {
        exports_by_file
            .entry(export.file.clone())
            .or_default()
            .push(export);
    }

    for export in &all_exports {
        // Check if this export name appears in any import
        if !all_imports.contains(&export.name) && !export.is_default {
            unused.push(export);
            dead_bytes += export.estimated_bytes;
        }
    }

    // Find fully dead files
    for (file, file_exports) in &exports_by_file {
        if file_exports
            .iter()
            .all(|e| !all_imports.contains(&e.name) && !e.is_default)
        {
            fully_dead_files.push(file.clone());
        }
    }

    // Build per-package stats
    let mut pkg_stats: HashMap<String, DeadCodePackage> = HashMap::new();
    for export in &all_exports {
        let entry = pkg_stats
            .entry(export.package.clone())
            .or_insert_with(|| DeadCodePackage {
                name: export.package.clone(),
                total_exports: 0,
                unused_exports: 0,
                estimated_dead_bytes: 0,
                has_side_effects: true,
                entry_files: Vec::new(),
            });
        entry.total_exports += 1;
        if !entry.entry_files.contains(&export.file) {
            entry.entry_files.push(export.file.clone());
        }
    }

    for export in &unused {
        if let Some(entry) = pkg_stats.get_mut(&export.package) {
            entry.unused_exports += 1;
            entry.estimated_dead_bytes += export.estimated_bytes;
        }
    }

    let mut top_dead: Vec<DeadCodePackage> = pkg_stats.into_values().collect();
    top_dead.sort_by(|a, b| b.estimated_dead_bytes.cmp(&a.estimated_dead_bytes));

    pb.finish_and_clear();

    Ok(TreeShakeResult {
        entry_points_analyzed,
        total_exports,
        unused_exports: unused.len() as u64,
        estimated_dead_code_bytes: dead_bytes,
        top_dead_packages: top_dead.into_iter().take(20).collect(),
        fully_dead_files,
        side_effect_free_count,
    })
}

/// Find entry point files for a package.
fn find_entry_points(pkg_dir: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();

    // Standard entry points
    let candidates = [
        "index.js",
        "index.mjs",
        "index.cjs",
        "lib/index.js",
        "dist/index.js",
        "src/index.js",
        "main.js",
    ];

    for candidate in &candidates {
        let path = pkg_dir.join(candidate);
        if path.exists() {
            entries.push(path);
        }
    }

    // Check package.json main/module/exports fields
    let pkg_json = pkg_dir.join("package.json");
    if let Ok(content) = fs::read_to_string(&pkg_json) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            for field in &["main", "module", "jsnext:main"] {
                if let Some(main) = json.get(*field).and_then(|v| v.as_str()) {
                    let main_path = pkg_dir.join(main);
                    if main_path.exists() && !entries.contains(&main_path) {
                        entries.push(main_path);
                    }
                }
            }
        }
    }

    entries
}

/// Extract export names from JavaScript/TypeScript content.
fn extract_exports(content: &str, file: &Path, package: &str) -> Vec<ExportEntry> {
    let mut exports = Vec::new();
    let file_size = content.len() as u64;
    let line_count = content.lines().count() as u64;

    // Estimate bytes per export (rough heuristic)
    let avg_export_size = if line_count > 0 {
        file_size / line_count.max(1) * 5 // ~5 lines per export average
    } else {
        200
    };

    for line in content.lines() {
        let trimmed = line.trim();

        // export function name(...) or export const name = ...
        if trimmed.starts_with("export ") && !trimmed.starts_with("export default") {
            if let Some(name) = extract_named_export(trimmed) {
                exports.push(ExportEntry {
                    name,
                    file: file.to_path_buf(),
                    package: package.to_string(),
                    is_default: false,
                    estimated_bytes: avg_export_size,
                });
            }
        }

        // export default
        if trimmed.starts_with("export default") {
            exports.push(ExportEntry {
                name: "default".to_string(),
                file: file.to_path_buf(),
                package: package.to_string(),
                is_default: true,
                estimated_bytes: avg_export_size,
            });
        }

        // module.exports.name = ...
        if trimmed.starts_with("module.exports.") {
            if let Some(name) = trimmed
                .strip_prefix("module.exports.")
                .and_then(|s| s.split(&[' ', '='][..]).next())
            {
                exports.push(ExportEntry {
                    name: name.to_string(),
                    file: file.to_path_buf(),
                    package: package.to_string(),
                    is_default: false,
                    estimated_bytes: avg_export_size,
                });
            }
        }

        // exports.name = ...
        if trimmed.starts_with("exports.") && !trimmed.starts_with("exports.__") {
            if let Some(name) = trimmed
                .strip_prefix("exports.")
                .and_then(|s| s.split(&[' ', '='][..]).next())
            {
                exports.push(ExportEntry {
                    name: name.to_string(),
                    file: file.to_path_buf(),
                    package: package.to_string(),
                    is_default: false,
                    estimated_bytes: avg_export_size,
                });
            }
        }

        // Object.defineProperty(exports, 'name', ...)
        if trimmed.contains("Object.defineProperty(exports") {
            if let Some(start) = trimmed.find('\'').or_else(|| trimmed.find('"')) {
                let rest = &trimmed[start + 1..];
                if let Some(end) = rest.find('\'').or_else(|| rest.find('"')) {
                    let name = &rest[..end];
                    if name != "__esModule" {
                        exports.push(ExportEntry {
                            name: name.to_string(),
                            file: file.to_path_buf(),
                            package: package.to_string(),
                            is_default: false,
                            estimated_bytes: avg_export_size,
                        });
                    }
                }
            }
        }
    }

    exports
}

/// Extract a named export identifier from a line.
fn extract_named_export(line: &str) -> Option<String> {
    let rest = line.strip_prefix("export ")?;

    // export function name
    if let Some(after_fn) = rest
        .strip_prefix("function ")
        .or_else(|| rest.strip_prefix("function* "))
    {
        return after_fn
            .split(&['(', ' ', '<'][..])
            .next()
            .map(|s| s.to_string());
    }

    // export class name
    if let Some(after_class) = rest.strip_prefix("class ") {
        return after_class
            .split(&[' ', '{', '<'][..])
            .next()
            .map(|s| s.to_string());
    }

    // export const/let/var name
    for keyword in &["const ", "let ", "var "] {
        if let Some(after_kw) = rest.strip_prefix(keyword) {
            return after_kw
                .split(&[' ', '=', ':', ','][..])
                .next()
                .map(|s| s.to_string());
        }
    }

    // export type/interface (TypeScript)
    for keyword in &["type ", "interface ", "enum "] {
        if let Some(after_kw) = rest.strip_prefix(keyword) {
            return after_kw
                .split(&[' ', '{', '<', '='][..])
                .next()
                .map(|s| s.to_string());
        }
    }

    None
}

/// Extract import references from JavaScript content.
fn extract_imports(content: &str) -> HashSet<String> {
    let mut imports = HashSet::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // import { name1, name2 } from '...'
        if trimmed.starts_with("import ") {
            if let Some(start) = trimmed.find('{') {
                if let Some(end) = trimmed.find('}') {
                    let names = &trimmed[start + 1..end];
                    for name in names.split(',') {
                        let clean = name.trim().split(" as ").next().unwrap_or("").trim();
                        if !clean.is_empty() {
                            imports.insert(clean.to_string());
                        }
                    }
                }
            }
        }

        // require('...').name or const { name } = require('...')
        if trimmed.contains("require(") {
            if let Some(start) = trimmed.find('{') {
                if let Some(end) = trimmed.find('}') {
                    let names = &trimmed[start + 1..end];
                    for name in names.split(',') {
                        let clean = name.trim().split(':').next().unwrap_or("").trim();
                        if !clean.is_empty() {
                            imports.insert(clean.to_string());
                        }
                    }
                }
            }
        }

        // Direct property access: require('pkg').methodName
        if trimmed.contains("require(") && trimmed.contains(").") {
            if let Some(dot_pos) = trimmed.rfind(").") {
                let after_dot = &trimmed[dot_pos + 2..];
                if let Some(name) = after_dot.split(&['(', ';', ' ', ','][..]).next() {
                    if !name.is_empty() {
                        imports.insert(name.to_string());
                    }
                }
            }
        }
    }

    imports
}

/// Print tree-shake analysis results.
pub fn print_treeshake_results(result: &TreeShakeResult) {
    println!();
    println!(
        "  {} {}",
        style("Tree-Shaking Analysis").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    println!(
        "  {} Entry points analyzed: {}",
        style("◉").cyan(),
        style(format_number(result.entry_points_analyzed))
            .white()
            .bold()
    );
    println!(
        "  {} Total exports found: {}",
        style("◉").cyan(),
        style(format_number(result.total_exports)).white().bold()
    );
    println!(
        "  {} Side-effect-free packages: {}",
        style("◉").cyan(),
        style(format_number(result.side_effect_free_count))
            .white()
            .bold()
    );
    println!(
        "  {} Potentially unused exports: {}",
        style("◉").yellow(),
        style(format_number(result.unused_exports)).yellow().bold()
    );
    println!(
        "  {} Estimated dead code: {}",
        style("◉").red(),
        style(format_size(result.estimated_dead_code_bytes))
            .red()
            .bold()
    );
    println!(
        "  {} Fully dead files: {}",
        style("◉").red(),
        style(format_number(result.fully_dead_files.len() as u64))
            .red()
            .bold()
    );

    // Top packages with dead code
    if !result.top_dead_packages.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Top Packages with Unused Exports").white().bold(),
            style("────────────────────────────").dim()
        );

        for pkg in result.top_dead_packages.iter().take(10) {
            if pkg.unused_exports == 0 {
                continue;
            }
            println!(
                "  {} {} — {}/{} exports unused ({:.0}%), ~{}",
                style("▸").dim(),
                style(&pkg.name).yellow(),
                style(pkg.unused_exports).red(),
                pkg.total_exports,
                pkg.dead_percentage(),
                style(format_size(pkg.estimated_dead_bytes)).red(),
            );
        }
    }

    println!();
    println!(
        "  {} {} packages are marked side-effect-free and can be tree-shaken by bundlers.",
        style("💡").bold(),
        style(format_number(result.side_effect_free_count))
            .green()
            .bold()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_named_export_function() {
        assert_eq!(
            extract_named_export("export function myFunc(arg) {"),
            Some("myFunc".to_string())
        );
    }

    #[test]
    fn test_extract_named_export_const() {
        assert_eq!(
            extract_named_export("export const MY_CONST = 42;"),
            Some("MY_CONST".to_string())
        );
    }

    #[test]
    fn test_extract_named_export_class() {
        assert_eq!(
            extract_named_export("export class MyClass {"),
            Some("MyClass".to_string())
        );
    }

    #[test]
    fn test_extract_named_export_type() {
        assert_eq!(
            extract_named_export("export type MyType = string;"),
            Some("MyType".to_string())
        );
    }

    #[test]
    fn test_extract_imports_named() {
        let content = "import { useState, useEffect } from 'react';";
        let imports = extract_imports(content);
        assert!(imports.contains("useState"));
        assert!(imports.contains("useEffect"));
    }

    #[test]
    fn test_extract_imports_require() {
        let content = "const { readFile, writeFile } = require('fs');";
        let imports = extract_imports(content);
        assert!(imports.contains("readFile"));
        assert!(imports.contains("writeFile"));
    }

    #[test]
    fn test_extract_exports_module_exports() {
        let content = "module.exports.myHelper = function() {};";
        let exports = extract_exports(content, Path::new("test.js"), "pkg");
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "myHelper");
    }

    #[test]
    fn test_dead_code_package_percentage() {
        let pkg = DeadCodePackage {
            name: "test".to_string(),
            total_exports: 10,
            unused_exports: 4,
            estimated_dead_bytes: 1000,
            has_side_effects: false,
            entry_files: Vec::new(),
        };
        assert!((pkg.dead_percentage() - 40.0).abs() < 0.01);
    }
}
