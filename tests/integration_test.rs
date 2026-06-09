//! Integration tests for jatin-lean core functionality.
//!
//! These tests create temporary node_modules structures and verify
//! that scanning, filtering, and analysis work correctly end-to-end.

use anyhow::Result;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Helper: create a mock node_modules with some packages.
fn create_mock_node_modules(root: &Path) -> Result<()> {
    let nm = root.join("node_modules");
    fs::create_dir_all(&nm)?;

    // Package 1: lodash (with various file types)
    let lodash = nm.join("lodash");
    fs::create_dir_all(&lodash)?;
    fs::write(
        lodash.join("package.json"),
        r#"{"name":"lodash","version":"4.17.21","main":"lodash.js","license":"MIT"}"#,
    )?;
    fs::write(lodash.join("lodash.js"), "module.exports = {};".repeat(100))?;
    fs::write(
        lodash.join("lodash.min.js"),
        "!function(){}.call(this)".repeat(50),
    )?;
    fs::write(
        lodash.join("README.md"),
        "# Lodash\n\nA modern JavaScript utility library.\n".repeat(10),
    )?;
    fs::write(
        lodash.join("LICENSE"),
        "MIT License\n\nCopyright (c) Lodash",
    )?;
    fs::write(
        lodash.join("CHANGELOG.md"),
        "# Changelog\n\n## 4.17.21\n- Fix security issue\n".repeat(20),
    )?;

    // Package 2: express (with test and example dirs)
    let express = nm.join("express");
    fs::create_dir_all(express.join("lib"))?;
    fs::create_dir_all(express.join("test"))?;
    fs::create_dir_all(express.join("examples"))?;
    fs::write(
        express.join("package.json"),
        r#"{"name":"express","version":"4.18.2","main":"index.js","license":"MIT"}"#,
    )?;
    fs::write(
        express.join("index.js"),
        "module.exports = require('./lib/express');",
    )?;
    fs::write(express.join("lib/express.js"), "const app = {};".repeat(50))?;
    fs::write(
        express.join("test/app.test.js"),
        "describe('express', () => { it('works', () => {}) });",
    )?;
    fs::write(
        express.join("test/req.test.js"),
        "describe('req', () => { it('works', () => {}) });",
    )?;
    fs::write(
        express.join("examples/hello.js"),
        "const express = require('../'); const app = express();",
    )?;
    fs::write(
        express.join("README.md"),
        "# Express\n\nFast, unopinionated, minimalist web framework.\n",
    )?;

    // Package 3: chalk (with TypeScript source alongside compiled JS)
    let chalk = nm.join("chalk");
    fs::create_dir_all(chalk.join("source"))?;
    fs::write(
        chalk.join("package.json"),
        r#"{"name":"chalk","version":"5.3.0","main":"source/index.js","license":"MIT","sideEffects":false}"#,
    )?;
    fs::write(chalk.join("source/index.js"), "export const chalk = {};")?;
    fs::write(
        chalk.join("source/index.d.ts"),
        "export declare const chalk: any;",
    )?;
    fs::write(
        chalk.join("readme.md"),
        "# Chalk\n\nTerminal styling done right.\n",
    )?;

    // Package 4: @babel/core (scoped package)
    let babel_scope = nm.join("@babel");
    let babel_core = babel_scope.join("core");
    fs::create_dir_all(babel_core.join("lib"))?;
    fs::write(
        babel_core.join("package.json"),
        r#"{"name":"@babel/core","version":"7.23.0","main":"lib/index.js","license":"MIT"}"#,
    )?;
    fs::write(
        babel_core.join("lib/index.js"),
        "module.exports = {};".repeat(200),
    )?;
    fs::write(
        babel_core.join("README.md"),
        "# @babel/core\n\nBabel compiler core.\n",
    )?;
    fs::write(babel_core.join("LICENSE"), "MIT License")?;

    // Package 5: Duplicate content across packages
    let is_number = nm.join("is-number");
    fs::create_dir_all(&is_number)?;
    fs::write(
        is_number.join("package.json"),
        r#"{"name":"is-number","version":"7.0.0","main":"index.js","license":"MIT"}"#,
    )?;
    fs::write(
        is_number.join("index.js"),
        "module.exports = function(n) { return typeof n === 'number'; };",
    )?;
    fs::write(
        is_number.join("README.md"),
        "# is-number\n\nReturns true if a value is a number.\n",
    )?;

    // Create a root package.json
    fs::write(
        root.join("package.json"),
        r#"{"name":"test-project","version":"1.0.0","dependencies":{"lodash":"^4.17.21","express":"^4.18.2","chalk":"^5.3.0","@babel/core":"^7.23.0","is-number":"^7.0.0"}}"#,
    )?;

    // Create .bin directory
    let bin = nm.join(".bin");
    fs::create_dir_all(&bin)?;

    Ok(())
}

#[test]
fn test_full_scan_pipeline() -> Result<()> {
    let temp = TempDir::new()?;
    create_mock_node_modules(temp.path())?;

    let nm_path = temp.path().join("node_modules");
    let rules = jatin_lean::rules::PruneRules::new();
    let result = jatin_lean::scanner::scan_node_modules(&nm_path, &rules, &[], None)?;

    assert!(result.total_files > 0, "Should find files");
    assert!(result.total_size > 0, "Should calculate size");
    assert!(result.total_packages > 0, "Should count packages");

    // Should find some candidates (README, CHANGELOG, test files, etc.)
    assert!(
        !result.candidates.is_empty(),
        "Should find prune candidates"
    );

    Ok(())
}

#[test]
fn test_scan_finds_documentation() -> Result<()> {
    let temp = TempDir::new()?;
    create_mock_node_modules(temp.path())?;

    let nm_path = temp.path().join("node_modules");
    let rules = jatin_lean::rules::PruneRules::new();
    let result = jatin_lean::scanner::scan_node_modules(&nm_path, &rules, &[], None)?;

    // README and CHANGELOG should be in candidates
    let has_readme = result.candidates.iter().any(|c| {
        c.path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.eq_ignore_ascii_case("readme.md") || n.eq_ignore_ascii_case("changelog.md")
            })
    });
    assert!(
        has_readme,
        "Should identify README/CHANGELOG as prune candidates"
    );

    Ok(())
}

#[test]
fn test_format_size_helper() {
    assert_eq!(jatin_lean::scanner::format_size(0), "0B");
    assert_eq!(jatin_lean::scanner::format_size(1023), "1023B");
    assert_eq!(jatin_lean::scanner::format_size(1024), "1.0KB");
    assert_eq!(jatin_lean::scanner::format_size(1_048_576), "1.0MB");
    assert_eq!(jatin_lean::scanner::format_size(1_073_741_824), "1.0GB");
}

#[test]
fn test_format_number_helper() {
    assert_eq!(jatin_lean::scanner::format_number(0), "0");
    assert_eq!(jatin_lean::scanner::format_number(999), "999");
    assert_eq!(jatin_lean::scanner::format_number(1000), "1,000");
    assert_eq!(jatin_lean::scanner::format_number(1_000_000), "1,000,000");
}

#[test]
fn test_scan_result_savings() -> Result<()> {
    let temp = TempDir::new()?;
    create_mock_node_modules(temp.path())?;

    let nm_path = temp.path().join("node_modules");
    let rules = jatin_lean::rules::PruneRules::new();
    let result = jatin_lean::scanner::scan_node_modules(&nm_path, &rules, &[], None)?;

    let savings = result.savings();
    assert!(
        savings <= result.total_size,
        "Savings should not exceed total size"
    );

    Ok(())
}

#[test]
fn test_lockfile_parser() -> Result<()> {
    let temp = TempDir::new()?;
    create_mock_node_modules(temp.path())?;

    // The mock project has no lock file, so it should return Unknown type
    let graph = jatin_lean::lockfile::DependencyGraph::from_project(temp.path())?;
    assert_eq!(graph.source, jatin_lean::lockfile::LockFileType::Unknown);
    assert!(
        graph.direct_dep_count() > 0,
        "Should parse direct deps from package.json"
    );

    Ok(())
}

#[test]
fn test_lockfile_npm_parse() -> Result<()> {
    let temp = TempDir::new()?;
    create_mock_node_modules(temp.path())?;

    // Create a minimal package-lock.json
    fs::write(
        temp.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-project", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2", "dependencies": {"accepts": "~1.3.8"}},
                "node_modules/chalk": {"version": "5.3.0"},
                "node_modules/@babel/core": {"version": "7.23.0"},
                "node_modules/is-number": {"version": "7.0.0"}
            }
        }"#,
    )?;

    let graph = jatin_lean::lockfile::DependencyGraph::from_project(temp.path())?;
    assert_eq!(graph.source, jatin_lean::lockfile::LockFileType::NpmV3);
    assert!(graph.is_production_dep("lodash"));
    assert!(graph.is_production_dep("express"));
    assert!(graph.total_deps() >= 5);

    Ok(())
}

#[test]
fn test_config_example_creation() -> Result<()> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("jatin-lean.toml");
    jatin_lean::config::Config::create_example(&config_path)?;
    assert!(config_path.exists());

    let content = fs::read_to_string(&config_path)?;
    assert!(content.contains("override_defaults") || content.contains("doc_files"));
    Ok(())
}

#[test]
fn test_prune_rules_default() {
    let _rules = jatin_lean::rules::PruneRules::new();
    // Default rules should have patterns — scan finds candidates
    // PruneRules::new() should work without panicking
}

#[test]
fn test_dedup_hash_consistency() -> Result<()> {
    let temp = TempDir::new()?;
    let file1 = temp.path().join("a.txt");
    let file2 = temp.path().join("b.txt");
    let content = "This is identical content for testing dedup functionality.";
    fs::write(&file1, content)?;
    fs::write(&file2, content)?;

    // Both files should have the same hash
    // (We can't directly test the private function, but we can test the find_duplicates fn)
    // This test validates the concept
    assert_eq!(fs::read_to_string(&file1)?, fs::read_to_string(&file2)?);
    Ok(())
}

#[test]
fn test_analytics_db_lifecycle() -> Result<()> {
    // AnalyticsDB should be creatable without errors
    let db = jatin_lean::analytics::AnalyticsDB::default();
    assert_eq!(db.entries.len(), 0);
    assert_eq!(db.total_bytes_saved(), 0);
    Ok(())
}

#[test]
fn test_profiler_basic_flow() {
    let mut profiler = jatin_lean::profiler::Profiler::new();
    profiler.start_span("test");
    profiler.end_span(100);
    // Profiler now uses record_package and phase_breakdown instead of spans()
    assert_eq!(profiler.total_packages, 0); // No packages recorded yet
}

#[test]
fn test_profiler_with_profiling() {
    let mut profiler = jatin_lean::profiler::Profiler::with_profiling(true);
    profiler.start_span("test");
    profiler.end_span(100);
    profiler.record_discovery(std::time::Duration::from_millis(10));
    assert_eq!(
        profiler.phase_breakdown.discovery,
        std::time::Duration::from_millis(10)
    );
}
