//! Configuration file support for custom pruning rules.
//!
//! Allows users to customize what gets deleted via a rules.toml file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// Predefined pruning safety profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PruneProfile {
    /// Safest tier: CI configuration and obvious test assets only.
    Conservative,
    /// Default tier: docs, examples, source maps, CI files, and test assets.
    Balanced,
    /// Highest savings tier: every known category, including build and TS sources.
    Aggressive,
}

impl Default for PruneProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

impl fmt::Display for PruneProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
        })
    }
}

impl FromStr for PruneProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "conservative" => Ok(Self::Conservative),
            "balanced" => Ok(Self::Balanced),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(format!(
                "invalid profile '{value}', expected conservative, balanced, or aggressive"
            )),
        }
    }
}

/// Configuration structure matching rules.toml format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Predefined pruning profile to apply before custom rule overrides.
    #[serde(default)]
    pub profile: PruneProfile,

    /// Whether to completely override default rules instead of merging
    #[serde(default)]
    pub override_defaults: bool,
    /// If true, license files (LICENSE, LICENCE, etc.) are never deleted
    #[serde(default)]
    pub keep_license: bool,

    /// Documentation file patterns
    #[serde(default)]
    pub doc_files: Vec<String>,

    /// Documentation directories
    #[serde(default)]
    pub doc_dirs: Vec<String>,

    /// Test directories
    #[serde(default)]
    pub test_dirs: Vec<String>,

    /// Test file patterns (regex)
    #[serde(default)]
    pub test_patterns: Vec<String>,

    /// Build artifact extensions
    #[serde(default)]
    pub build_extensions: Vec<String>,

    /// Build artifact filenames
    #[serde(default)]
    pub build_files: Vec<String>,

    /// Build artifact directories
    #[serde(default)]
    pub build_dirs: Vec<String>,

    /// Source map extensions
    #[serde(default)]
    pub map_extensions: Vec<String>,

    /// CI/CD config files
    #[serde(default)]
    pub ci_files: Vec<String>,

    /// CI/CD directories
    #[serde(default)]
    pub ci_dirs: Vec<String>,

    /// Example directories
    #[serde(default)]
    pub example_dirs: Vec<String>,

    /// TypeScript source extensions
    #[serde(default)]
    pub ts_source_extensions: Vec<String>,

    /// Additional patterns to exclude (never delete)
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// Additional patterns to include (always delete)
    #[serde(default)]
    pub include_patterns: Vec<String>,

    // === Performance & Cache Settings (Steps 11, 12, 15) ===
    /// Enable the incremental scan cache
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    /// Cache TTL in seconds (default: 86400 = 24h)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// Maximum cache size in MB
    #[serde(default = "default_cache_max_mb")]
    pub cache_max_size_mb: u64,

    /// Enable memory-mapped cache files
    #[serde(default)]
    pub mmap_cache: bool,

    // === Strategy Settings (Step 15) ===
    /// Fast-path threshold: max file count for fast-path scanning
    #[serde(default = "default_fast_path_files")]
    pub fast_path_max_files: i64,

    /// Fast-path threshold: max package size in KB
    #[serde(default = "default_fast_path_size_kb")]
    pub fast_path_max_size_kb: u64,

    /// Packages to always use fast-path scanning
    #[serde(default)]
    pub fast_path_packages: Vec<String>,

    /// Packages to always skip
    #[serde(default)]
    pub skip_packages: Vec<String>,

    // === Profiling Settings (Step 15) ===
    /// Enable performance profiling by default
    #[serde(default)]
    pub profiling_enabled: bool,

    /// Show per-package timing breakdown
    #[serde(default)]
    pub show_package_timings: bool,

    // === Distributed Cache Settings (Step 15) ===
    /// Enable distributed caching
    #[serde(default)]
    pub distributed_cache_enabled: bool,

    /// Remote cache endpoints
    #[serde(default)]
    pub distributed_cache_endpoints: Vec<String>,

    /// Distributed cache timeout in ms
    #[serde(default = "default_dist_cache_timeout")]
    pub distributed_cache_timeout_ms: u64,
}

fn default_true() -> bool {
    true
}
fn default_cache_ttl() -> u64 {
    86400
}
fn default_cache_max_mb() -> u64 {
    100
}
fn default_fast_path_files() -> i64 {
    20
}
fn default_fast_path_size_kb() -> u64 {
    100
}
fn default_dist_cache_timeout() -> u64 {
    5000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: PruneProfile::default(),
            keep_license: false,
            override_defaults: false,
            doc_files: vec![],
            doc_dirs: vec![],
            test_dirs: vec![],
            test_patterns: vec![],
            build_extensions: vec![],
            build_files: vec![],
            build_dirs: vec![],
            map_extensions: vec![],
            ci_files: vec![],
            ci_dirs: vec![],
            example_dirs: vec![],
            ts_source_extensions: vec![],
            exclude_patterns: vec![],
            include_patterns: vec![],
            // Performance & Cache
            cache_enabled: true,
            cache_ttl_seconds: 86400,
            cache_max_size_mb: 100,
            mmap_cache: false,
            // Strategy
            fast_path_max_files: 20,
            fast_path_max_size_kb: 100,
            fast_path_packages: vec![],
            skip_packages: vec![],
            // Profiling
            profiling_enabled: false,
            show_package_timings: false,
            // Distributed Cache
            distributed_cache_enabled: false,
            distributed_cache_endpoints: vec![],
            distributed_cache_timeout_ms: 5000,
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Try to load config from multiple locations in order:
    /// 1. --config <path> (if provided)
    /// 2. ./jatin-lean.toml
    /// 3. ./.jatin-lean.toml
    /// 4. ~/.config/jatin-lean/rules.toml
    pub fn load(custom_path: Option<&Path>, project_dir: &Path) -> Result<Option<Self>> {
        // 1. Custom path provided via CLI
        if let Some(path) = custom_path {
            if path.exists() {
                println!(
                    "  {} Loading config from: {}",
                    console::style("◉").cyan(),
                    console::style(path.display()).dim()
                );
                return Ok(Some(Self::from_file(path)?));
            } else {
                anyhow::bail!("Config file not found: {}", path.display());
            }
        }

        // 2. ./jatin-lean.toml
        let local_config = project_dir.join("jatin-lean.toml");
        if local_config.exists() {
            println!(
                "  {} Loading config from: {}",
                console::style("◉").cyan(),
                console::style("jatin-lean.toml").dim()
            );
            return Ok(Some(Self::from_file(&local_config)?));
        }

        // 3. ./.jatin-lean.toml
        let hidden_config = project_dir.join(".jatin-lean.toml");
        if hidden_config.exists() {
            println!(
                "  {} Loading config from: {}",
                console::style("◉").cyan(),
                console::style(".jatin-lean.toml").dim()
            );
            return Ok(Some(Self::from_file(&hidden_config)?));
        }

        // 4. ~/.config/jatin-lean/rules.toml
        if let Some(home) = dirs::home_dir() {
            let global_config = home.join(".config").join("jatin-lean").join("rules.toml");
            if global_config.exists() {
                println!(
                    "  {} Loading global config from: {}",
                    console::style("◉").cyan(),
                    console::style("~/.config/jatin-lean/rules.toml").dim()
                );
                return Ok(Some(Self::from_file(&global_config)?));
            }
        }

        // No config found, use defaults
        Ok(None)
    }

    /// Generate a sample config file
    pub fn generate_sample() -> String {
        r#"# jatin-lean configuration file
# Customize what gets deleted from node_modules

# Predefined pruning profile:
# - conservative: CI/CD config and obvious test assets only
# - balanced: documentation, examples, source maps, CI/CD config, and tests
# - aggressive: all known categories, including build artifacts and TypeScript sources
profile = "balanced"

# If true, ignores all built-in rules and only uses the ones defined here.
# If false, these rules are added to the built-in defaults.
override_defaults = false
# Keep license files (LICENSE, LICENCE, etc.) even when pruning documentation
keep_license = false

# Documentation files (exact filenames)
doc_files = [
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
]

# Documentation directories
doc_dirs = [
    "docs",
    "doc",
    ".github",
]

# Test directories
test_dirs = [
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
]

# Test file patterns (regex)
test_patterns = [
    "\\.test\\.[jt]sx?$",
    "\\.spec\\.[jt]sx?$",
]

# Build artifact extensions
build_extensions = [
    ".c",
    ".cpp",
    ".o",
    ".gyp",
]

# Build artifact filenames
build_files = [
    "Makefile",
    "binding.gyp",
    "tsconfig.json",
    ".eslintrc",
]

# Build artifact directories
build_dirs = [
    "build",
]

# Source map extensions
map_extensions = [
    ".js.map",
    ".css.map",
]

# CI/CD config files
ci_files = [
    ".travis.yml",
    "circle.yml",
    "appveyor.yml",
]

# CI/CD directories
ci_dirs = [
    ".circleci",
    ".travis",
]

# Example directories
example_dirs = [
    "example",
    "examples",
    "demo",
    "demos",
]

# TypeScript source extensions (NOT .d.ts)
ts_source_extensions = [
    ".ts",
    ".tsx",
]

# Exclude patterns (never delete these)
exclude_patterns = [
    # "important-file.js",
    # "keep-this-dir/",
]

# Include patterns (always delete these)
include_patterns = [
    # "*.backup",
    # "temp/",
]
"#
        .to_string()
    }

    /// Create an example config file at the specified path
    pub fn create_example(path: &Path) -> Result<()> {
        let sample = Self::generate_sample();
        fs::write(path, sample)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.profile, PruneProfile::Balanced);
        assert!(!config.override_defaults);
        assert!(config.doc_files.is_empty());
        assert!(config.test_dirs.is_empty());
    }

    #[test]
    fn test_config_generate_sample() {
        let sample = Config::generate_sample();
        assert!(sample.contains("profile = \"balanced\""));
        assert!(sample.contains("override_defaults"));
        assert!(sample.contains("doc_files"));
        assert!(sample.contains("test_dirs"));
        assert!(sample.contains("build_extensions"));
    }

    #[test]
    fn test_config_create_example() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test-config.toml");

        Config::create_example(&config_path)?;

        assert!(config_path.exists());
        let content = fs::read_to_string(&config_path)?;
        assert!(content.contains("jatin-lean configuration file"));

        Ok(())
    }

    #[test]
    fn test_config_from_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test.toml");

        let toml_content = r#"
profile = "aggressive"
override_defaults = true
doc_files = ["CUSTOM_README.md"]
test_dirs = ["custom_tests"]
"#;
        fs::write(&config_path, toml_content)?;

        let config = Config::from_file(&config_path)?;
        assert_eq!(config.profile, PruneProfile::Aggressive);
        assert!(config.override_defaults);
        assert_eq!(config.doc_files, vec!["CUSTOM_README.md"]);
        assert_eq!(config.test_dirs, vec!["custom_tests"]);

        Ok(())
    }

    #[test]
    fn test_config_load_custom_path() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("custom.toml");

        Config::create_example(&config_path)?;

        let loaded = Config::load(Some(&config_path), temp_dir.path())?;
        assert!(loaded.is_some());

        Ok(())
    }

    #[test]
    fn test_config_load_local() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("jatin-lean.toml");

        Config::create_example(&config_path)?;

        let loaded = Config::load(None, temp_dir.path())?;
        assert!(loaded.is_some());

        Ok(())
    }

    #[test]
    fn test_config_load_none() -> Result<()> {
        let temp_dir = TempDir::new()?;

        let loaded = Config::load(None, temp_dir.path())?;
        assert!(loaded.is_none());

        Ok(())
    }

    #[test]
    fn test_config_invalid_path() {
        let result = Config::load(Some(Path::new("/nonexistent/config.toml")), Path::new("."));
        assert!(result.is_err());
    }
}
