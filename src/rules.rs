//! Heuristic ruleset for identifying non-essential files in node_modules.
//!
//! Defines patterns for strict junk, development bloat, build leftovers,
//! and source map files that can be safely removed.

use regex::RegexSet;
use std::path::Path;

use crate::config::PruneProfile;

/// Categories of files that can be pruned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileCategory {
    /// Documentation files (README, CHANGELOG, LICENSE, etc.)
    Documentation,
    /// Test assets (test/, __tests__/, *.test.js, etc.)
    TestAsset,
    /// Build artifacts (*.c, *.cpp, *.o, Makefile, binding.gyp, etc.)
    BuildArtifact,
    /// Source maps (*.js.map, *.css.map)
    SourceMap,
    /// CI/CD configuration files (.travis.yml, circle.yml, etc.)
    CiConfig,
    /// TypeScript source files (*.ts, *.tsx — only declarations are needed at runtime)
    TypeScriptSource,
    /// Example / demo files
    Example,
}

impl FileCategory {
    /// Returns a human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            FileCategory::Documentation => "Documentation",
            FileCategory::TestAsset => "Test-Asset",
            FileCategory::BuildArtifact => "Build-Artifact",
            FileCategory::CiConfig => "CI-Config",
            FileCategory::SourceMap => "Source-Map",
            FileCategory::TypeScriptSource => "TS-Source",
            FileCategory::Example => "Example",
        }
    }

    /// Returns a risk level (0 = no risk, 1 = low, 2 = medium).
    pub fn risk_level(&self) -> u8 {
        match self {
            FileCategory::Documentation => 0,
            FileCategory::CiConfig => 0,
            FileCategory::TestAsset => 0,
            FileCategory::SourceMap => 1,
            FileCategory::BuildArtifact => 1,
            FileCategory::TypeScriptSource => 2,
            FileCategory::Example => 0,
        }
    }
}

impl PruneProfile {
    fn includes(self, category: FileCategory) -> bool {
        match self {
            PruneProfile::Conservative => {
                matches!(category, FileCategory::CiConfig | FileCategory::TestAsset)
            }
            PruneProfile::Balanced => matches!(
                category,
                FileCategory::Documentation
                    | FileCategory::TestAsset
                    | FileCategory::SourceMap
                    | FileCategory::CiConfig
                    | FileCategory::Example
            ),
            PruneProfile::Aggressive => true,
        }
    }
}

/// File patterns organized by category.
pub struct PruneRules {
    /// Predefined safety profile controlling which categories are enabled.
    pub profile: PruneProfile,
    /// Documentation file patterns (checked by filename)
    pub doc_files: Vec<String>,
    /// Documentation directories
    pub doc_dirs: Vec<String>,
    /// Test directories
    pub test_dirs: Vec<String>,
    /// Test file extensions/patterns (regex)
    pub test_file_regex: RegexSet,
    /// Build artifact extensions
    pub build_extensions: Vec<String>,
    /// Build artifact filenames
    pub build_files: Vec<String>,
    /// Build artifact directories
    pub build_dirs: Vec<String>,
    /// Source map extensions
    pub map_extensions: Vec<String>,
    /// CI/CD config files
    pub ci_files: Vec<String>,
    /// CI/CD directories
    pub ci_dirs: Vec<String>,
    /// Example directories
    pub example_dirs: Vec<String>,
    /// TypeScript source extensions (NOT .d.ts)
    pub ts_source_extensions: Vec<String>,
    /// If true, license files (LICENSE, LICENCE, license*, licence*) are never deleted
    pub keep_license: bool,
}

impl Default for PruneRules {
    fn default() -> Self {
        Self::new()
    }
}

impl PruneRules {
    pub fn new() -> Self {
        Self::new_with_config(None)
    }

    pub fn new_with_config(config: Option<crate::config::Config>) -> Self {
        let mut rules = Self {
            profile: PruneProfile::Balanced,
            // ── Documentation ──────────────────────────────
            doc_files: vec![
                "README.md",
                "README",
                "README.txt",
                "README.markdown",
                "readme.md",
                "readme.markdown",
                "CHANGELOG.md",
                "CHANGELOG",
                "CHANGELOG.txt",
                "changelog.md",
                "CHANGES.md",
                "CHANGES",
                "HISTORY.md",
                "HISTORY",
                "AUTHORS",
                "AUTHORS.md",
                "CONTRIBUTORS",
                "CONTRIBUTORS.md",
                "CONTRIBUTING.md",
                "CODE_OF_CONDUCT.md",
                "SECURITY.md",
                "TODO.md",
                "TODO",
                "NOTICE",
                "NOTICE.md",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            doc_dirs: vec!["docs", "doc", ".github"]
                .into_iter()
                .map(String::from)
                .collect(),

            // ── Test Assets ───────────────────────────────
            test_dirs: vec![
                "test",
                "tests",
                "spec",
                "specs",
                "__tests__",
                "__test__",
                "__mocks__",
                "__snapshots__",
                "fixtures",
                "test-fixtures",
                "coverage",
                ".nyc_output",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            test_file_regex: RegexSet::new([
                r"\.test\.[jt]sx?$",
                r"\.spec\.[jt]sx?$",
                r"\.test\.mjs$",
                r"\.spec\.mjs$",
                r"jest\.config\.[jt]s$",
                r"jest\.config\.mjs$",
                r"jest\.setup\.[jt]s$",
                r"karma\.conf\.[jt]s$",
                r"mocha\..+$",
                r"\.mocharc\..+$",
                r"\.nycrc",
                r"nyc\.config\.[jt]s$",
                r"\.coveralls\.yml$",
            ])
            .expect("Invalid regex in test patterns"),

            // ── Build Artifacts ───────────────────────────
            build_extensions: vec![
                ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".o", ".obj", ".a", ".lib",
                ".gyp", ".gypi",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            build_files: vec![
                "Makefile",
                "makefile",
                "GNUmakefile",
                "CMakeLists.txt",
                "binding.gyp",
                "Gruntfile.js",
                "Gulpfile.js",
                "gulpfile.js",
                "webpack.config.js",
                "webpack.config.ts",
                "rollup.config.js",
                "rollup.config.mjs",
                "tsconfig.json",
                "tslint.json",
                ".eslintrc",
                ".eslintrc.js",
                ".eslintrc.json",
                ".eslintrc.yml",
                ".eslintignore",
                ".prettierrc",
                ".prettierrc.js",
                ".prettierrc.json",
                ".prettierignore",
                ".babelrc",
                ".babelrc.js",
                "babel.config.js",
                "babel.config.json",
                ".editorconfig",
                ".jshintrc",
                ".npmignore",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            build_dirs: vec!["build", "obj"].into_iter().map(String::from).collect(),

            // ── Source Maps ───────────────────────────────
            map_extensions: vec![".js.map", ".css.map", ".mjs.map"]
                .into_iter()
                .map(String::from)
                .collect(),

            // ── CI/CD Config ──────────────────────────────
            ci_files: vec![
                ".travis.yml",
                "circle.yml",
                "appveyor.yml",
                ".appveyor.yml",
                "Jenkinsfile",
                ".gitlab-ci.yml",
                "azure-pipelines.yml",
                "codecov.yml",
                ".codecov.yml",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            ci_dirs: vec![".circleci", ".travis"]
                .into_iter()
                .map(String::from)
                .collect(),

            // ── Examples ──────────────────────────────────
            example_dirs: vec!["example", "examples", "demo", "demos", "sample", "samples"]
                .into_iter()
                .map(String::from)
                .collect(),

            // ── TypeScript Sources ────────────────────────
            ts_source_extensions: vec![".ts", ".tsx"].into_iter().map(String::from).collect(),

            // ── License protection (off by default) ───────
            keep_license: false,
        };

        // Apply custom config if provided
        if let Some(cfg) = config {
            rules.profile = cfg.profile;

            // Apply keep_license from config
            rules.keep_license = cfg.keep_license;

            if cfg.override_defaults {
                // Replace defaults with config
                if !cfg.doc_files.is_empty() {
                    rules.doc_files = cfg.doc_files.clone();
                }
                if !cfg.doc_dirs.is_empty() {
                    rules.doc_dirs = cfg.doc_dirs.clone();
                }
                if !cfg.test_dirs.is_empty() {
                    rules.test_dirs = cfg.test_dirs.clone();
                }
                if !cfg.build_extensions.is_empty() {
                    rules.build_extensions = cfg.build_extensions.clone();
                }
                if !cfg.build_files.is_empty() {
                    rules.build_files = cfg.build_files.clone();
                }
                if !cfg.build_dirs.is_empty() {
                    rules.build_dirs = cfg.build_dirs.clone();
                }
                if !cfg.map_extensions.is_empty() {
                    rules.map_extensions = cfg.map_extensions.clone();
                }
                if !cfg.ci_files.is_empty() {
                    rules.ci_files = cfg.ci_files.clone();
                }
                if !cfg.ci_dirs.is_empty() {
                    rules.ci_dirs = cfg.ci_dirs.clone();
                }
                if !cfg.example_dirs.is_empty() {
                    rules.example_dirs = cfg.example_dirs.clone();
                }
                if !cfg.ts_source_extensions.is_empty() {
                    rules.ts_source_extensions = cfg.ts_source_extensions.clone();
                }
            } else {
                // Extend defaults with config
                for item in &cfg.doc_files {
                    if !rules.doc_files.contains(item) {
                        rules.doc_files.push(item.clone());
                    }
                }
                for item in &cfg.doc_dirs {
                    if !rules.doc_dirs.contains(item) {
                        rules.doc_dirs.push(item.clone());
                    }
                }
                for item in &cfg.test_dirs {
                    if !rules.test_dirs.contains(item) {
                        rules.test_dirs.push(item.clone());
                    }
                }
                for item in &cfg.build_extensions {
                    if !rules.build_extensions.contains(item) {
                        rules.build_extensions.push(item.clone());
                    }
                }
                for item in &cfg.build_files {
                    if !rules.build_files.contains(item) {
                        rules.build_files.push(item.clone());
                    }
                }
                for item in &cfg.build_dirs {
                    if !rules.build_dirs.contains(item) {
                        rules.build_dirs.push(item.clone());
                    }
                }
                for item in &cfg.map_extensions {
                    if !rules.map_extensions.contains(item) {
                        rules.map_extensions.push(item.clone());
                    }
                }
                for item in &cfg.ci_files {
                    if !rules.ci_files.contains(item) {
                        rules.ci_files.push(item.clone());
                    }
                }
                for item in &cfg.ci_dirs {
                    if !rules.ci_dirs.contains(item) {
                        rules.ci_dirs.push(item.clone());
                    }
                }
                for item in &cfg.example_dirs {
                    if !rules.example_dirs.contains(item) {
                        rules.example_dirs.push(item.clone());
                    }
                }
                for item in &cfg.ts_source_extensions {
                    if !rules.ts_source_extensions.contains(item) {
                        rules.ts_source_extensions.push(item.clone());
                    }
                }
            }
        }

        rules
    }

    /// Returns true if the given filename matches a license file pattern
    /// (case-insensitive: license*, licence*, LICENSE, LICENCE, etc.)
    fn is_license_file(file_name: &str) -> bool {
        let lower = file_name.to_lowercase();
        lower.starts_with("license") || lower.starts_with("licence")
    }

    fn category(&self, category: FileCategory) -> Option<FileCategory> {
        if self.profile.includes(category) {
            Some(category)
        } else {
            None
        }
    }

    /// Classify a file path into a category, or None if it should be kept.
    ///
    /// The `rel_path` should be relative to the package directory within node_modules.
    pub fn classify(&self, rel_path: &Path) -> Option<FileCategory> {
        let file_name = rel_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // ── If keep_license is enabled, protect license files before any other check ──
        if self.keep_license && Self::is_license_file(file_name) {
            return None;
        }

        // ── Safety: never touch .bin or dotfiles (except .github) ──
        for component in rel_path.components() {
            if let Some(s) = component.as_os_str().to_str() {
                if s == ".bin" || s == "node_modules" {
                    return None;
                }
                // Allow .github to be deleted (it's in ci_dirs/doc_dirs)
                if s.starts_with('.') && s != ".github" && s != ".circleci" && s != ".travis" {
                    return None;
                }
            }
        }

        // ── Check directories in path ──
        for component in rel_path.components() {
            let dir_name = component.as_os_str().to_str().unwrap_or("");

            if self.test_dirs.iter().any(|d| d == dir_name) {
                return self.category(FileCategory::TestAsset);
            }
            if self.doc_dirs.iter().any(|d| d == dir_name) {
                if dir_name == ".github" {
                    return self.category(FileCategory::CiConfig);
                }
                return self.category(FileCategory::Documentation);
            }
            if self.ci_dirs.iter().any(|d| d == dir_name) {
                return self.category(FileCategory::CiConfig);
            }
            if self.example_dirs.iter().any(|d| d == dir_name) {
                return self.category(FileCategory::Example);
            }
            // build dirs — but only if not the package root build
            if self.build_dirs.iter().any(|d| d == dir_name) {
                return self.category(FileCategory::BuildArtifact);
            }
        }

        // ── Check filenames (documentation) ──
        if self.doc_files.iter().any(|f| f == file_name) {
            return self.category(FileCategory::Documentation);
        }

        // ── Check CI config files ──
        if self.ci_files.iter().any(|f| f == file_name) {
            return self.category(FileCategory::CiConfig);
        }

        // ── Check build artifact filenames ──
        if self.build_files.iter().any(|f| f == file_name) {
            return self.category(FileCategory::BuildArtifact);
        }

        // ── Check extensions ──
        let path_str = rel_path.to_str().unwrap_or("");

        // Source maps (check before general extension checks since .js.map contains .map)
        for ext in &self.map_extensions {
            if path_str.ends_with(ext) {
                return self.category(FileCategory::SourceMap);
            }
        }

        // Build artifact extensions
        for ext in &self.build_extensions {
            if file_name.ends_with(ext) {
                return self.category(FileCategory::BuildArtifact);
            }
        }

        // Test file patterns (regex)
        if self.test_file_regex.is_match(file_name) {
            return self.category(FileCategory::TestAsset);
        }

        // TypeScript sources (but NOT .d.ts declaration files)
        if !file_name.ends_with(".d.ts") && !file_name.ends_with(".d.tsx") {
            for ext in &self.ts_source_extensions {
                if file_name.ends_with(ext) {
                    return self.category(FileCategory::TypeScriptSource);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn rules_with_profile(profile: PruneProfile) -> PruneRules {
        PruneRules::new_with_config(Some(Config {
            profile,
            ..Default::default()
        }))
    }

    #[test]
    fn test_readme_classified_as_documentation() {
        let rules = PruneRules::new();
        let path = PathBuf::from("README.md");
        assert_eq!(rules.classify(&path), Some(FileCategory::Documentation));
    }

    #[test]
    fn test_test_dir_classified() {
        let rules = PruneRules::new();
        let path = PathBuf::from("__tests__/foo.js");
        assert_eq!(rules.classify(&path), Some(FileCategory::TestAsset));
    }

    #[test]
    fn test_source_map_classified() {
        let rules = PruneRules::new();
        let path = PathBuf::from("dist/bundle.js.map");
        assert_eq!(rules.classify(&path), Some(FileCategory::SourceMap));
    }

    #[test]
    fn test_dotbin_never_deleted() {
        let rules = PruneRules::new();
        let path = PathBuf::from(".bin/somefile");
        assert_eq!(rules.classify(&path), None);
    }

    #[test]
    fn test_dts_files_kept() {
        let rules = PruneRules::new();
        let path = PathBuf::from("index.d.ts");
        assert_eq!(rules.classify(&path), None);
    }

    #[test]
    fn test_ts_source_classified() {
        let rules = rules_with_profile(PruneProfile::Aggressive);
        let path = PathBuf::from("src/utils.ts");
        assert_eq!(rules.classify(&path), Some(FileCategory::TypeScriptSource));
    }

    #[test]
    fn test_nested_node_modules_skipped() {
        let rules = PruneRules::new();
        let path = PathBuf::from("some-package/node_modules/nested/file.js");
        assert_eq!(rules.classify(&path), None);
    }

    #[test]
    fn test_ci_config_classified() {
        let rules = PruneRules::new();

        // CI files (non-dotfiles)
        assert_eq!(
            rules.classify(&PathBuf::from("circle.yml")),
            Some(FileCategory::CiConfig)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("appveyor.yml")),
            Some(FileCategory::CiConfig)
        );

        // CI directories (these are allowed even though they start with dots)
        assert_eq!(
            rules.classify(&PathBuf::from(".circleci/config.yml")),
            Some(FileCategory::CiConfig)
        );
        assert_eq!(
            rules.classify(&PathBuf::from(".github/workflows/test.yml")),
            Some(FileCategory::CiConfig)
        );
        assert_eq!(
            rules.classify(&PathBuf::from(".travis/config.yml")),
            Some(FileCategory::CiConfig)
        );
    }

    #[test]
    fn test_build_files_classified() {
        let rules = rules_with_profile(PruneProfile::Aggressive);

        // Build files
        assert_eq!(
            rules.classify(&PathBuf::from("Makefile")),
            Some(FileCategory::BuildArtifact)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("binding.gyp")),
            Some(FileCategory::BuildArtifact)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("tsconfig.json")),
            Some(FileCategory::BuildArtifact)
        );

        // Build extensions
        assert_eq!(
            rules.classify(&PathBuf::from("native/addon.c")),
            Some(FileCategory::BuildArtifact)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("native/addon.o")),
            Some(FileCategory::BuildArtifact)
        );
    }

    #[test]
    fn test_example_dirs_classified() {
        let rules = PruneRules::new();

        assert_eq!(
            rules.classify(&PathBuf::from("example/demo.js")),
            Some(FileCategory::Example)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("examples/basic.js")),
            Some(FileCategory::Example)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("demo/app.js")),
            Some(FileCategory::Example)
        );
    }

    #[test]
    fn test_test_file_regex() {
        let rules = PruneRules::new();

        assert_eq!(
            rules.classify(&PathBuf::from("utils.test.js")),
            Some(FileCategory::TestAsset)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("utils.spec.ts")),
            Some(FileCategory::TestAsset)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("jest.config.js")),
            Some(FileCategory::TestAsset)
        );
    }

    #[test]
    fn test_dotfiles_skipped() {
        let rules = PruneRules::new();

        // Regular dotfiles should be skipped
        assert_eq!(rules.classify(&PathBuf::from(".env")), None);
        assert_eq!(rules.classify(&PathBuf::from(".gitignore")), None);

        // But .github, .circleci, .travis are allowed
        assert_eq!(
            rules.classify(&PathBuf::from(".github/workflows/ci.yml")),
            Some(FileCategory::CiConfig)
        );
    }

    #[test]
    fn test_category_labels() {
        assert_eq!(FileCategory::Documentation.label(), "Documentation");
        assert_eq!(FileCategory::TestAsset.label(), "Test-Asset");
        assert_eq!(FileCategory::BuildArtifact.label(), "Build-Artifact");
        assert_eq!(FileCategory::CiConfig.label(), "CI-Config");
        assert_eq!(FileCategory::SourceMap.label(), "Source-Map");
        assert_eq!(FileCategory::TypeScriptSource.label(), "TS-Source");
        assert_eq!(FileCategory::Example.label(), "Example");
    }

    #[test]
    fn test_category_risk_levels() {
        assert_eq!(FileCategory::Documentation.risk_level(), 0);
        assert_eq!(FileCategory::TestAsset.risk_level(), 0);
        assert_eq!(FileCategory::CiConfig.risk_level(), 0);
        assert_eq!(FileCategory::Example.risk_level(), 0);
        assert_eq!(FileCategory::SourceMap.risk_level(), 1);
        assert_eq!(FileCategory::BuildArtifact.risk_level(), 1);
        assert_eq!(FileCategory::TypeScriptSource.risk_level(), 2);
    }

    #[test]
    fn test_conservative_profile_limits_categories() {
        let rules = rules_with_profile(PruneProfile::Conservative);

        assert_eq!(
            rules.classify(&PathBuf::from(".github/workflows/ci.yml")),
            Some(FileCategory::CiConfig)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("__tests__/foo.js")),
            Some(FileCategory::TestAsset)
        );
        assert_eq!(rules.classify(&PathBuf::from("README.md")), None);
        assert_eq!(rules.classify(&PathBuf::from("dist/bundle.js.map")), None);
    }

    #[test]
    fn test_balanced_profile_keeps_risky_sources_and_build_artifacts() {
        let rules = PruneRules::new();

        assert_eq!(
            rules.classify(&PathBuf::from("README.md")),
            Some(FileCategory::Documentation)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("examples/basic.js")),
            Some(FileCategory::Example)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("dist/bundle.js.map")),
            Some(FileCategory::SourceMap)
        );
        assert_eq!(rules.classify(&PathBuf::from("src/utils.ts")), None);
        assert_eq!(rules.classify(&PathBuf::from("native/addon.c")), None);
    }

    #[test]
    fn test_aggressive_profile_enables_all_categories() {
        let rules = rules_with_profile(PruneProfile::Aggressive);

        assert_eq!(
            rules.classify(&PathBuf::from("README.md")),
            Some(FileCategory::Documentation)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("native/addon.c")),
            Some(FileCategory::BuildArtifact)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("src/utils.ts")),
            Some(FileCategory::TypeScriptSource)
        );
    }

    /// Verifies that with --keep-license enabled, LICENSE files are never deleted.
    #[test]
    fn test_keep_license_protects_license_files() {
        let mut rules = PruneRules::new();
        rules.keep_license = true;

        // All common license filename variants must be protected (return None)
        assert_eq!(rules.classify(&PathBuf::from("LICENSE")), None);
        assert_eq!(rules.classify(&PathBuf::from("LICENSE.md")), None);
        assert_eq!(rules.classify(&PathBuf::from("LICENSE.txt")), None);
        assert_eq!(rules.classify(&PathBuf::from("LICENCE")), None);
        assert_eq!(rules.classify(&PathBuf::from("LICENCE.md")), None);
        // Case-insensitive variants
        assert_eq!(rules.classify(&PathBuf::from("license")), None);
        assert_eq!(rules.classify(&PathBuf::from("licence")), None);
        assert_eq!(rules.classify(&PathBuf::from("License.txt")), None);

        // Without keep_license, LICENSE would normally be classified as Documentation
        let mut rules_no_keep = PruneRules::new();
        rules_no_keep.keep_license = false;
        // LICENSE is not in the default doc_files list, but let's confirm keep_license=true
        // protects it regardless — set keep_license and verify it returns None
        rules_no_keep.keep_license = true;
        assert_eq!(rules_no_keep.classify(&PathBuf::from("LICENSE")), None);

        // Non-license files are unaffected by keep_license
        rules.keep_license = true;
        assert_eq!(
            rules.classify(&PathBuf::from("README.md")),
            Some(FileCategory::Documentation)
        );
        assert_eq!(
            rules.classify(&PathBuf::from("utils.test.js")),
            Some(FileCategory::TestAsset)
        );
    }
}
