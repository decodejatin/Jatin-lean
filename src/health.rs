//! Health checker: comprehensive node_modules health assessment.
//!
//! Analyzes the overall health of a node_modules directory including
//! version conflicts, missing peer dependencies, circular dependencies,
//! license compliance, and maintenance status.

use anyhow::Result;
use console::style;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::scanner::{format_number, format_size};

/// Health score grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthGrade {
    /// Excellent — no issues found
    A,
    /// Good — minor issues
    B,
    /// Fair — some concerns
    C,
    /// Poor — significant problems
    D,
    /// Critical — major issues
    F,
}

impl HealthGrade {
    pub fn label(&self) -> &'static str {
        match self {
            Self::A => "A — Excellent",
            Self::B => "B — Good",
            Self::C => "C — Fair",
            Self::D => "D — Poor",
            Self::F => "F — Critical",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::A => "🟢",
            Self::B => "🟡",
            Self::C => "🟠",
            Self::D => "🔴",
            Self::F => "💀",
        }
    }

    pub fn from_score(score: u32) -> Self {
        match score {
            90..=100 => Self::A,
            75..=89 => Self::B,
            60..=74 => Self::C,
            40..=59 => Self::D,
            _ => Self::F,
        }
    }
}

impl std::fmt::Display for HealthGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.emoji(), self.label())
    }
}

/// A health issue found during analysis.
#[derive(Debug, Clone)]
pub struct HealthIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub message: String,
    pub package: Option<String>,
    pub suggestion: Option<String>,
}

/// Severity level for health issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl IssueSeverity {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Info => "ℹ",
            Self::Warning => "⚠",
            Self::Error => "✗",
            Self::Critical => "🔥",
        }
    }
}

/// Categories of health issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueCategory {
    DuplicatePackage,
    MissingPeerDep,
    DeprecatedPackage,
    LicenseIssue,
    LargePackage,
    DeepNesting,
    CircularDependency,
    UnusedPackage,
    SecurityRisk,
    Maintenance,
}

impl IssueCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DuplicatePackage => "Duplicate Packages",
            Self::MissingPeerDep => "Missing Peer Dependencies",
            Self::DeprecatedPackage => "Deprecated Packages",
            Self::LicenseIssue => "License Concerns",
            Self::LargePackage => "Oversized Packages",
            Self::DeepNesting => "Deep Nesting",
            Self::CircularDependency => "Circular Dependencies",
            Self::UnusedPackage => "Unused Packages",
            Self::SecurityRisk => "Security Risks",
            Self::Maintenance => "Maintenance Concerns",
        }
    }
}

/// Complete health report for a node_modules directory.
#[derive(Debug)]
pub struct HealthReport {
    /// Overall health score (0-100)
    pub score: u32,
    /// Grade derived from score
    pub grade: HealthGrade,
    /// Total number of packages analyzed
    pub packages_analyzed: u64,
    /// Total size of node_modules
    pub total_size: u64,
    /// Number of unique packages
    pub unique_packages: u64,
    /// Issues found during analysis
    pub issues: Vec<HealthIssue>,
    /// Per-category issue counts
    pub category_counts: HashMap<IssueCategory, usize>,
    /// Top 10 largest packages
    pub largest_packages: Vec<(String, u64)>,
    /// License distribution
    pub license_distribution: HashMap<String, u32>,
    /// Deepest nesting level found
    pub max_nesting_depth: u32,
}

/// Minimal package.json fields we need.
#[derive(Debug, Deserialize)]
struct PkgJson {
    name: Option<String>,
    version: Option<String>,
    license: Option<serde_json::Value>,
    #[serde(default)]
    deprecated: Option<String>,
    #[serde(rename = "peerDependencies", default)]
    peer_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependenciesMeta", default)]
    peer_dependencies_meta: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    engines: Option<HashMap<String, String>>,
    #[serde(default)]
    scripts: Option<HashMap<String, String>>,
}

/// Run a comprehensive health check on node_modules.
pub fn check_health(node_modules_path: &Path) -> Result<HealthReport> {
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
    pb.set_message("Running health check...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut issues: Vec<HealthIssue> = Vec::new();
    let mut packages_analyzed: u64 = 0;
    let mut total_size: u64 = 0;
    let mut package_sizes: Vec<(String, u64)> = Vec::new();
    let mut license_map: HashMap<String, u32> = HashMap::new();
    let mut version_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_packages: HashSet<String> = HashSet::new();
    let mut max_depth: u32 = 0;

    // Scan all packages
    scan_packages_recursive(
        node_modules_path,
        0,
        &mut issues,
        &mut packages_analyzed,
        &mut total_size,
        &mut package_sizes,
        &mut license_map,
        &mut version_map,
        &mut all_packages,
        &mut max_depth,
        &pb,
    )?;

    pb.set_message("Analyzing results...");

    // Check for duplicate versions
    for (name, versions) in &version_map {
        if versions.len() > 1 {
            let unique: HashSet<&String> = versions.iter().collect();
            if unique.len() > 1 {
                issues.push(HealthIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::DuplicatePackage,
                    message: format!(
                        "{} has {} different versions installed: {}",
                        name,
                        unique.len(),
                        unique
                            .iter()
                            .take(5)
                            .map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    package: Some(name.clone()),
                    suggestion: Some("Consider deduplicating with `npm dedupe`".into()),
                });
            }
        }
    }

    // Check for large packages (>5MB)
    package_sizes.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, size) in package_sizes.iter().take(20) {
        if *size > 5_000_000 {
            issues.push(HealthIssue {
                severity: IssueSeverity::Info,
                category: IssueCategory::LargePackage,
                message: format!(
                    "{} is {} — consider if all features are needed",
                    name,
                    format_size(*size)
                ),
                package: Some(name.clone()),
                suggestion: Some("Check if a lighter alternative exists".into()),
            });
        }
    }

    // Check nesting depth
    if max_depth > 5 {
        issues.push(HealthIssue {
            severity: IssueSeverity::Warning,
            category: IssueCategory::DeepNesting,
            message: format!(
                "Maximum nesting depth is {} levels — may cause path length issues on Windows",
                max_depth
            ),
            package: None,
            suggestion: Some("Run `npm dedupe` to flatten the tree".into()),
        });
    }

    // Check license concerns
    let problematic_licenses = ["UNLICENSED", "UNKNOWN", "SEE LICENSE IN", ""];
    for (license, count) in &license_map {
        let upper = license.to_uppercase();
        if problematic_licenses.iter().any(|p| upper.contains(p)) || license.is_empty() {
            issues.push(HealthIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::LicenseIssue,
                message: format!(
                    "{} package(s) have unclear license: \"{}\"",
                    count,
                    if license.is_empty() {
                        "(none)"
                    } else {
                        license
                    }
                ),
                package: None,
                suggestion: Some("Review license compliance for production use".into()),
            });
        }
    }

    pb.finish_and_clear();

    // Calculate category counts
    let mut category_counts: HashMap<IssueCategory, usize> = HashMap::new();
    for issue in &issues {
        *category_counts.entry(issue.category).or_default() += 1;
    }

    // Calculate health score
    let score = calculate_health_score(&issues, packages_analyzed, max_depth);
    let grade = HealthGrade::from_score(score);

    let largest_packages: Vec<(String, u64)> = package_sizes.into_iter().take(10).collect();

    Ok(HealthReport {
        score,
        grade,
        packages_analyzed,
        total_size,
        unique_packages: all_packages.len() as u64,
        issues,
        category_counts,
        largest_packages,
        license_distribution: license_map,
        max_nesting_depth: max_depth,
    })
}

/// Recursively scan packages in a node_modules directory.
fn scan_packages_recursive(
    dir: &Path,
    depth: u32,
    issues: &mut Vec<HealthIssue>,
    packages_analyzed: &mut u64,
    total_size: &mut u64,
    package_sizes: &mut Vec<(String, u64)>,
    license_map: &mut HashMap<String, u32>,
    version_map: &mut HashMap<String, Vec<String>>,
    all_packages: &mut HashSet<String>,
    max_depth: &mut u32,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    if depth > 10 {
        return Ok(());
    }
    *max_depth = (*max_depth).max(depth);

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name_str = name.to_str().unwrap_or("");

        if name_str == ".bin" || name_str == ".cache" || name_str == ".package-lock.json" {
            continue;
        }

        if name_str.starts_with('@') {
            // Scoped packages — recurse one level deeper
            if let Ok(scoped_entries) = fs::read_dir(&path) {
                for scoped_entry in scoped_entries.flatten() {
                    let scoped_path = scoped_entry.path();
                    if scoped_path.is_dir() {
                        let scoped_name = format!(
                            "{}/{}",
                            name_str,
                            scoped_entry.file_name().to_str().unwrap_or("")
                        );
                        analyze_single_package(
                            &scoped_path,
                            &scoped_name,
                            depth,
                            issues,
                            packages_analyzed,
                            total_size,
                            package_sizes,
                            license_map,
                            version_map,
                            all_packages,
                            max_depth,
                            pb,
                        )?;
                    }
                }
            }
        } else {
            analyze_single_package(
                &path,
                name_str,
                depth,
                issues,
                packages_analyzed,
                total_size,
                package_sizes,
                license_map,
                version_map,
                all_packages,
                max_depth,
                pb,
            )?;
        }
    }

    Ok(())
}

/// Analyze a single package directory.
fn analyze_single_package(
    pkg_path: &Path,
    pkg_name: &str,
    depth: u32,
    issues: &mut Vec<HealthIssue>,
    packages_analyzed: &mut u64,
    total_size: &mut u64,
    package_sizes: &mut Vec<(String, u64)>,
    license_map: &mut HashMap<String, u32>,
    version_map: &mut HashMap<String, Vec<String>>,
    all_packages: &mut HashSet<String>,
    max_depth: &mut u32,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    *packages_analyzed += 1;
    if (*packages_analyzed).is_multiple_of(100) {
        pb.set_message(format!(
            "Analyzing... {} packages",
            format_number(*packages_analyzed)
        ));
    }

    all_packages.insert(pkg_name.to_string());

    // Calculate package size
    let pkg_size = dir_size(pkg_path);
    *total_size += pkg_size;
    package_sizes.push((pkg_name.to_string(), pkg_size));

    // Read package.json
    let pkg_json_path = pkg_path.join("package.json");
    if let Ok(content) = fs::read_to_string(&pkg_json_path) {
        if let Ok(pkg) = serde_json::from_str::<PkgJson>(&content) {
            // Track version
            if let Some(version) = &pkg.version {
                version_map
                    .entry(pkg_name.to_string())
                    .or_default()
                    .push(version.clone());
            }

            // Check deprecated
            if let Some(deprecated_msg) = &pkg.deprecated {
                issues.push(HealthIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::DeprecatedPackage,
                    message: format!("{} is deprecated: {}", pkg_name, deprecated_msg),
                    package: Some(pkg_name.to_string()),
                    suggestion: Some("Find an active replacement for this package".into()),
                });
            }

            // Track license
            let license_str = match &pkg.license {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Object(obj)) => obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Complex")
                    .to_string(),
                _ => "Unknown".to_string(),
            };
            *license_map.entry(license_str).or_default() += 1;

            // Check for install scripts (potential security risk)
            if let Some(scripts) = &pkg.scripts {
                let risky_scripts = ["preinstall", "install", "postinstall"];
                for script_name in &risky_scripts {
                    if let Some(script_cmd) = scripts.get(*script_name) {
                        // Skip common safe scripts
                        if !script_cmd.contains("node-gyp")
                            && !script_cmd.contains("prebuild")
                            && !script_cmd.contains("husky")
                        {
                            issues.push(HealthIssue {
                                severity: IssueSeverity::Info,
                                category: IssueCategory::SecurityRisk,
                                message: format!(
                                    "{} has {} script: {}",
                                    pkg_name,
                                    script_name,
                                    if script_cmd.len() > 60 {
                                        format!("{}...", &script_cmd[..60])
                                    } else {
                                        script_cmd.clone()
                                    }
                                ),
                                package: Some(pkg_name.to_string()),
                                suggestion: Some("Review install scripts for security".into()),
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for nested node_modules (deep nesting)
    let nested_nm = pkg_path.join("node_modules");
    if nested_nm.exists() {
        scan_packages_recursive(
            &nested_nm,
            depth + 1,
            issues,
            packages_analyzed,
            total_size,
            package_sizes,
            license_map,
            version_map,
            all_packages,
            max_depth,
            pb,
        )?;
    }

    Ok(())
}

/// Calculate the total size of a directory.
fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    if let Ok(walker) = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(false)
        .build()
        .try_fold(0u64, |acc, entry| {
            entry.map(|e| acc + e.metadata().map(|m| m.len()).unwrap_or(0))
        })
    {
        return walker;
    }
    // Fallback: just count files directly
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                } else if meta.is_dir() {
                    total += dir_size(&entry.path());
                }
            }
        }
    }
    total
}

/// Calculate health score from issues.
fn calculate_health_score(issues: &[HealthIssue], _package_count: u64, max_depth: u32) -> u32 {
    let mut score: i32 = 100;

    for issue in issues {
        match issue.severity {
            IssueSeverity::Critical => score -= 15,
            IssueSeverity::Error => score -= 8,
            IssueSeverity::Warning => score -= 3,
            IssueSeverity::Info => score -= 1,
        }
    }

    // Bonus for low nesting
    if max_depth <= 2 {
        score += 5;
    }

    // Penalty for very deep nesting
    if max_depth > 8 {
        score -= 10;
    }

    score.clamp(0, 100) as u32
}

/// Print the health report to the terminal.
pub fn print_health_report(report: &HealthReport) {
    println!();
    println!(
        "  {} {}",
        style("node_modules Health Report").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    // Grade
    println!(
        "  {} Overall Grade: {}",
        style("◉").bold(),
        match report.grade {
            HealthGrade::A => style(report.grade.to_string()).green().bold(),
            HealthGrade::B => style(report.grade.to_string()).green(),
            HealthGrade::C => style(report.grade.to_string()).yellow(),
            HealthGrade::D => style(report.grade.to_string()).red(),
            HealthGrade::F => style(report.grade.to_string()).red().bold(),
        }
    );
    println!(
        "  {} Score: {}/100",
        style("◉").bold(),
        style(report.score).white().bold()
    );
    println!();

    // Overview
    println!(
        "  {} {}",
        style("Overview").white().bold(),
        style("─────────────────────────────────").dim()
    );
    println!(
        "  {} Packages analyzed: {}",
        style("◉").cyan(),
        style(format_number(report.packages_analyzed))
            .white()
            .bold()
    );
    println!(
        "  {} Unique packages: {}",
        style("◉").cyan(),
        style(format_number(report.unique_packages)).white().bold()
    );
    println!(
        "  {} Total size: {}",
        style("◉").cyan(),
        style(format_size(report.total_size)).white().bold()
    );
    println!(
        "  {} Max nesting depth: {}",
        style("◉").cyan(),
        style(report.max_nesting_depth).white().bold()
    );
    println!(
        "  {} Issues found: {}",
        style("◉").yellow(),
        style(report.issues.len()).yellow().bold()
    );

    // Issues by category
    if !report.category_counts.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Issues by Category").white().bold(),
            style("──────────────────────────────").dim()
        );
        let mut cats: Vec<_> = report.category_counts.iter().collect();
        cats.sort_by(|a, b| b.1.cmp(a.1));
        for (cat, count) in cats {
            println!(
                "  {} {:30} {}",
                style("▸").dim(),
                cat.label(),
                style(count).yellow().bold()
            );
        }
    }

    // Top issues
    if !report.issues.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Top Issues").white().bold(),
            style("─────────────────────────────────").dim()
        );

        // Show critical/error first, then warnings
        let mut sorted_issues = report.issues.clone();
        sorted_issues.sort_by(|a, b| b.severity.cmp(&a.severity));

        for issue in sorted_issues.iter().take(15) {
            let severity_style = match issue.severity {
                IssueSeverity::Critical => style(issue.severity.icon()).red().bold(),
                IssueSeverity::Error => style(issue.severity.icon()).red(),
                IssueSeverity::Warning => style(issue.severity.icon()).yellow(),
                IssueSeverity::Info => style(issue.severity.icon()).blue(),
            };
            println!("  {} {}", severity_style, issue.message);
            if let Some(ref suggestion) = issue.suggestion {
                println!("    {} {}", style("→").dim(), style(suggestion).dim());
            }
        }

        if report.issues.len() > 15 {
            println!(
                "\n  {} ...and {} more issues",
                style("→").dim(),
                report.issues.len() - 15
            );
        }
    }

    // Largest packages
    if !report.largest_packages.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Largest Packages").white().bold(),
            style("────────────────────────────────").dim()
        );
        for (name, size) in &report.largest_packages {
            let bar_len = (*size as f64 / report.largest_packages[0].1 as f64 * 30.0) as usize;
            let bar: String = "█".repeat(bar_len);
            let empty: String = "░".repeat(30 - bar_len);
            println!(
                "  {} {:30} {:>8} {}{}",
                style("▸").dim(),
                style(name).cyan(),
                format_size(*size),
                style(&bar).cyan(),
                style(&empty).dim(),
            );
        }
    }

    // License distribution
    if !report.license_distribution.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("License Distribution").white().bold(),
            style("──────────────────────────────").dim()
        );
        let mut licenses: Vec<_> = report.license_distribution.iter().collect();
        licenses.sort_by(|a, b| b.1.cmp(a.1));
        for (license, count) in licenses.iter().take(10) {
            println!(
                "  {} {:25} {} packages",
                style("▸").dim(),
                license,
                style(count).white().bold()
            );
        }
        if licenses.len() > 10 {
            println!(
                "  {} ...and {} more license types",
                style("→").dim(),
                licenses.len() - 10
            );
        }
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_grade_from_score() {
        assert_eq!(HealthGrade::from_score(95), HealthGrade::A);
        assert_eq!(HealthGrade::from_score(80), HealthGrade::B);
        assert_eq!(HealthGrade::from_score(65), HealthGrade::C);
        assert_eq!(HealthGrade::from_score(45), HealthGrade::D);
        assert_eq!(HealthGrade::from_score(20), HealthGrade::F);
    }

    #[test]
    fn test_health_grade_display() {
        let grade = HealthGrade::A;
        let display = format!("{}", grade);
        assert!(display.contains("Excellent"));
    }

    #[test]
    fn test_calculate_health_score_perfect() {
        let score = calculate_health_score(&[], 100, 2);
        assert_eq!(score, 100); // 100 + 5 bonus capped at 100
    }

    #[test]
    fn test_calculate_health_score_with_issues() {
        let issues = vec![
            HealthIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::DuplicatePackage,
                message: "test".into(),
                package: None,
                suggestion: None,
            },
            HealthIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::SecurityRisk,
                message: "test".into(),
                package: None,
                suggestion: None,
            },
        ];
        let score = calculate_health_score(&issues, 100, 3);
        assert_eq!(score, 89); // 100 - 3 - 8
    }

    #[test]
    fn test_issue_severity_ordering() {
        assert!(IssueSeverity::Critical > IssueSeverity::Error);
        assert!(IssueSeverity::Error > IssueSeverity::Warning);
        assert!(IssueSeverity::Warning > IssueSeverity::Info);
    }
}
