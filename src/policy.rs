//! Policy engine: enterprise-grade compliance and enforcement rules.
//!
//! Allows organizations to define policies that restrict package sizes,
//! ban specific packages, enforce license allowlists, and set other
//! governance constraints on the dependency tree.

use anyhow::{bail, Context, Result};
use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::scanner::format_size;

/// A policy definition that constrains the dependency tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name
    pub name: String,
    /// Policy version
    pub version: String,
    /// Description
    pub description: Option<String>,
    /// Rules within this policy
    pub rules: PolicyRules,
}

/// Collection of policy rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRules {
    /// Maximum total size of node_modules (bytes)
    #[serde(default)]
    pub max_total_size: Option<u64>,
    /// Maximum size of any single package (bytes)
    #[serde(default)]
    pub max_package_size: Option<u64>,
    /// Maximum number of dependencies
    #[serde(default)]
    pub max_dependency_count: Option<u64>,
    /// Maximum nesting depth
    #[serde(default)]
    pub max_nesting_depth: Option<u32>,
    /// Banned packages (must not be present)
    #[serde(default)]
    pub banned_packages: Vec<String>,
    /// Allowed licenses (if set, only these are permitted)
    #[serde(default)]
    pub allowed_licenses: Vec<String>,
    /// Banned licenses (these are never allowed)
    #[serde(default)]
    pub banned_licenses: Vec<String>,
    /// Required packages (must be present)
    #[serde(default)]
    pub required_packages: Vec<String>,
    /// Ban packages with install scripts (security)
    #[serde(default)]
    pub ban_install_scripts: bool,
    /// Maximum age of packages in days (based on publish date)
    #[serde(default)]
    pub max_package_age_days: Option<u64>,
    /// Enforce side-effects: false for all packages
    #[serde(default)]
    pub require_side_effect_free: bool,
    /// Custom message to display on violation
    #[serde(default)]
    pub violation_message: Option<String>,
}

/// A policy violation found during enforcement.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: ViolationSeverity,
    pub message: String,
    pub package: Option<String>,
    pub actual_value: String,
    pub limit_value: String,
}

/// Severity of a policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationSeverity {
    Warning,
    Error,
    Blocking,
}

impl ViolationSeverity {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Warning => "⚠",
            Self::Error => "✗",
            Self::Blocking => "🚫",
        }
    }
}

impl std::fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Blocking => write!(f, "BLOCKING"),
        }
    }
}

/// Result of enforcing a policy.
#[derive(Debug)]
pub struct PolicyResult {
    pub policy_name: String,
    pub violations: Vec<PolicyViolation>,
    pub rules_checked: u32,
    pub rules_passed: u32,
    pub rules_failed: u32,
    pub is_compliant: bool,
}

impl PolicyResult {
    /// Whether there are any blocking violations.
    pub fn has_blockers(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Blocking)
    }

    /// Count violations by severity.
    pub fn violation_counts(&self) -> (usize, usize, usize) {
        let warnings = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let errors = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count();
        let blockers = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Blocking)
            .count();
        (warnings, errors, blockers)
    }
}

/// Load a policy from a file.
pub fn load_policy(path: &Path) -> Result<Policy> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read policy file: {}", path.display()))?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "json" => serde_json::from_str(&content).with_context(|| "Failed to parse JSON policy"),
        "toml" => toml::from_str(&content).with_context(|| "Failed to parse TOML policy"),
        _ => bail!("Unsupported policy file format: .{}", ext),
    }
}

/// Create an example policy file.
pub fn create_example_policy(path: &Path) -> Result<()> {
    let example = Policy {
        name: "default-policy".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Example enterprise policy for jatin-lean".to_string()),
        rules: PolicyRules {
            max_total_size: Some(500_000_000), // 500MB
            max_package_size: Some(50_000_000), // 50MB
            max_dependency_count: Some(500),
            max_nesting_depth: Some(5),
            banned_packages: vec![
                "left-pad".to_string(),
                "is-odd".to_string(),
                "is-even".to_string(),
            ],
            allowed_licenses: vec![
                "MIT".to_string(),
                "ISC".to_string(),
                "BSD-2-Clause".to_string(),
                "BSD-3-Clause".to_string(),
                "Apache-2.0".to_string(),
                "0BSD".to_string(),
            ],
            banned_licenses: vec![
                "GPL-2.0".to_string(),
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
            ],
            required_packages: Vec::new(),
            ban_install_scripts: false,
            max_package_age_days: None,
            require_side_effect_free: false,
            violation_message: Some(
                "This project violates the dependency policy. Contact the platform team for exceptions.".to_string()
            ),
        },
    };

    let content = toml::to_string_pretty(&example)?;
    fs::write(path, content)?;
    Ok(())
}

/// Enforce a policy against a node_modules directory.
pub fn enforce_policy(policy: &Policy, node_modules_path: &Path) -> Result<PolicyResult> {
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
    pb.set_message(format!("Enforcing policy: {}...", policy.name));
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut violations: Vec<PolicyViolation> = Vec::new();
    let mut rules_checked: u32 = 0;
    let mut rules_passed: u32 = 0;

    // Scan packages
    let mut total_size: u64 = 0;
    let mut package_count: u64 = 0;
    let mut package_names: HashSet<String> = HashSet::new();
    let mut package_sizes: Vec<(String, u64)> = Vec::new();
    let mut licenses_found: HashSet<String> = HashSet::new();
    let mut max_depth: u32 = 0;
    let mut packages_with_install_scripts: Vec<String> = Vec::new();

    scan_packages_for_policy(
        node_modules_path,
        0,
        &mut total_size,
        &mut package_count,
        &mut package_names,
        &mut package_sizes,
        &mut licenses_found,
        &mut max_depth,
        &mut packages_with_install_scripts,
    )?;

    pb.set_message("Checking policy rules...");

    // Rule: max_total_size
    if let Some(max_size) = policy.rules.max_total_size {
        rules_checked += 1;
        if total_size > max_size {
            violations.push(PolicyViolation {
                rule: "max_total_size".to_string(),
                severity: ViolationSeverity::Blocking,
                message: format!(
                    "Total node_modules size {} exceeds limit of {}",
                    format_size(total_size),
                    format_size(max_size)
                ),
                package: None,
                actual_value: format_size(total_size),
                limit_value: format_size(max_size),
            });
        } else {
            rules_passed += 1;
        }
    }

    // Rule: max_package_size
    if let Some(max_pkg_size) = policy.rules.max_package_size {
        rules_checked += 1;
        let oversized: Vec<_> = package_sizes
            .iter()
            .filter(|(_, size)| *size > max_pkg_size)
            .collect();
        if oversized.is_empty() {
            rules_passed += 1;
        } else {
            for (name, size) in &oversized {
                violations.push(PolicyViolation {
                    rule: "max_package_size".to_string(),
                    severity: ViolationSeverity::Error,
                    message: format!(
                        "Package {} ({}) exceeds size limit of {}",
                        name,
                        format_size(*size),
                        format_size(max_pkg_size)
                    ),
                    package: Some(name.clone()),
                    actual_value: format_size(*size),
                    limit_value: format_size(max_pkg_size),
                });
            }
        }
    }

    // Rule: max_dependency_count
    if let Some(max_deps) = policy.rules.max_dependency_count {
        rules_checked += 1;
        if package_count > max_deps {
            violations.push(PolicyViolation {
                rule: "max_dependency_count".to_string(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "Dependency count {} exceeds limit of {}",
                    package_count, max_deps
                ),
                package: None,
                actual_value: package_count.to_string(),
                limit_value: max_deps.to_string(),
            });
        } else {
            rules_passed += 1;
        }
    }

    // Rule: max_nesting_depth
    if let Some(max_nest) = policy.rules.max_nesting_depth {
        rules_checked += 1;
        if max_depth > max_nest {
            violations.push(PolicyViolation {
                rule: "max_nesting_depth".to_string(),
                severity: ViolationSeverity::Warning,
                message: format!("Nesting depth {} exceeds limit of {}", max_depth, max_nest),
                package: None,
                actual_value: max_depth.to_string(),
                limit_value: max_nest.to_string(),
            });
        } else {
            rules_passed += 1;
        }
    }

    // Rule: banned_packages
    if !policy.rules.banned_packages.is_empty() {
        rules_checked += 1;
        let banned_found: Vec<_> = policy
            .rules
            .banned_packages
            .iter()
            .filter(|p| package_names.contains(p.as_str()))
            .collect();
        if banned_found.is_empty() {
            rules_passed += 1;
        } else {
            for pkg in banned_found {
                violations.push(PolicyViolation {
                    rule: "banned_packages".to_string(),
                    severity: ViolationSeverity::Blocking,
                    message: format!("Banned package '{}' is installed", pkg),
                    package: Some(pkg.clone()),
                    actual_value: "present".to_string(),
                    limit_value: "not present".to_string(),
                });
            }
        }
    }

    // Rule: required_packages
    if !policy.rules.required_packages.is_empty() {
        rules_checked += 1;
        let missing: Vec<_> = policy
            .rules
            .required_packages
            .iter()
            .filter(|p| !package_names.contains(p.as_str()))
            .collect();
        if missing.is_empty() {
            rules_passed += 1;
        } else {
            for pkg in missing {
                violations.push(PolicyViolation {
                    rule: "required_packages".to_string(),
                    severity: ViolationSeverity::Error,
                    message: format!("Required package '{}' is not installed", pkg),
                    package: Some(pkg.clone()),
                    actual_value: "not present".to_string(),
                    limit_value: "present".to_string(),
                });
            }
        }
    }

    // Rule: banned_licenses
    if !policy.rules.banned_licenses.is_empty() {
        rules_checked += 1;
        let banned_found: Vec<_> = policy
            .rules
            .banned_licenses
            .iter()
            .filter(|l| licenses_found.contains(l.as_str()))
            .collect();
        if banned_found.is_empty() {
            rules_passed += 1;
        } else {
            for license in banned_found {
                violations.push(PolicyViolation {
                    rule: "banned_licenses".to_string(),
                    severity: ViolationSeverity::Blocking,
                    message: format!("Banned license '{}' found in dependencies", license),
                    package: None,
                    actual_value: license.clone(),
                    limit_value: "not present".to_string(),
                });
            }
        }
    }

    // Rule: allowed_licenses
    if !policy.rules.allowed_licenses.is_empty() {
        rules_checked += 1;
        let allowed_set: HashSet<&str> = policy
            .rules
            .allowed_licenses
            .iter()
            .map(|s| s.as_str())
            .collect();
        let unauthorized: Vec<_> = licenses_found
            .iter()
            .filter(|l| !allowed_set.contains(l.as_str()) && *l != "Unknown")
            .collect();
        if unauthorized.is_empty() {
            rules_passed += 1;
        } else {
            for license in unauthorized {
                violations.push(PolicyViolation {
                    rule: "allowed_licenses".to_string(),
                    severity: ViolationSeverity::Error,
                    message: format!("License '{}' is not in the allowed list", license),
                    package: None,
                    actual_value: license.clone(),
                    limit_value: format!("one of: {}", policy.rules.allowed_licenses.join(", ")),
                });
            }
        }
    }

    // Rule: ban_install_scripts
    if policy.rules.ban_install_scripts {
        rules_checked += 1;
        if packages_with_install_scripts.is_empty() {
            rules_passed += 1;
        } else {
            for pkg in &packages_with_install_scripts {
                violations.push(PolicyViolation {
                    rule: "ban_install_scripts".to_string(),
                    severity: ViolationSeverity::Warning,
                    message: format!("Package '{}' has install scripts", pkg),
                    package: Some(pkg.clone()),
                    actual_value: "has install scripts".to_string(),
                    limit_value: "no install scripts".to_string(),
                });
            }
        }
    }

    pb.finish_and_clear();

    let rules_failed = rules_checked - rules_passed;
    let is_compliant = violations
        .iter()
        .all(|v| v.severity != ViolationSeverity::Blocking);

    Ok(PolicyResult {
        policy_name: policy.name.clone(),
        violations,
        rules_checked,
        rules_passed,
        rules_failed,
        is_compliant,
    })
}

/// Scan packages to gather policy-relevant data.
fn scan_packages_for_policy(
    dir: &Path,
    depth: u32,
    total_size: &mut u64,
    package_count: &mut u64,
    package_names: &mut HashSet<String>,
    package_sizes: &mut Vec<(String, u64)>,
    licenses: &mut HashSet<String>,
    max_depth: &mut u32,
    install_script_packages: &mut Vec<String>,
) -> Result<()> {
    *max_depth = (*max_depth).max(depth);

    if depth > 10 {
        return Ok(());
    }

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

        if name_str.starts_with('.') || name_str == ".bin" {
            continue;
        }

        if name_str.starts_with('@') {
            // Scoped packages
            if let Ok(scoped) = fs::read_dir(&path) {
                for s in scoped.flatten() {
                    if s.path().is_dir() {
                        let scoped_name =
                            format!("{}/{}", name_str, s.file_name().to_str().unwrap_or(""));
                        analyze_package_for_policy(
                            &s.path(),
                            &scoped_name,
                            depth,
                            total_size,
                            package_count,
                            package_names,
                            package_sizes,
                            licenses,
                            max_depth,
                            install_script_packages,
                        )?;
                    }
                }
            }
        } else {
            analyze_package_for_policy(
                &path,
                name_str,
                depth,
                total_size,
                package_count,
                package_names,
                package_sizes,
                licenses,
                max_depth,
                install_script_packages,
            )?;
        }
    }

    Ok(())
}

fn analyze_package_for_policy(
    pkg_path: &Path,
    pkg_name: &str,
    depth: u32,
    total_size: &mut u64,
    package_count: &mut u64,
    package_names: &mut HashSet<String>,
    package_sizes: &mut Vec<(String, u64)>,
    licenses: &mut HashSet<String>,
    max_depth: &mut u32,
    install_script_packages: &mut Vec<String>,
) -> Result<()> {
    *package_count += 1;
    package_names.insert(pkg_name.to_string());

    // Estimate size
    let pkg_size = estimate_dir_size(pkg_path);
    *total_size += pkg_size;
    package_sizes.push((pkg_name.to_string(), pkg_size));

    // Read package.json
    let pkg_json_path = pkg_path.join("package.json");
    if let Ok(content) = fs::read_to_string(&pkg_json_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            // License
            if let Some(license) = json.get("license").and_then(|v| v.as_str()) {
                licenses.insert(license.to_string());
            }

            // Install scripts
            if let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) {
                if scripts.contains_key("preinstall")
                    || scripts.contains_key("install")
                    || scripts.contains_key("postinstall")
                {
                    install_script_packages.push(pkg_name.to_string());
                }
            }
        }
    }

    // Check nested node_modules
    let nested_nm = pkg_path.join("node_modules");
    if nested_nm.exists() {
        scan_packages_for_policy(
            &nested_nm,
            depth + 1,
            total_size,
            package_count,
            package_names,
            package_sizes,
            licenses,
            max_depth,
            install_script_packages,
        )?;
    }

    Ok(())
}

/// Fast directory size estimation (non-recursive, just top-level files + rough dir estimates).
fn estimate_dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                } else if meta.is_dir() {
                    total += estimate_dir_size(&entry.path());
                }
            }
        }
    }
    total
}

/// Print policy enforcement results.
pub fn print_policy_result(result: &PolicyResult) {
    println!();
    println!(
        "  {} {}",
        style("Policy Enforcement").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    println!(
        "  {} Policy: {}",
        style("◉").cyan(),
        style(&result.policy_name).white().bold()
    );
    println!(
        "  {} Rules checked: {}",
        style("◉").cyan(),
        style(result.rules_checked).white().bold()
    );
    println!(
        "  {} Rules passed: {}",
        style("◉").green(),
        style(result.rules_passed).green().bold()
    );
    println!(
        "  {} Rules failed: {}",
        style("◉").red(),
        style(result.rules_failed).red().bold()
    );

    let (warnings, errors, blockers) = result.violation_counts();

    let compliance_status = if result.is_compliant {
        style("✓ COMPLIANT").green().bold()
    } else {
        style("✗ NON-COMPLIANT").red().bold()
    };
    println!("  {} Status: {}", style("◉").bold(), compliance_status);

    if !result.violations.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Violations").white().bold(),
            style("─────────────────────────────────────").dim()
        );

        for violation in &result.violations {
            let severity_style = match violation.severity {
                ViolationSeverity::Blocking => {
                    style(format!("[{}]", violation.severity)).red().bold()
                }
                ViolationSeverity::Error => style(format!("[{}]", violation.severity)).red(),
                ViolationSeverity::Warning => style(format!("[{}]", violation.severity)).yellow(),
            };

            println!(
                "  {} {} {} {}",
                style(violation.severity.icon()).bold(),
                severity_style,
                violation.message,
                style(format!("(rule: {})", violation.rule)).dim()
            );
        }

        println!();
        println!(
            "  {} {} warnings, {} errors, {} blockers",
            style("Summary:").dim(),
            style(warnings).yellow(),
            style(errors).red(),
            style(blockers).red().bold(),
        );
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_rules() {
        let rules = PolicyRules::default();
        assert!(rules.max_total_size.is_none());
        assert!(rules.banned_packages.is_empty());
        assert!(rules.allowed_licenses.is_empty());
        assert!(!rules.ban_install_scripts);
    }

    #[test]
    fn test_violation_severity_display() {
        assert_eq!(format!("{}", ViolationSeverity::Warning), "WARNING");
        assert_eq!(format!("{}", ViolationSeverity::Error), "ERROR");
        assert_eq!(format!("{}", ViolationSeverity::Blocking), "BLOCKING");
    }

    #[test]
    fn test_policy_result_has_blockers() {
        let result = PolicyResult {
            policy_name: "test".into(),
            violations: vec![PolicyViolation {
                rule: "test".into(),
                severity: ViolationSeverity::Blocking,
                message: "test".into(),
                package: None,
                actual_value: "".into(),
                limit_value: "".into(),
            }],
            rules_checked: 1,
            rules_passed: 0,
            rules_failed: 1,
            is_compliant: false,
        };
        assert!(result.has_blockers());
    }

    #[test]
    fn test_policy_result_violation_counts() {
        let result = PolicyResult {
            policy_name: "test".into(),
            violations: vec![
                PolicyViolation {
                    rule: "a".into(),
                    severity: ViolationSeverity::Warning,
                    message: "".into(),
                    package: None,
                    actual_value: "".into(),
                    limit_value: "".into(),
                },
                PolicyViolation {
                    rule: "b".into(),
                    severity: ViolationSeverity::Error,
                    message: "".into(),
                    package: None,
                    actual_value: "".into(),
                    limit_value: "".into(),
                },
                PolicyViolation {
                    rule: "c".into(),
                    severity: ViolationSeverity::Blocking,
                    message: "".into(),
                    package: None,
                    actual_value: "".into(),
                    limit_value: "".into(),
                },
            ],
            rules_checked: 3,
            rules_passed: 0,
            rules_failed: 3,
            is_compliant: false,
        };
        let (w, e, b) = result.violation_counts();
        assert_eq!(w, 1);
        assert_eq!(e, 1);
        assert_eq!(b, 1);
    }

    #[test]
    fn test_create_example_policy() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let path = temp.path().join("policy.toml");
        create_example_policy(&path)?;
        assert!(path.exists());
        let content = fs::read_to_string(&path)?;
        assert!(content.contains("default-policy"));
        assert!(content.contains("banned_packages"));
        Ok(())
    }
}
