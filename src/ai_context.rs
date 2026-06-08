//! AI-friendly context generation for jatin-lean.
//!
//! Provides the `ai-context` command that outputs structured information
//! about the tool's capabilities, the current project, and the system.

use crate::output::OutputContext;
use anyhow::Result;
use console::style;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub struct AiContext {
    tool: String,
    version: String,
    capabilities: Vec<String>,
    quick_commands: QuickCommands,
    project_context: Option<ProjectContext>,
    system_context: SystemContext,
}

#[derive(Serialize)]
struct QuickCommands {
    scan_node_modules: String,
    prune_node_modules: String,
    system_assessment: String,
    network_benchmark: String,
    memory_benchmark: String,
}

#[derive(Serialize)]
struct ProjectContext {
    has_node_modules: bool,
    node_modules_size_bytes: u64,
    node_modules_packages: usize,
    potential_savings_bytes: u64,
    frameworks_detected: Vec<String>,
    package_manager: String,
}

#[derive(Serialize)]
struct SystemContext {
    os: String,
    arch: String,
    cpu_cores: usize,
    simd_tier: String,
}

/// Handle the `ai-context` command.
pub fn handle_ai_context(path: PathBuf, ctx: &OutputContext) -> Result<()> {
    let target = std::fs::canonicalize(&path)?;
    let nm_path = target.join("node_modules");

    // Detect project context
    let project_ctx = if nm_path.exists() {
        let rules = crate::rules::PruneRules::new();
        let scan_result = crate::scanner::scan_node_modules(&nm_path, &rules, &[], None)?;
        let analysis = crate::analyzer::analyze_project(&nm_path)?;

        Some(ProjectContext {
            has_node_modules: true,
            node_modules_size_bytes: scan_result.total_size,
            node_modules_packages: scan_result.total_packages as usize,
            potential_savings_bytes: scan_result.savings(),
            frameworks_detected: analysis
                .package_analyses
                .iter()
                .flat_map(|a| a.frameworks.iter().map(|f| f.label().to_string()))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
            package_manager: detect_package_manager(&target),
        })
    } else {
        None
    };

    // Detect system context
    let caps = crate::simd::CpuCapabilities::detect();
    let system_ctx = SystemContext {
        os: std::env::consts::OS.to_string(),
        arch: caps.arch.to_string(),
        cpu_cores: num_cpus::get(),
        simd_tier: caps.tier_name().to_string(),
    };

    let ai_context = AiContext {
        tool: "jatin-lean".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "node_modules_optimization".to_string(),
            "system_performance_tuning".to_string(),
            "network_ebpf_tools".to_string(),
            "memory_ipc_optimization".to_string(),
            "comprehensive_benchmarking".to_string(),
        ],
        quick_commands: QuickCommands {
            scan_node_modules: "jatin-lean node scan [path]".to_string(),
            prune_node_modules: "jatin-lean node prune [path] --force".to_string(),
            system_assessment: "jatin-lean system optimize --assess".to_string(),
            network_benchmark: "jatin-lean network xdp --bench".to_string(),
            memory_benchmark: "jatin-lean memory ipc --bench".to_string(),
        },
        project_context: project_ctx,
        system_context: system_ctx,
    };

    if ctx.json {
        crate::output::output_result("ai-context", &ai_context, ctx)?;
    } else {
        // Human-readable output
        println!();
        println!(
            "  {} {}",
            style("AI Context").cyan().bold(),
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );
        println!(
            "  {} Tool: {} v{}",
            style("◉").cyan(),
            style(&ai_context.tool).white().bold(),
            style(&ai_context.version).green()
        );
        println!();
        println!("  {} Capabilities:", style("🎯").yellow());
        for cap in &ai_context.capabilities {
            println!("    {} {}", style("→").dim(), cap);
        }
        println!();
        println!("  {} Quick Commands:", style("⚡").yellow());
        println!(
            "    {} {}",
            style("→").dim(),
            style(&ai_context.quick_commands.scan_node_modules).green()
        );
        println!(
            "    {} {}",
            style("→").dim(),
            style(&ai_context.quick_commands.prune_node_modules).green()
        );
        println!(
            "    {} {}",
            style("→").dim(),
            style(&ai_context.quick_commands.system_assessment).green()
        );
        println!(
            "    {} {}",
            style("→").dim(),
            style(&ai_context.quick_commands.network_benchmark).green()
        );
        println!(
            "    {} {}",
            style("→").dim(),
            style(&ai_context.quick_commands.memory_benchmark).green()
        );
        println!();
        if let Some(ref pc) = ai_context.project_context {
            println!("  {} Project:", style("📦").yellow());
            println!(
                "    node_modules: {} ({} packages)",
                style(crate::scanner::format_size(pc.node_modules_size_bytes))
                    .white()
                    .bold(),
                pc.node_modules_packages
            );
            println!(
                "    Savings:      {}",
                style(crate::scanner::format_size(pc.potential_savings_bytes)).green()
            );
            println!(
                "    Frameworks:   {}",
                style(pc.frameworks_detected.join(", ")).cyan()
            );
            println!("    Pkg manager:  {}", style(&pc.package_manager).white());
            println!();
        } else {
            println!(
                "  {} No node_modules found at current path",
                style("ℹ").blue()
            );
            println!();
        }
        println!(
            "  {} System: {} / {} / {} cores / SIMD: {}",
            style("🖥️").yellow(),
            style(&ai_context.system_context.os).white(),
            style(&ai_context.system_context.arch).white(),
            ai_context.system_context.cpu_cores,
            style(&ai_context.system_context.simd_tier).green()
        );
        println!();
        println!(
            "  {} For JSON output, use: {}",
            style("→").dim(),
            style("jatin-lean ai-context --json").yellow()
        );
        println!();
    }

    Ok(())
}

fn detect_package_manager(path: &Path) -> String {
    if path.join("package-lock.json").exists() {
        "npm".to_string()
    } else if path.join("yarn.lock").exists() {
        "yarn".to_string()
    } else if path.join("pnpm-lock.yaml").exists() {
        "pnpm".to_string()
    } else if path.join("bun.lockb").exists() {
        "bun".to_string()
    } else {
        "unknown".to_string()
    }
}
