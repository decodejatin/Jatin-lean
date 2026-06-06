//! jatin-lean — Universal System Optimization Platform
//!
//! A high-performance CLI utility for system optimization, covering
//! node_modules pruning, system tuning, network analysis, memory
//! optimization, benchmarking, and AI-friendly context generation.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(clippy::new_without_default)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::needless_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::len_zero)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::print_literal)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::items_after_test_module)]
#![allow(clippy::unused_enumerate_index)]
#![allow(clippy::unnecessary_min_or_max)]
#![allow(clippy::mut_from_ref)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(unused_parens)]
mod adaptive_engine;
mod ai_context;
mod allocator;
mod analytics;
mod analyzer;
mod benchmark;
mod bpf_verifier;
mod cache;
mod cli;
mod compress;
mod config;
mod cpu_cache;
mod dedup;
mod deleter;
mod display;
mod distributed_cache;
mod hardware_tuning;
mod health;
mod hedging;
mod io_uring;
mod lockfile;
mod maglev;
mod memory_pool;
mod mmap;
mod mmap_ipc;
mod network;
mod network_trace;
mod output;
mod pcie_bottleneck;
mod plugin;
mod policy;
mod profiler;
mod request_coalescing;
mod ringbuffer;
mod rules;
mod scanner;
mod shared_memory_ipc;
mod simd;
mod simd_json;
mod snapshot;
mod static_plugins;
mod strategy;
mod syscall;
mod tracer;
mod treeshake;
mod unified_gateway;
mod visualizer;
mod watcher;
mod xdp_middleware;
mod zero_copy_serde;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::Confirm;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// ⚡ jatin-lean — Universal System Optimization Platform
#[derive(Parser, Debug)]
#[command(
    name = "jatin-lean",
    version,
    about = "Universal System Optimization Platform — node_modules pruning, system tuning, benchmarking & more",
    long_about = "jatin-lean v2.0 — Universal System Optimization Platform\n\n\
        Organize your workflow with category-based commands:\n\
        \n  jatin-lean node <command>      Node.js ecosystem optimization\
        \n  jatin-lean system <command>    System-level tuning\
        \n  jatin-lean network <command>   Network & eBPF tools\
        \n  jatin-lean memory <command>    Memory & IPC optimization\
        \n  jatin-lean bench <command>     Benchmarking suite\
        \n  jatin-lean analyze <command>   Analysis & reporting\
        \n  jatin-lean ai-context          AI assistant context\
        \n\nLegacy flat commands (e.g., 'jatin-lean health .') still work but show deprecation warnings.\
        \nAll commands support --json and --json-pretty for machine-readable output."
)]
struct Cli {
    /// Output results as JSON (machine-readable)
    #[arg(long, global = true)]
    json: bool,

    /// Output results as pretty-printed JSON
    #[arg(long, global = true)]
    json_pretty: bool,

    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Execute deletion (default is dry-run simulation)
    #[arg(long, short = 'f')]
    force: bool,

    /// Skip confirmation prompt (auto-confirm)
    #[arg(long, short = 'y')]
    yes: bool,

    /// Path to custom config file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Global mode — scan all projects in a directory
    #[arg(long, short = 'g')]
    global: bool,

    /// Show individual files that would be deleted
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Keep license files even when pruning documentation
    #[arg(long)]
    keep_license: bool,

    /// Maximum depth for global scan
    #[arg(long, default_value = "4")]
    max_depth: usize,

    /// Generate example config file
    #[arg(long, value_name = "FILE")]
    init_config: Option<PathBuf>,

    /// Pruning safety tier (conservative, balanced, aggressive)
    #[arg(long, value_enum)]
    profile: Option<rules::PruningProfile>,

    /// Enable performance profiling
    #[arg(long = "perf-profile")]
    perf_profile: bool,

    /// Create a snapshot before deletion (for undo support)
    #[arg(long)]
    snapshot: bool,

    /// Export scan results to a file (json, csv, or md)
    #[arg(long, value_name = "FILE")]
    export: Option<PathBuf>,

    /// Subcommands for advanced features
    #[command(subcommand)]
    command: Option<Commands>,
}

/// v2.0 Hierarchical command structure
#[derive(Subcommand, Debug)]
enum Commands {
    /// Node.js ecosystem optimization (health, dedup, deps, compress, treeshake, audit, analyze, watch, policy, visualize)
    Node {
        #[command(subcommand)]
        command: cli::NodeCommands,
    },

    /// System-level optimization (optimize, cpu-cache, io)
    System {
        #[command(subcommand)]
        command: cli::SystemCommands,
    },

    /// Network & eBPF tools (xdp, bpf, gateway)
    Network {
        #[command(subcommand)]
        command: cli::NetworkCommands,
    },

    /// Memory & IPC optimization (ipc, mmap, arena, pcie)
    Memory {
        #[command(subcommand)]
        command: cli::MemoryCommands,
    },

    /// Benchmarking suite (all, serde, json, io-uring, coalesce, hedge, maglev, static-dispatch)
    Bench {
        #[command(subcommand)]
        command: cli::BenchCommands,
    },

    /// Analysis & reporting tools (cache, dist-cache, engine, snapshots, analytics, undo, plugins)
    Analyze {
        #[command(subcommand)]
        command: cli::AnalyzeCommands,
    },

    /// Generate AI-friendly context about this tool and project
    AiContext {
        /// Path to the project directory
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    #[command(flatten)]
    Legacy(cli::legacy::LegacyCommands),
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Build output context from global flags
    let ctx = output::OutputContext {
        json: args.json || args.json_pretty,
        pretty: args.json_pretty,
        verbose: args.verbose,
    };

    // Handle --init-config flag
    if let Some(config_path) = args.init_config {
        config::Config::create_example(&config_path)?;
        if !ctx.json {
            println!(
                "  {} Example config file created: {}",
                style("✓").green().bold(),
                style(config_path.display()).cyan()
            );
            println!(
                "  {} Edit this file to customize pruning rules.",
                style("→").dim()
            );
            println!(
                "  {} Use with: {} {}",
                style("→").dim(),
                style("jatin-lean --config").yellow(),
                style(config_path.display()).cyan()
            );
        }
        return Ok(());
    }

    // Handle subcommands
    if let Some(command) = args.command {
        return handle_subcommand(command, &ctx);
    }

    // Default: run node_modules scan (backward compatible)
    if !ctx.json {
        display::print_banner();
    }

    let target = std::fs::canonicalize(&args.path)
        .with_context(|| format!("Cannot access path: {}", args.path.display()))?;

    if args.global {
        run_global_mode(&target, args.max_depth)?;
    } else {
        run_local_mode(
            &target,
            args.force,
            args.yes,
            args.verbose,
            args.config.as_deref(),
            args.keep_license,
            args.profile,
            args.perf_profile,
            args.snapshot,
            args.export.as_deref(),
        )?;
    }

    Ok(())
}

/// Handle subcommands.
fn handle_subcommand(command: Commands, ctx: &output::OutputContext) -> Result<()> {
    match command {
        Commands::Node { command } => cli::handle_node_command(command, ctx)?,
        Commands::System { command } => cli::handle_system_command(command, ctx)?,
        Commands::Network { command } => cli::handle_network_command(command, ctx)?,
        Commands::Memory { command } => cli::handle_memory_command(command, ctx)?,
        Commands::Bench { command } => cli::handle_bench_command(command, ctx)?,
        Commands::Analyze { command } => cli::handle_analyze_command(command, ctx)?,
        Commands::AiContext { path } => ai_context::handle_ai_context(path, ctx)?,
        Commands::Legacy(cmd) => cli::legacy::handle_command(cmd, ctx)?,
    }
    Ok(())
}

/// Wrapper for the CLI node scan command to call the internal runner
pub fn run_local_mode_from_args(
    path: &std::path::PathBuf,
    force: bool,
    yes: bool,
    verbose: bool,
    keep_license: bool,
    perf_profile: bool,
    snapshot: bool,
    export: Option<&std::path::Path>,
    _ctx: &output::OutputContext,
) -> Result<()> {
    let target = std::fs::canonicalize(path)?;
    run_local_mode(
        &target,
        force,
        yes,
        verbose,
        None,
        keep_license,
        None,
        perf_profile,
        snapshot,
        export,
    )
}

/// Run in local mode — scan a single project's node_modules.
fn run_local_mode(
    project_path: &Path,
    force: bool,
    yes: bool,
    verbose: bool,
    config_path: Option<&Path>,
    keep_license: bool,
    pruning_profile: Option<rules::PruningProfile>,
    perf_profile: bool,
    create_snapshot: bool,
    export_path: Option<&Path>,
) -> Result<()> {
    let mut profiler = profiler::Profiler::with_profiling(perf_profile);
    let overall_start = Instant::now();

    // Find node_modules
    let nm_path = project_path.join("node_modules");
    if !nm_path.exists() {
        println!(
            "  {} No node_modules found at {}",
            style("✗").red().bold(),
            style(project_path.display()).dim()
        );
        println!(
            "  {} Run {} first, or specify a different path.",
            style("→").dim(),
            style("npm install").yellow()
        );
        return Ok(());
    }

    // Detect recent install
    if let Some(install_info) = watcher::detect_recent_install(project_path) {
        println!(
            "  {} Detected recent {} install ({}s ago)",
            style("⚡").yellow(),
            style(&install_info.package_manager).white().bold(),
            install_info.age_seconds
        );
    }

    // Load configuration
    profiler.start_span("Config Loading");
    let mut config = config::Config::load(config_path, project_path)?;

    // Apply --keep-license flag to config
    if let Some(ref mut cfg) = config {
        cfg.keep_license = keep_license;
    }

    if let Some(ref _cfg) = config {
        let source = if config_path.is_some() {
            "custom config"
        } else if Path::new("./jatin-lean.toml").exists() {
            "./jatin-lean.toml"
        } else {
            "~/.config/jatin-lean/rules.toml"
        };
        println!(
            "  {} Using {} {}",
            style("◉").cyan(),
            style("custom rules from").dim(),
            style(source).cyan()
        );
    }
    profiler.end_span(0);

    // Phase 1: Discovery
    profiler.start_span("Discovery (Scan)");
    let rules = rules::PruneRules::new_with_config_and_profile(config, pruning_profile);
    println!(
        "  {} Using pruning profile: {}",
        style("◉").cyan(),
        style(rules.profile.name()).cyan()
    );
    let scan_result = scanner::scan_node_modules(&nm_path, &rules, None)
        .context("Failed to scan node_modules")?;
    profiler.end_span(scan_result.total_files);

    display::print_discovery(&scan_result);

    if scan_result.candidates.is_empty() {
        println!(
            "  {} node_modules is already lean! Nothing to prune.",
            style("✓").green().bold()
        );
        return Ok(());
    }

    // Phase 2: Simulation — verify runtime safety
    profiler.start_span("Runtime Safety Check");
    let runtime_files = tracer::verify_runtime_safety(&nm_path, &scan_result.candidates)
        .context("Failed to verify runtime safety")?;
    profiler.end_span(scan_result.candidates.len() as u64);

    // Filter out any candidates that are actually runtime-required
    let original_count = scan_result.candidates.len();
    let safe_candidates: Vec<_> = scan_result
        .candidates
        .iter()
        .filter(|c| !runtime_files.contains(&c.path))
        .cloned()
        .collect();
    let tracer_whitelisted = (original_count - safe_candidates.len()) as u64;

    let filtered_result = scanner::ScanResult {
        root: scan_result.root,
        total_files: scan_result.total_files,
        total_size: scan_result.total_size,
        candidates: safe_candidates,
        total_packages: scan_result.total_packages,
        whitelisted_count: scan_result.whitelisted_count + tracer_whitelisted,
    };

    display::print_simulation(&filtered_result);

    // Verbose: list individual files
    if verbose {
        println!(
            "  {} {}",
            style("Files targeted for deletion:").dim(),
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );
        let mut by_cat: std::collections::HashMap<
            rules::FileCategory,
            Vec<&scanner::PruneCandidate>,
        > = std::collections::HashMap::new();
        for c in &filtered_result.candidates {
            by_cat.entry(c.category).or_default().push(c);
        }
        for (cat, files) in &by_cat {
            println!(
                "\n  {} [{}]:",
                style("▸").cyan(),
                style(cat.label()).yellow()
            );
            for f in files.iter().take(20) {
                println!(
                    "    {} {} ({})",
                    style("·").dim(),
                    style(f.path.display()).dim(),
                    scanner::format_size(f.size)
                );
            }
            if files.len() > 20 {
                println!("    {} ...and {} more", style("·").dim(), files.len() - 20);
            }
        }
        println!();
    }

    // Export report if requested
    if let Some(export_file) = export_path {
        profiler.start_span("Report Export");
        export_report(&filtered_result, export_file)?;
        profiler.end_span(filtered_result.candidates.len() as u64);
    }

    // Phase 3 or 4
    if force {
        // Interactive confirmation (unless --yes flag is used)
        if !yes {
            println!(
                "  {} {}",
                style("Phase 3: Confirmation").cyan().bold(),
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
            );

            let savings = filtered_result.savings();
            let pct = if filtered_result.total_size > 0 {
                (savings as f64 / filtered_result.total_size as f64 * 100.0) as u64
            } else {
                0
            };

            println!(
                "  {} About to delete {} ({} files, {}% of node_modules)",
                style("⚠").yellow().bold(),
                style(scanner::format_size(savings)).yellow().bold(),
                style(scanner::format_number(
                    filtered_result.candidates.len() as u64
                ))
                .yellow(),
                style(pct).yellow()
            );

            println!();

            let confirmed = Confirm::new()
                .with_prompt("  Do you want to proceed with deletion?")
                .default(false)
                .interact()
                .unwrap_or(false);

            if !confirmed {
                println!();
                println!(
                    "  {} Deletion cancelled. No files were deleted.",
                    style("✓").green().bold()
                );
                println!(
                    "  {} Run with {} to skip this prompt next time.",
                    style("→").dim(),
                    style("--yes").yellow()
                );
                println!();
                return Ok(());
            }

            println!();
        }

        // Create snapshot before deletion if requested
        if create_snapshot {
            profiler.start_span("Snapshot Creation");
            println!("  {} Creating snapshot...", style("📸").bold());
            let manager = snapshot::SnapshotManager::new()?;
            let snap_id = manager.create_snapshot(&filtered_result.candidates, &nm_path)?;
            println!(
                "  {} Snapshot created: {}",
                style("✓").green().bold(),
                style(&snap_id).cyan()
            );
            println!(
                "  {} Undo with:    {}",
                style("→").dim(),
                style("jatin-lean undo").yellow()
            );
            println!(
                "  {} Restore with: {}",
                style("→").dim(),
                style(format!("jatin-lean restore {}", snap_id)).yellow()
            );
            profiler.end_span(filtered_result.candidates.len() as u64);
        }

        // Phase 4: Execute
        profiler.start_span("Deletion");
        println!(
            "  {} {}",
            style("Phase 4: Execution").cyan().bold(),
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );

        let result = deleter::execute_deletion(&filtered_result.candidates)
            .context("Failed to execute deletion")?;

        deleter::print_deletion_summary(&result);
        profiler.end_span(result.deleted_count);

        // Record in analytics
        let scan_duration = overall_start.elapsed().as_millis() as u64;
        if let Ok(mut db) = analytics::AnalyticsDB::load() {
            db.record_scan(
                &filtered_result,
                true,
                result.deleted_size,
                result.deleted_count,
                scan_duration,
            );
            let _ = db.save();
        }

        println!();
    } else {
        // Phase 3: Dry run confirmation
        display::print_dry_run_confirmation(&filtered_result);

        // Record in analytics (dry run)
        let scan_duration = overall_start.elapsed().as_millis() as u64;
        if let Ok(mut db) = analytics::AnalyticsDB::load() {
            db.record_scan(&filtered_result, false, 0, 0, scan_duration);
            let _ = db.save();
        }
    }

    // Print profiling report
    if perf_profile {
        profiler::print_profiling_report(&profiler);
        // Enhanced dashboard (Step 14)
        let metrics = profiler.clone().finalize();
        display::print_performance_dashboard(&metrics);
    }

    Ok(())
}

/// Export a scan report to a file.
fn export_report(scan_result: &scanner::ScanResult, path: &Path) -> Result<()> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("json");

    let content = match extension {
        "json" => analytics::generate_json_report(scan_result)?,
        "csv" => analytics::generate_csv_report(scan_result),
        "md" | "markdown" => analytics::generate_markdown_report(scan_result),
        _ => {
            println!(
                "  {} Unknown export format: {}. Using JSON.",
                style("⚠").yellow(),
                extension
            );
            analytics::generate_json_report(scan_result)?
        }
    };

    std::fs::write(path, &content)
        .with_context(|| format!("Failed to write report: {}", path.display()))?;

    println!(
        "  {} Report exported to: {}",
        style("✓").green().bold(),
        style(path.display()).cyan()
    );

    Ok(())
}

/// Run in global mode — scan all projects in a directory.
fn run_global_mode(root: &Path, max_depth: usize) -> Result<()> {
    println!(
        "  {} Scanning for node_modules in {}...",
        style("◉").cyan(),
        style(root.display()).white().bold()
    );

    let node_modules_dirs = scanner::find_node_modules(root, max_depth);

    if node_modules_dirs.is_empty() {
        println!(
            "  {} No node_modules directories found.",
            style("✗").red().bold()
        );
        return Ok(());
    }

    println!(
        "  {} Found {} node_modules directories. Analyzing...\n",
        style("◉").cyan(),
        style(node_modules_dirs.len()).white().bold()
    );

    let rules = rules::PruneRules::new();
    let mut projects: Vec<(String, u64, u64, Option<u64>)> = Vec::new();

    for nm_path in &node_modules_dirs {
        let project_dir = nm_path.parent().unwrap_or(nm_path);
        let project_name = project_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match scanner::scan_node_modules(nm_path, &rules, None) {
            Ok(result) => {
                let savings = result.savings();
                let days = scanner::last_accessed_days(nm_path);
                projects.push((project_name, result.total_size, savings, days));
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to scan {}: {}",
                    style("⚠").yellow(),
                    nm_path.display(),
                    e
                );
            }
        }
    }

    display::print_global_table(&projects);

    let total_savings: u64 = projects.iter().map(|(_, _, s, _)| s).sum();
    println!(
        "  {} Total potential savings: {}",
        style("💾").bold(),
        style(scanner::format_size(total_savings)).green().bold()
    );
    println!(
        "  {} Run {} on individual projects to prune.",
        style("→").dim(),
        style("jatin-lean <path> --force").yellow()
    );
    println!(
        "  {} Made with ❤️  by {}\n",
        style("✨").dim(),
        style("Jatin Jalandhra").cyan(),
    );

    Ok(())
}
