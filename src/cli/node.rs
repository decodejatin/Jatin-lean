//! Node.js ecosystem optimization commands.

use crate::output::OutputContext;
use anyhow::Result;
use clap::Subcommand;
use console::style;
use std::path::PathBuf;
use std::process::Command;

#[derive(Subcommand, Debug)]
pub enum NodeCommands {
    /// Scan node_modules for optimization opportunities (dry-run)
    Scan {
        /// Path to project directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show individual files
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Execute deletion (default is dry-run)
        #[arg(long, short = 'f')]
        force: bool,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,

        /// Create snapshot before deletion
        #[arg(long)]
        snapshot: bool,

        /// Enable performance profiling
        #[arg(long)]
        profile: bool,

        /// Export results to file (json, csv, md)
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,
    },

    /// Prune non-essential files from node_modules
    Prune {
        /// Path to project directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Execute deletion (default is dry-run)
        #[arg(long, short = 'f')]
        force: bool,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,

        /// Create snapshot before deletion
        #[arg(long)]
        snapshot: bool,

        /// Show individual files
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Run comprehensive health check on node_modules
    Health {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Find duplicate files across packages
    Dedup {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Analyze dependency graph from lock files
    Deps {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Analyze compression potential (gzip/brotli)
    Compress {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Analyze tree-shaking potential and dead exports
    Treeshake {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Audit installed packages
    Audit {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Analyze project structure and detect frameworks
    Analyze {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Watch node_modules for changes and auto-prune
    Watch {
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Polling interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Automatically prune on changes
        #[arg(long)]
        auto_prune: bool,

        /// Maximum prune cycles (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_cycles: u64,
    },

    /// Enforce dependency policies
    Policy {
        /// Path to policy file (TOML or JSON)
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,

        /// Generate example policy file
        #[arg(long, value_name = "FILE")]
        init: Option<PathBuf>,

        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Render visual analysis of node_modules
    Visualize {
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show treemap of package sizes
        #[arg(long)]
        treemap: bool,

        /// Show size sparklines
        #[arg(long)]
        sparklines: bool,
    },

    /// Print Node.js binding and build environment diagnostics
    Version,
}

pub fn handle_command(command: NodeCommands, ctx: &OutputContext) -> Result<()> {
    match command {
        NodeCommands::Scan {
            path,
            verbose,
            force,
            yes,
            snapshot,
            profile,
            export,
        } => {
            // keep_license is not exposed on the node scan subcommand; default to false
            crate::run_local_mode_from_args(
                &path,
                force,
                yes,
                verbose,
                false,
                profile,
                snapshot,
                export.as_deref(),
                ctx,
            )
        }
        NodeCommands::Prune {
            path,
            force,
            yes,
            snapshot,
            verbose,
        } => {
            // keep_license is not exposed on the node prune subcommand; default to false
            crate::run_local_mode_from_args(
                &path, force, yes, verbose, false, false, snapshot, None, ctx,
            )
        }
        NodeCommands::Health { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node health", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            let report = crate::health::check_health(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node health",
                    &serde_json::json!({
                        "grade": report.grade.label(),
                        "score": report.score,
                        "total_packages": report.packages_analyzed,
                        "total_size_bytes": report.total_size,
                    }),
                    ctx,
                )?;
            } else {
                crate::display::print_banner();
                crate::health::print_health_report(&report);
            }
            Ok(())
        }
        NodeCommands::Dedup { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node dedup", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let result = crate::dedup::find_duplicates(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node dedup",
                    &serde_json::json!({
                        "duplicate_groups": result.duplicate_groups.len(),
                        "wasted_bytes": result.total_wasted,
                    }),
                    ctx,
                )?;
            } else {
                crate::dedup::print_dedup_results(&result);
            }
            Ok(())
        }
        NodeCommands::Deps { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !ctx.json {
                crate::display::print_banner();
            }
            let graph = crate::lockfile::DependencyGraph::from_project(&target)?;
            if ctx.json {
                crate::output::output_result(
                    "node deps",
                    &serde_json::json!({
                        "total_dependencies": graph.total_deps(),
                        "direct_dependencies": graph.direct_deps,
                    }),
                    ctx,
                )?;
            } else {
                crate::lockfile::print_dep_graph_summary(&graph, &nm_path);
            }
            Ok(())
        }
        NodeCommands::Compress { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node compress", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let result = crate::compress::analyze_compression(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node compress",
                    &serde_json::json!({
                        "original_bytes": result.total_original_size,
                        "gzip_bytes": result.total_gzip_size,
                        "brotli_bytes": result.total_brotli_size,
                    }),
                    ctx,
                )?;
            } else {
                crate::compress::print_compression_results(&result);
            }
            Ok(())
        }
        NodeCommands::Treeshake { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node treeshake", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let result = crate::treeshake::analyze_treeshake(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node treeshake",
                    &serde_json::json!({
                        "total_exports": result.total_exports,
                        "unused_exports": result.unused_exports,
                        "estimated_dead_bytes": result.estimated_dead_code_bytes,
                    }),
                    ctx,
                )?;
            } else {
                crate::treeshake::print_treeshake_results(&result);
            }
            Ok(())
        }
        NodeCommands::Audit { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node audit", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let installed = crate::network::scan_installed_packages(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node audit",
                    &serde_json::json!({
                        "installed_packages": installed.len(),
                    }),
                    ctx,
                )?;
            } else {
                println!(
                    "  {} Found {} installed packages",
                    style("◉").cyan(),
                    style(installed.len()).white().bold()
                );
                println!(
                    "  {} Note: Version auditing requires network access.",
                    style("ℹ").blue()
                );
                for (name, version) in installed.iter().take(25) {
                    println!("  {} {}@{}", style("·").dim(), name, style(version).dim());
                }
                if installed.len() > 25 {
                    println!(
                        "  {} ...and {} more",
                        style("·").dim(),
                        installed.len() - 25
                    );
                }
            }
            Ok(())
        }
        NodeCommands::Analyze { path } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node analyze", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let analysis = crate::analyzer::analyze_project(&nm_path)?;
            if ctx.json {
                crate::output::output_result(
                    "node analyze",
                    &serde_json::json!({
                        "packages": analysis.package_analyses.len(),
                    }),
                    ctx,
                )?;
            } else {
                crate::analyzer::print_analysis(&analysis);
                let engine = crate::strategy::StrategyEngine::new();
                let profiles: Vec<crate::strategy::PackageProfile> = analysis
                    .package_analyses
                    .iter()
                    .map(|a| crate::strategy::PackageProfile {
                        name: a.name.clone(),
                        file_count: a.file_count as i64,
                        total_size: a.total_size,
                        has_package_json: true,
                        has_native_bindings: a.has_native,
                        is_scoped: a.name.starts_with('@'),
                        is_cached: false,
                        framework: a.frameworks.first().map(|f| f.label().to_string()),
                        previous_scan_time: None,
                    })
                    .collect();
                let strategies = engine.select_batch(&profiles);
                let summary = engine.strategy_summary(&strategies);
                summary.print();
            }
            Ok(())
        }
        NodeCommands::Watch {
            path,
            interval,
            auto_prune,
            max_cycles,
        } => {
            let target = std::fs::canonicalize(&path)?;
            if !ctx.json {
                crate::display::print_banner();
            }
            let should_prune = auto_prune;
            let config = crate::watcher::WatcherConfig {
                debounce_secs: interval,
                auto_prune,
                max_cycles,
            };
            let mut w = crate::watcher::LockfileWatcher::new(target.clone(), config);
            w.watch(|project_path| {
                let nm_path = project_path.join("node_modules");
                if !nm_path.exists() {
                    if ctx.json {
                        crate::output::output_error(
                            "node watch",
                            "No node_modules found; skipping",
                            ctx,
                        )?;
                    }
                    return Ok(());
                }
                if should_prune {
                    crate::run_local_mode_from_args(
                        &project_path.to_path_buf(),
                        true,
                        true,
                        false,
                        false,
                        false,
                        false,
                        None,
                        ctx,
                    )?;
                } else {
                    let rules = crate::rules::PruneRules::new();
                    let scan_result =
                        crate::scanner::scan_node_modules(&nm_path, &rules, None)?;
                    if ctx.json {
                        crate::output::output_result(
                            "node watch_event",
                            &serde_json::json!({
                                "event": "scan_completed",
                                "candidates": scan_result.candidates.len(),
                            }),
                            ctx,
                        )?;
                    } else {
                        crate::display::print_discovery(&scan_result);
                        crate::display::print_simulation(&scan_result);
                    }
                }
                Ok(())
            })?;
            Ok(())
        }
        NodeCommands::Policy { file, init, path } => {
            if let Some(init_path) = init {
                crate::policy::create_example_policy(&init_path)?;
                if ctx.json {
                    crate::output::output_result(
                        "node policy",
                        &serde_json::json!({
                            "policy_created": init_path.display().to_string()
                        }),
                        ctx,
                    )?;
                } else {
                    println!(
                        "  {} Example policy created: {}",
                        style("✓").green().bold(),
                        style(init_path.display()).cyan()
                    );
                }
                return Ok(());
            }
            if let Some(policy_file) = file {
                let target = std::fs::canonicalize(&path)?;
                let nm_path = target.join("node_modules");
                if !nm_path.exists() {
                    if ctx.json {
                        crate::output::output_error("node policy", "No node_modules found", ctx)?;
                    } else {
                        println!(
                            "  {} No node_modules found at {}",
                            style("✗").red().bold(),
                            style(target.display()).dim()
                        );
                    }
                    return Ok(());
                }
                if !ctx.json {
                    crate::display::print_banner();
                }
                let p = crate::policy::load_policy(&policy_file)?;
                let result = crate::policy::enforce_policy(&p, &nm_path)?;
                if ctx.json {
                    let violations_json: Vec<String> = result
                        .violations
                        .iter()
                        .map(|v| format!("{:?}", v))
                        .collect();
                    crate::output::output_result(
                        "node policy",
                        &serde_json::json!({
                            "is_compliant": result.is_compliant,
                            "violations": violations_json,
                        }),
                        ctx,
                    )?;
                } else {
                    crate::policy::print_policy_result(&result);
                }
                if !result.is_compliant {
                    std::process::exit(1);
                }
            } else {
                if ctx.json {
                    crate::output::output_error("node policy", "No policy file specified", ctx)?;
                } else {
                    println!(
                        "  {} Specify a policy file with {} or generate one with {}",
                        style("ℹ").blue(),
                        style("--file <FILE>").yellow(),
                        style("--init <FILE>").yellow()
                    );
                }
            }
            Ok(())
        }
        NodeCommands::Visualize {
            path,
            treemap,
            sparklines,
        } => {
            let target = std::fs::canonicalize(&path)?;
            let nm_path = target.join("node_modules");
            if !nm_path.exists() {
                if ctx.json {
                    crate::output::output_error("node visualize", "No node_modules found", ctx)?;
                } else {
                    println!(
                        "  {} No node_modules found at {}",
                        style("✗").red().bold(),
                        style(target.display()).dim()
                    );
                }
                return Ok(());
            }
            if !ctx.json {
                crate::display::print_banner();
            }
            let rules = crate::rules::PruneRules::new();
            let scan_result = crate::scanner::scan_node_modules(&nm_path, &rules, None)?;

            if ctx.json {
                crate::output::output_result(
                    "node visualize",
                    &serde_json::json!({
                        "visualize_ready": true,
                        "items": scan_result.candidates.len()
                    }),
                    ctx,
                )?;
            } else {
                if treemap || (!treemap && !sparklines) {
                    let mut by_cat: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    for c in &scan_result.candidates {
                        *by_cat.entry(c.category.label().to_string()).or_default() += c.size;
                    }
                    let children: Vec<crate::visualizer::TreemapNode> = by_cat
                        .iter()
                        .map(|(name, size)| crate::visualizer::TreemapNode::new(name, *size))
                        .collect();
                    let root = crate::visualizer::TreemapNode::with_children(
                        "node_modules (prunable)",
                        children,
                    );
                    crate::visualizer::render_treemap(&root, 60);
                }
                if sparklines {
                    let pkg_data = crate::scanner::package_sizes(&nm_path);
                    let mut entries: Vec<crate::visualizer::BarChartEntry> = pkg_data
                        .iter()
                        .take(20)
                        .map(|(name, size)| crate::visualizer::BarChartEntry {
                            label: name.clone(),
                            value: *size as f64,
                            display_value: crate::scanner::format_size(*size),
                        })
                        .collect();
                    entries.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
                    crate::visualizer::render_bar_chart("Top 20 Packages by Size", &entries, 40);
                }
            }
            Ok(())
        }
        NodeCommands::Version => {
            let target_triple = option_env!("JATIN_LEAN_TARGET")
                .unwrap_or(current_target_triple())
                .to_string();
            let node_version = detect_node_version();
            let rustc_version = option_env!("JATIN_LEAN_RUSTC_VERSION")
                .unwrap_or("unknown")
                .to_string();

            if ctx.json {
                crate::output::output_result(
                    "node version",
                    &serde_json::json!({
                        "target_triple": target_triple,
                        "napi_bindings_version": env!("CARGO_PKG_VERSION"),
                        "node_version": node_version,
                        "rustc_version": rustc_version,
                    }),
                    ctx,
                )?;
            } else {
                println!("{}", style("Node diagnostics").cyan().bold());
                println!("  target triple: {}", style(target_triple).white().bold());
                println!(
                    "  N-API bindings version: {}",
                    style(env!("CARGO_PKG_VERSION")).white().bold()
                );
                println!("  Node.js version: {}", style(node_version).white().bold());
                println!("  Rust compiler: {}", style(rustc_version).white().bold());
            }

            Ok(())
        }
    }
}

fn current_target_triple() -> &'static str {
    match (
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::env::consts::FAMILY,
    ) {
        ("x86_64", "linux", _) => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux", _) => "aarch64-unknown-linux-gnu",
        ("x86_64", "macos", _) => "x86_64-apple-darwin",
        ("aarch64", "macos", _) => "aarch64-apple-darwin",
        ("x86_64", "windows", _) => "x86_64-pc-windows-msvc",
        ("aarch64", "windows", _) => "aarch64-pc-windows-msvc",
        _ => "unknown",
    }
}

fn detect_node_version() -> String {
    Command::new("node")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}
