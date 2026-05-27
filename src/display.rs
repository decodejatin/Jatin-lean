//! Display and reporting module: terminal UI for scan results.

use crate::scanner::{format_number, format_size, ScanResult};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;

/// Print the Phase 1: Discovery summary.
pub fn print_discovery(result: &ScanResult) {
    if is_silent() {
        return;
    }
    println!();
    println!(
        "  {} {}",
        style("Phase 1: Discovery").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!(
        "  {} Scanning node_modules... Found {} files across {} packages.",
        style("◉").cyan(),
        style(format_number(result.total_files)).white().bold(),
        style(format_number(result.total_packages as u64))
            .white()
            .bold(),
    );
    println!(
        "  {} Total size indexed: {}",
        style("◉").cyan(),
        style(format_size(result.total_size)).white().bold(),
    );
    println!();
}

/// Print the Phase 2: Simulation summary.
pub fn print_simulation(result: &ScanResult) {
    if is_silent() {
        return;
    }
    let savings = result.savings();
    let breakdown = result.category_breakdown();

    println!(
        "  {} {}",
        style("Phase 2: Simulation").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!(
        "  {} Analyzing dependency tree... {} files ({}) identified as non-runtime assets.",
        style("◉").cyan(),
        style(format_number(result.candidates.len() as u64))
            .yellow()
            .bold(),
        style(format_size(savings)).yellow().bold(),
    );

    if result.whitelisted_count > 0 {
        println!(
            "  {} {} files auto-whitelisted (required at runtime).",
            style("◉").green(),
            style(format_number(result.whitelisted_count))
                .green()
                .bold(),
        );
    }

    // Category breakdown table
    println!();
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Category").fg(Color::Cyan),
            Cell::new("Files").fg(Color::Cyan),
            Cell::new("Size").fg(Color::Cyan),
            Cell::new("Risk").fg(Color::Cyan),
        ]);

    let mut sorted: Vec<_> = breakdown.iter().collect();
    sorted.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));

    for (cat, (count, size)) in &sorted {
        let risk_str = match cat.risk_level() {
            0 => "▪ Low",
            1 => "▪▪ Medium",
            _ => "▪▪▪ High",
        };
        let risk_color = match cat.risk_level() {
            0 => Color::Green,
            1 => Color::Yellow,
            _ => Color::Red,
        };
        table.add_row(vec![
            Cell::new(cat.label()),
            Cell::new(format_number(*count)),
            Cell::new(format_size(*size)),
            Cell::new(risk_str).fg(risk_color),
        ]);
    }

    // Total row
    let total_count: u64 = breakdown.values().map(|(c, _)| c).sum();
    table.add_row(vec![
        Cell::new("TOTAL").fg(Color::White),
        Cell::new(format_number(total_count)).fg(Color::White),
        Cell::new(format_size(savings)).fg(Color::White),
        Cell::new(result.risk_label()).fg(Color::Yellow),
    ]);

    for line in table.to_string().lines() {
        println!("    {}", line);
    }
    println!();
}

/// Print the Phase 3: Confirmation (dry run).
pub fn print_dry_run_confirmation(result: &ScanResult) {
    if is_silent() {
        return;
    }
    let savings = result.savings();
    let pct = if result.total_size > 0 {
        (savings as f64 / result.total_size as f64 * 100.0) as u64
    } else {
        0
    };

    println!(
        "  {} {}",
        style("Phase 3: Confirmation").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );

    if result.max_risk() <= 1 {
        println!(
            "  {} No critical runtime files targeted.",
            style("[SAFE]").green().bold()
        );
    } else {
        println!(
            "  {} Some higher-risk files included. Review the breakdown above.",
            style("[REVIEW]").yellow().bold()
        );
    }

    println!(
        "\n  {} Total Savings: {} ({}% of node_modules)",
        style("💾").bold(),
        style(format_size(savings)).green().bold(),
        style(pct).green().bold(),
    );
    println!(
        "  {} This will NOT affect {} or {}.",
        style("ℹ").blue(),
        style("npm start").white().bold(),
        style("npm build").white().bold(),
    );
    println!(
        "\n  {} Run with {} to execute deletion.",
        style("→").dim(),
        style("--force").yellow().bold(),
    );
    println!(
        "  {} Made with ❤️  by {}",
        style("✨").dim(),
        style("Jatin Jalandhra").cyan(),
    );
    println!();
}

/// Print the global scan table.
pub fn print_global_table(projects: &[(String, u64, u64, Option<u64>)]) {
    if is_silent() {
        return;
    }
    println!();
    println!(
        "  {} {}",
        style("System Efficiency Report").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Project").fg(Color::Cyan),
            Cell::new("Size").fg(Color::Cyan),
            Cell::new("Potential Savings").fg(Color::Cyan),
            Cell::new("Last Accessed").fg(Color::Cyan),
        ]);

    let mut total_size: u64 = 0;
    let mut total_savings: u64 = 0;

    for (name, size, savings, days) in projects {
        total_size += size;
        total_savings += savings;

        let days_str = match days {
            Some(d) if *d > 90 => format!("{} days ago", d),
            Some(d) => format!("{} days ago", d),
            None => "Unknown".to_string(),
        };

        let days_color = match days {
            Some(d) if *d > 90 => Color::Red,
            Some(d) if *d > 30 => Color::Yellow,
            _ => Color::Green,
        };

        table.add_row(vec![
            Cell::new(name),
            Cell::new(format_size(*size)),
            Cell::new(format_size(*savings)).fg(Color::Green),
            Cell::new(&days_str).fg(days_color),
        ]);
    }

    table.add_row(vec![
        Cell::new("TOTAL").fg(Color::White),
        Cell::new(format_size(total_size)).fg(Color::White),
        Cell::new(format_size(total_savings)).fg(Color::Green),
        Cell::new("—"),
    ]);

    for line in table.to_string().lines() {
        println!("    {}", line);
    }
    println!();
}

/// Print the banner.
pub fn print_banner() {
    if is_silent() {
        return;
    }
    println!();
    println!(
        "  {}",
        style("╔═══════════════════════════════════════════════╗").cyan()
    );
    println!(
        "  {}  {}  {}",
        style("║").cyan(),
        style("⚡ jatin-lean — Node Modules Pruner ⚡")
            .white()
            .bold(),
        style("║").cyan()
    );
    println!(
        "  {}  {}  {}",
        style("║").cyan(),
        style("   Slim your node_modules by up to 50%   ").dim(),
        style("║").cyan()
    );
    println!(
        "  {}  {}  {}",
        style("║").cyan(),
        style("        Created by Jatin Jalandhra        ").dim(),
        style("║").cyan()
    );
    println!(
        "  {}",
        style("╚═══════════════════════════════════════════════╝").cyan()
    );
    println!();
}

/// Print enhanced performance metrics dashboard (Step 14).
pub fn print_performance_dashboard(metrics: &crate::profiler::PerformanceMetrics) {
    if is_silent() {
        return;
    }
    println!();
    println!(
        "  {} {}",
        style("Performance Dashboard").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );

    // Throughput metrics
    println!();
    println!(
        "  {} {}",
        style("Throughput").white().bold(),
        style("─────────────────────────────").dim()
    );
    println!(
        "  {} Files/sec: {}",
        style("⚡").yellow(),
        style(format!("{:.0}", metrics.files_per_second))
            .green()
            .bold(),
    );
    println!(
        "  {} MB/sec: {}",
        style("⚡").yellow(),
        style(format!("{:.2}", metrics.bytes_per_second / 1_000_000.0))
            .green()
            .bold(),
    );
    println!(
        "  {} Packages: {} at {}/pkg avg",
        style("📦").dim(),
        style(metrics.packages_scanned).white().bold(),
        style(crate::profiler::format_duration(
            metrics.avg_time_per_package
        ))
        .dim(),
    );

    // Phase breakdown
    println!();
    println!(
        "  {} {}",
        style("Phase Breakdown").white().bold(),
        style("─────────────────────────────").dim()
    );

    let phases = [
        ("Discovery", metrics.phase_breakdown.discovery),
        ("Parsing", metrics.phase_breakdown.parsing),
        ("Walking", metrics.phase_breakdown.walking),
        ("Classification", metrics.phase_breakdown.classification),
        ("Tracing", metrics.phase_breakdown.tracing),
        ("Deletion", metrics.phase_breakdown.deletion),
    ];

    let total_ms = metrics.total_duration.as_millis().max(1) as f64;

    for (name, duration) in &phases {
        let ms = duration.as_millis() as f64;
        let pct = (ms / total_ms * 100.0) as u64;
        let bar_len = (pct as usize).min(30);
        let bar: String = "█".repeat(bar_len);
        let pad: String = "░".repeat(30 - bar_len);

        println!(
            "  {} {:15} {} {}{}  {}",
            style("▸").dim(),
            name,
            style(crate::profiler::format_duration(*duration)).cyan(),
            style(&bar).green(),
            style(&pad).dim(),
            style(format!("{}%", pct)).dim(),
        );
    }

    // Bottleneck analysis
    if !metrics.bottlenecks.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Bottlenecks").yellow().bold(),
            style("─────────────────────────────").dim()
        );

        for bottleneck in metrics.bottlenecks.iter().take(5) {
            let severity_bar = match bottleneck.severity {
                1..=3 => style("▪▪▪░░░░░░░").green(),
                4..=6 => style("▪▪▪▪▪▪░░░░").yellow(),
                7..=8 => style("▪▪▪▪▪▪▪▪░░").red(),
                _ => style("▪▪▪▪▪▪▪▪▪▪").red().bold(),
            };

            println!(
                "  {} {} [{}] {}  {}",
                severity_bar,
                style(&bottleneck.name).yellow(),
                &bottleneck.operation,
                style(crate::profiler::format_duration(bottleneck.duration)).cyan(),
                style(&bottleneck.reason).dim(),
            );
        }

        // Optimization suggestions
        println!();
        println!(
            "  {} {}",
            style("Suggestions").white().bold(),
            style("─────────────────────────────").dim()
        );

        let io_pct = metrics.phase_breakdown.io_time.as_millis() as f64 / total_ms * 100.0;
        if io_pct > 50.0 {
            println!(
                "  {} I/O bound ({:.0}% in I/O) — consider SSD or memory-mapped cache",
                style("💡").yellow(),
                io_pct,
            );
        }

        if metrics.packages_scanned > 200 {
            println!(
                "  {} Large project ({} packages) — enable distributed cache for faster re-scans",
                style("💡").yellow(),
                metrics.packages_scanned,
            );
        }

        if metrics.bottlenecks.iter().any(|b| b.severity >= 8) {
            println!(
                "  {} Critical bottlenecks detected — consider using {} for targeted pruning",
                style("💡").yellow(),
                style("--config").cyan(),
            );
        }

        if metrics.avg_time_per_package > std::time::Duration::from_millis(50) {
            println!(
                "  {} Slow per-package scanning — enable adaptive strategy with {} for speedup",
                style("💡").yellow(),
                style("--profile").cyan(),
            );
        }
    }

    println!();
}
