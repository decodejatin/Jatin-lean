//! Deletion engine: atomic batch file removal with error resilience.

use crate::scanner::{format_number, format_size, PruneCandidate};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug)]
pub struct DeletionResult {
    pub deleted_count: u64,
    pub deleted_size: u64,
    pub failures: Vec<(PathBuf, String)>,
    pub duration: std::time::Duration,
}

pub fn execute_deletion(candidates: &[PruneCandidate]) -> Result<DeletionResult> {
    let start = Instant::now();
    let mut by_package: HashMap<String, Vec<&PruneCandidate>> = HashMap::new();
    for c in candidates {
        by_package
            .entry(c.package_name.clone())
            .or_default()
            .push(c);
    }

    let total_size: u64 = candidates.iter().map(|c| c.size).sum();
    let pb = ProgressBar::new(total_size);
    if crate::display::is_silent() {
        pb.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} Cleaning... [{bar:30.green/dim}] {percent}% | Deleted {msg}",
        )
        .unwrap()
        .progress_chars("██░")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut deleted_count: u64 = 0;
    let mut deleted_size: u64 = 0;
    let mut failures: Vec<(PathBuf, String)> = Vec::new();

    for files in by_package.values() {
        for candidate in files {
            match fs::remove_file(&candidate.path) {
                Ok(()) => {
                    deleted_count += 1;
                    deleted_size += candidate.size;
                    pb.set_position(deleted_size);
                    pb.set_message(format_size(deleted_size));
                }
                Err(e) => {
                    failures.push((candidate.path.clone(), e.to_string()));
                }
            }
        }
    }

    // Clean empty directories
    let mut dirs: Vec<PathBuf> = candidates
        .iter()
        .filter_map(|c| c.path.parent().map(|p| p.to_path_buf()))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));
    for dir in dirs {
        if dir.is_dir() {
            if let Ok(mut entries) = fs::read_dir(&dir) {
                if entries.next().is_none() {
                    let _ = fs::remove_dir(&dir);
                }
            }
        }
    }

    pb.finish_and_clear();

    Ok(DeletionResult {
        deleted_count,
        deleted_size,
        failures,
        duration: start.elapsed(),
    })
}

pub fn print_deletion_summary(result: &DeletionResult) {
    if crate::display::is_silent() {
        return;
    }
    println!(
        "  {} Deleted {} ({} files) in {:.1}s",
        console::style("✓").green().bold(),
        console::style(format_size(result.deleted_size))
            .green()
            .bold(),
        format_number(result.deleted_count),
        result.duration.as_secs_f64()
    );
    if !result.failures.is_empty() {
        println!(
            "  {} {} files could not be deleted (locked/permission denied):",
            console::style("⚠").yellow(),
            result.failures.len()
        );
        for (path, err) in result.failures.iter().take(5) {
            println!(
                "    {} {} — {}",
                console::style("→").dim(),
                path.display(),
                err
            );
        }
        if result.failures.len() > 5 {
            println!(
                "    {} ...and {} more",
                console::style("→").dim(),
                result.failures.len() - 5
            );
        }
    }
    println!(
        "\n  {} Your node_modules is now leaner and faster!",
        console::style("🎉").bold()
    );
    println!(
        "  {} Made with ❤️  by {}",
        console::style("✨").dim(),
        console::style("Jatin Jalandhra").cyan(),
    );
}
