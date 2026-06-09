//! Deletion engine: atomic batch file removal with error resilience.

use crate::scanner::{format_number, format_size, PruneCandidate};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const ERROR_SHARING_VIOLATION: i32 = 32;

fn is_locked_file_error(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

#[derive(Debug)]
pub struct DeletionResult {
    pub deleted_count: u64,
    pub deleted_size: u64,
    pub locked_skips: Vec<(PathBuf, String)>,
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
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.green} Cleaning... [{bar:30.green/dim}] {percent}% | Deleted {msg}",
        )
        .unwrap()
        .progress_chars("██░")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let deleted_count = AtomicU64::new(0);
    let deleted_size = AtomicU64::new(0);
    let locked_skips: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());
    let failures: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

    by_package.par_iter().for_each(|(_package, files)| {
        for candidate in files {
            match fs::remove_file(&candidate.path) {
                Ok(()) => {
                    deleted_count.fetch_add(1, Ordering::Relaxed);
                    let new_size =
                        deleted_size.fetch_add(candidate.size, Ordering::Relaxed) + candidate.size;
                    pb.set_position(new_size);
                    pb.set_message(format_size(new_size));
                }
                Err(e) => {
                    if is_locked_file_error(&e) {
                        locked_skips
                            .lock()
                            .expect("locked skips mutex poisoned")
                            .push((candidate.path.clone(), e.to_string()));
                    } else {
                        failures
                            .lock()
                            .expect("failure collection mutex poisoned")
                            .push((candidate.path.clone(), e.to_string()));
                    }
                }
            }
        }
    });

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

    let mut locked_skips = locked_skips
        .into_inner()
        .expect("locked skips mutex poisoned");
    locked_skips.sort_by(|a, b| a.0.cmp(&b.0));
    let mut failures = failures
        .into_inner()
        .expect("failure collection mutex poisoned");
    failures.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(DeletionResult {
        deleted_count: deleted_count.load(Ordering::Relaxed),
        deleted_size: deleted_size.load(Ordering::Relaxed),
        locked_skips,
        failures,
        duration: start.elapsed(),
    })
}

pub fn print_deletion_summary(result: &DeletionResult) {
    println!(
        "  {} Deleted {} ({} files) in {:.1}s",
        console::style("✓").green().bold(),
        console::style(format_size(result.deleted_size))
            .green()
            .bold(),
        format_number(result.deleted_count),
        result.duration.as_secs_f64()
    );
    if !result.locked_skips.is_empty() {
        println!(
            "  {} {} files were skipped (locked by active processes):",
            console::style("ℹ").cyan(),
            result.locked_skips.len()
        );
        for (path, err) in result.locked_skips.iter().take(5) {
            println!(
                "    {} {} — {}",
                console::style("→").dim(),
                path.display(),
                err
            );
        }
        if result.locked_skips.len() > 5 {
            println!(
                "    {} ...and {} more locked files",
                console::style("→").dim(),
                result.locked_skips.len() - 5
            );
        }
    }
    if !result.failures.is_empty() {
        println!(
            "  {} {} files could not be deleted (permission denied / other):",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::FileCategory;

    fn candidate(path: PathBuf, package_name: &str, size: u64) -> PruneCandidate {
        PruneCandidate {
            path,
            size,
            category: FileCategory::SourceMap,
            package_name: package_name.to_string(),
        }
    }

    #[test]
    fn test_execute_deletion_removes_files_in_parallel() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut candidates = Vec::new();

        for package in ["alpha", "beta", "gamma"] {
            let package_dir = temp.path().join("node_modules").join(package);
            fs::create_dir_all(&package_dir)?;
            for idx in 0..4 {
                let file_path = package_dir.join(format!("file-{}.map", idx));
                fs::write(&file_path, b"abcd")?;
                candidates.push(candidate(file_path, package, 4));
            }
        }

        let result = execute_deletion(&candidates)?;

        assert_eq!(result.deleted_count, 12);
        assert_eq!(result.deleted_size, 48);
        assert!(result.failures.is_empty());
        for candidate in &candidates {
            assert!(!candidate.path.exists());
        }
        Ok(())
    }

    #[test]
    fn test_is_locked_file_error_windows_only() {
        let sharing_violation = std::io::Error::from_raw_os_error(32);
        let access_denied = std::io::Error::from_raw_os_error(5);
        let unknown = std::io::Error::from_raw_os_error(999);

        #[cfg(windows)]
        {
            assert!(is_locked_file_error(&sharing_violation));
            assert!(!is_locked_file_error(&access_denied));
            assert!(!is_locked_file_error(&unknown));
        }
        #[cfg(not(windows))]
        {
            assert!(!is_locked_file_error(&sharing_violation));
            assert!(!is_locked_file_error(&access_denied));
            assert!(!is_locked_file_error(&unknown));
        }
    }

    #[test]
    fn test_execute_deletion_collects_failures_without_stopping() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let package_dir = temp.path().join("node_modules").join("alpha");
        fs::create_dir_all(&package_dir)?;
        let present = package_dir.join("present.map");
        let missing = package_dir.join("missing.map");
        fs::write(&present, b"abcd")?;

        let candidates = vec![
            candidate(present.clone(), "alpha", 4),
            candidate(missing.clone(), "alpha", 8),
        ];

        let result = execute_deletion(&candidates)?;

        assert_eq!(result.deleted_count, 1);
        assert_eq!(result.deleted_size, 4);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].0, missing);
        assert!(!present.exists());
        Ok(())
    }
}
