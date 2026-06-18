//! Lockfile watcher: monitor lockfiles for auto-pruning.
//!
//! Uses the `notify` crate for event-driven file system monitoring of lockfiles
//! (package-lock.json, yarn.lock, pnpm-lock.yaml) with debouncing.

use anyhow::{Context, Result};
use console::style;
use notify::{RecursiveMode, Watcher};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const LOCK_FILES: &[&str] = &["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

/// Configuration for the lockfile watcher.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Debounce delay in seconds (default: 4)
    pub debounce_secs: u64,
    /// Whether to auto-prune on detected changes
    pub auto_prune: bool,
    /// Maximum number of auto-prune cycles (0 = unlimited)
    pub max_cycles: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            debounce_secs: 4,
            auto_prune: false,
            max_cycles: 0,
        }
    }
}

/// A watcher that monitors lockfiles in a project root directory.
pub struct LockfileWatcher {
    /// Path to the project root
    project_path: PathBuf,
    /// Watcher configuration
    config: WatcherConfig,
    /// Running flag (shared with signal handler)
    running: Arc<AtomicBool>,
    /// Number of prune cycles completed
    cycle_count: u64,
}

impl LockfileWatcher {
    /// Create a new lockfile watcher.
    pub fn new(project_path: PathBuf, config: WatcherConfig) -> Self {
        Self {
            project_path,
            config,
            running: Arc::new(AtomicBool::new(true)),
            cycle_count: 0,
        }
    }

    /// Get a clone of the running flag for use in signal handlers.
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Start watching lockfiles (blocking call).
    pub fn watch<F>(&mut self, on_change: F) -> Result<()>
    where
        F: Fn(&Path) -> Result<()>,
    {
        let (tx, rx) = mpsc::channel::<DebounceEventResult>();

        let mut debouncer = new_debouncer(
            Duration::from_secs(self.config.debounce_secs),
            None,
            tx,
        )
        .context("Failed to create file debouncer")?;

        debouncer
            .watcher()
            .watch(&self.project_path, RecursiveMode::NonRecursive)
            .with_context(|| {
                format!(
                    "Failed to watch directory: {}",
                    self.project_path.display()
                )
            })?;

        println!();
        println!(
            "  {} {}",
            style("Watch Mode (Lockfiles)").cyan().bold(),
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );
        println!(
            "  {} Watching: {}",
            style("◉").cyan(),
            style(self.project_path.display()).white().bold()
        );
        println!(
            "  {} Lockfiles: {}",
            style("◉").cyan(),
            style("package-lock.json, yarn.lock, pnpm-lock.yaml").dim()
        );
        println!(
            "  {} Debounce: {}s",
            style("◉").cyan(),
            self.config.debounce_secs
        );
        println!(
            "  {} Auto-prune: {}",
            style("◉").cyan(),
            if self.config.auto_prune { "ON" } else { "OFF" }
        );
        println!(
            "  {} Press {} to stop watching.",
            style("ℹ").blue(),
            style("Ctrl+C").yellow().bold()
        );
        println!();

        while self.running.load(Ordering::SeqCst) {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(Ok(events)) => {
                    let has_lockfile_event = events.iter().any(|e| {
                        e.path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| LOCK_FILES.contains(&n))
                            .unwrap_or(false)
                    });

                    if !has_lockfile_event {
                        continue;
                    }

                    println!(
                        "  {} Lockfile change detected!",
                        style("⚡").yellow().bold()
                    );

                    match on_change(&self.project_path) {
                        Ok(()) => {
                            self.cycle_count += 1;
                            println!(
                                "  {} Prune cycle #{} complete.",
                                style("✓").green().bold(),
                                self.cycle_count
                            );
                        }
                        Err(e) => {
                            eprintln!("  {} Prune failed: {}", style("✗").red(), e);
                        }
                    }

                    if self.config.max_cycles > 0
                        && self.cycle_count >= self.config.max_cycles
                    {
                        println!(
                            "  {} Max cycles ({}) reached. Stopping.",
                            style("ℹ").blue(),
                            self.config.max_cycles
                        );
                        break;
                    }
                }
                Ok(Err(errors)) => {
                    for e in &errors {
                        eprintln!("  {} Watch error: {:?}", style("⚠").yellow(), e);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        println!(
            "\n  {} Watcher stopped. {} prune cycles completed.",
            style("◉").cyan(),
            self.cycle_count
        );
        println!();

        Ok(())
    }

    /// Stop the watcher.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Post-install hook checker: detect if npm/yarn/pnpm just ran.
pub fn detect_recent_install(project_dir: &Path) -> Option<InstallInfo> {
    let lock_files = [
        ("package-lock.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
    ];

    for (filename, manager) in &lock_files {
        let path = project_dir.join(filename);
        if let Ok(metadata) = std::fs::metadata(&path) {
            if let Ok(modified) = metadata.modified() {
                let age = SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();

                if age.as_secs() < 30 {
                    return Some(InstallInfo {
                        package_manager: manager.to_string(),
                        lock_file: filename.to_string(),
                        age_seconds: age.as_secs(),
                    });
                }
            }
        }
    }

    None
}

/// Information about a recent package install.
#[derive(Debug)]
pub struct InstallInfo {
    pub package_manager: String,
    pub lock_file: String,
    pub age_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_watcher_config_default() {
        let config = WatcherConfig::default();
        assert_eq!(config.debounce_secs, 4);
        assert!(!config.auto_prune);
    }

    #[test]
    fn test_watcher_creation() {
        let watcher =
            LockfileWatcher::new(PathBuf::from("/tmp/test"), WatcherConfig::default());
        assert_eq!(watcher.cycle_count, 0);
    }

    #[test]
    fn test_detect_recent_install_none() {
        let temp = TempDir::new().unwrap();
        assert!(detect_recent_install(temp.path()).is_none());
    }
}
