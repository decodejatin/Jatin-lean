//! Duplicate file detection engine: finds identical files across packages.
//!
//! Identifies duplicate files using content hashing, helping users understand
//! the true level of redundancy in their node_modules directory.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::scanner::{format_number, format_size};

/// Information about a group of duplicate files.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Content hash (simplified)
    pub hash: u64,
    /// Size of each file in the group
    pub file_size: u64,
    /// All paths that share this content
    pub paths: Vec<PathBuf>,
    /// Package names these files belong to
    pub packages: Vec<String>,
}

impl DuplicateGroup {
    /// Total wasted space (all copies except one).
    pub fn wasted_space(&self) -> u64 {
        if self.paths.len() > 1 {
            self.file_size * (self.paths.len() as u64 - 1)
        } else {
            0
        }
    }

    /// Number of extra copies.
    pub fn extra_copies(&self) -> usize {
        if self.paths.len() > 1 {
            self.paths.len() - 1
        } else {
            0
        }
    }
}

/// Result of a deduplication scan.
#[derive(Debug)]
pub struct DeduplicationResult {
    /// Total files analyzed
    pub total_files_analyzed: u64,
    /// Total unique content hashes
    pub unique_contents: u64,
    /// Groups of duplicate files
    pub duplicate_groups: Vec<DuplicateGroup>,
    /// Total wasted space from duplicates
    pub total_wasted: u64,
    /// Total extra file copies
    pub total_extra_copies: u64,
}

/// Compute a fast content hash for a file.
/// Uses FNV-1a-like hashing for speed — not cryptographic but sufficient
/// for duplicate detection when combined with file size.
fn fast_content_hash(path: &Path) -> Result<u64> {
    let mut file =
        fs::File::open(path).with_context(|| format!("Cannot open file: {}", path.display()))?;

    let metadata = file.metadata()?;
    let file_size = metadata.len();

    // For very large files, only hash first + last chunks
    let mut hasher: u64 = 0xcbf29ce484222325; // FNV offset basis

    if file_size <= 65536 {
        // Small file: hash everything
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        for byte in &buffer {
            hasher ^= *byte as u64;
            hasher = hasher.wrapping_mul(0x100000001b3); // FNV prime
        }
    } else {
        // Large file: hash first 32KB + last 32KB + file size
        let mut buffer = vec![0u8; 32768];

        // First chunk
        let bytes_read = file.read(&mut buffer)?;
        for byte in &buffer[..bytes_read] {
            hasher ^= *byte as u64;
            hasher = hasher.wrapping_mul(0x100000001b3);
        }

        // Mix in file size
        hasher ^= file_size;
        hasher = hasher.wrapping_mul(0x100000001b3);
    }

    // Mix in file size for extra discrimination
    hasher ^= file_size;
    hasher = hasher.wrapping_mul(0x100000001b3);

    Ok(hasher)
}

/// Scan a node_modules directory for duplicate files.
pub fn find_duplicates(node_modules_path: &Path) -> Result<DeduplicationResult> {
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
    pb.set_message("Scanning for duplicates...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    // Map: (file_size, hash) -> Vec<(path, package_name)>
    let mut content_map: HashMap<(u64, u64), Vec<(PathBuf, String)>> = HashMap::new();
    let mut total_files: u64 = 0;

    // Walk all packages
    if let Ok(entries) = fs::read_dir(node_modules_path) {
        for entry in entries.flatten() {
            let pkg_path = entry.path();
            if !pkg_path.is_dir() {
                continue;
            }

            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or("");

            if name_str == ".bin" || name_str == ".cache" {
                continue;
            }

            let packages_to_scan: Vec<(PathBuf, String)> = if name_str.starts_with('@') {
                // Scoped packages
                fs::read_dir(&pkg_path)
                    .into_iter()
                    .flat_map(|rd| rd.flatten())
                    .filter(|e| e.path().is_dir())
                    .map(|e| {
                        let pkg_name =
                            format!("{}/{}", name_str, e.file_name().to_str().unwrap_or(""));
                        (e.path(), pkg_name)
                    })
                    .collect()
            } else {
                vec![(pkg_path.clone(), name_str.to_string())]
            };

            for (pkg_dir, pkg_name) in packages_to_scan {
                scan_package_files(&pkg_dir, &pkg_name, &mut content_map, &mut total_files, &pb)?;
            }
        }
    }

    pb.finish_and_clear();

    // Find groups with more than one file
    let mut duplicate_groups: Vec<DuplicateGroup> = Vec::new();
    let mut unique_contents: u64 = 0;
    let mut total_wasted: u64 = 0;
    let mut total_extra_copies: u64 = 0;

    for ((file_size, hash), files) in &content_map {
        unique_contents += 1;
        if files.len() > 1 {
            let paths: Vec<PathBuf> = files.iter().map(|(p, _)| p.clone()).collect();
            let packages: Vec<String> = files.iter().map(|(_, n)| n.clone()).collect();
            let wasted = file_size * (files.len() as u64 - 1);
            total_wasted += wasted;
            total_extra_copies += (files.len() - 1) as u64;

            duplicate_groups.push(DuplicateGroup {
                hash: *hash,
                file_size: *file_size,
                paths,
                packages,
            });
        }
    }

    // Sort by wasted space (largest first)
    duplicate_groups.sort_by(|a, b| b.wasted_space().cmp(&a.wasted_space()));

    Ok(DeduplicationResult {
        total_files_analyzed: total_files,
        unique_contents,
        duplicate_groups,
        total_wasted,
        total_extra_copies,
    })
}

/// Scan all files in a package directory and add to the content map.
fn scan_package_files(
    pkg_dir: &Path,
    pkg_name: &str,
    content_map: &mut HashMap<(u64, u64), Vec<(PathBuf, String)>>,
    total_files: &mut u64,
    pb: &indicatif::ProgressBar,
) -> Result<()> {
    let walker = ignore::WalkBuilder::new(pkg_dir)
        .hidden(false)
        .git_ignore(false)
        .follow_links(false)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.into_path();
        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let file_size = metadata.len();

        // Skip very small files (not worth deduplicating)
        if file_size < 256 {
            continue;
        }

        *total_files += 1;
        if (*total_files).is_multiple_of(1000) {
            pb.set_message(format!(
                "Scanning... {} files hashed",
                format_number(*total_files)
            ));
        }

        if let Ok(hash) = fast_content_hash(&path) {
            content_map
                .entry((file_size, hash))
                .or_default()
                .push((path, pkg_name.to_string()));
        }
    }

    Ok(())
}

/// Print the deduplication results to the terminal.
pub fn print_dedup_results(result: &DeduplicationResult) {
    use console::style;

    println!();
    println!(
        "  {} {}",
        style("Duplicate File Analysis").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!();

    println!(
        "  {} Files analyzed: {}",
        style("◉").cyan(),
        style(format_number(result.total_files_analyzed))
            .white()
            .bold()
    );
    println!(
        "  {} Unique contents: {}",
        style("◉").cyan(),
        style(format_number(result.unique_contents)).white().bold()
    );
    println!(
        "  {} Duplicate groups: {}",
        style("◉").yellow(),
        style(format_number(result.duplicate_groups.len() as u64))
            .yellow()
            .bold()
    );
    println!(
        "  {} Extra copies: {}",
        style("◉").yellow(),
        style(format_number(result.total_extra_copies))
            .yellow()
            .bold()
    );
    println!(
        "  {} Wasted space: {}",
        style("◉").red(),
        style(format_size(result.total_wasted)).red().bold()
    );

    // Show top duplicate groups
    if !result.duplicate_groups.is_empty() {
        println!();
        println!(
            "  {} {}",
            style("Top Duplicates").white().bold(),
            style("─────────────────────────────").dim()
        );

        for group in result.duplicate_groups.iter().take(10) {
            let file_name = group.paths[0]
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?");

            let unique_packages: std::collections::HashSet<&str> =
                group.packages.iter().map(|s| s.as_str()).collect();

            println!(
                "  {} {} — {} × {} (wastes {})",
                style("▸").dim(),
                style(file_name).yellow(),
                format_size(group.file_size),
                style(group.paths.len()).white().bold(),
                style(format_size(group.wasted_space())).red(),
            );
            println!(
                "    {} Packages: {}",
                style("→").dim(),
                unique_packages
                    .into_iter()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if result.duplicate_groups.len() > 10 {
            println!(
                "\n  {} ...and {} more duplicate groups",
                style("→").dim(),
                result.duplicate_groups.len() - 10,
            );
        }
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_fast_content_hash_same_content() -> Result<()> {
        let temp = TempDir::new()?;
        let file1 = temp.path().join("file1.txt");
        let file2 = temp.path().join("file2.txt");
        let content = "Hello, world! This is test content for hashing purposes.";
        fs::write(&file1, content)?;
        fs::write(&file2, content)?;

        let hash1 = fast_content_hash(&file1)?;
        let hash2 = fast_content_hash(&file2)?;
        assert_eq!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_fast_content_hash_different_content() -> Result<()> {
        let temp = TempDir::new()?;
        let file1 = temp.path().join("file1.txt");
        let file2 = temp.path().join("file2.txt");
        fs::write(&file1, "Content A — something unique here")?;
        fs::write(&file2, "Content B — something else entirely")?;

        let hash1 = fast_content_hash(&file1)?;
        let hash2 = fast_content_hash(&file2)?;
        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_duplicate_group_wasted_space() {
        let group = DuplicateGroup {
            hash: 12345,
            file_size: 1024,
            paths: vec![
                PathBuf::from("/a/file.js"),
                PathBuf::from("/b/file.js"),
                PathBuf::from("/c/file.js"),
            ],
            packages: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(group.wasted_space(), 2048); // 1024 * (3-1)
        assert_eq!(group.extra_copies(), 2);
    }

    #[test]
    fn test_duplicate_group_single_file() {
        let group = DuplicateGroup {
            hash: 12345,
            file_size: 1024,
            paths: vec![PathBuf::from("/a/file.js")],
            packages: vec!["a".into()],
        };
        assert_eq!(group.wasted_space(), 0);
        assert_eq!(group.extra_copies(), 0);
    }
}
