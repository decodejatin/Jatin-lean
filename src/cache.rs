//! Incremental scanning cache: hash-based caching to skip unchanged packages.
//!
//! Computes a fast hash of each package directory's modification times
//! and skips re-scanning packages that haven't changed since the last scan.

use anyhow::{Context, Result};
use memmap2::Mmap;
use rkyv::Deserialize as RkyvDeserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const CACHE_VERSION: u32 = 2;

/// A cached scan state for a single package.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[archive(check_bytes)]
pub struct PackageCacheEntry {
    /// Hash of the package directory (based on file count + total mtime)
    pub hash: u64,
    /// Total files found during the cached scan.
    pub file_count: u64,
    /// Total size of all files found during the cached scan.
    pub total_size: u64,
    /// Number of candidate files last time
    pub candidate_count: u64,
    /// Total candidate size last time
    pub candidate_size: u64,
    /// Total packages included in the cached scan.
    pub total_packages: usize,
    /// Number of whitelisted files found during the cached scan.
    pub whitelisted_count: u64,
    /// Cached candidates from the previous successful scan.
    pub candidates: Vec<CachedPruneCandidate>,
    /// Timestamp of when this cache entry was created
    pub cached_at: u64,
}

/// A prune candidate stored in the disk cache.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[archive(check_bytes)]
pub struct CachedPruneCandidate {
    /// Absolute path to the candidate file.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Compact category identifier, interpreted by the scanner.
    pub category: u8,
    /// Package that owns the candidate.
    pub package_name: String,
}

/// The full scan cache database.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[archive(check_bytes)]
pub struct ScanCache {
    /// Version of the cache format
    pub version: u32,
    /// Cache keyed by absolute package directory path
    pub packages: HashMap<String, PackageCacheEntry>,
    /// When the cache was last written
    pub last_updated: u64,
}

impl Default for ScanCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            packages: HashMap::new(),
            last_updated: 0,
        }
    }
}

impl ScanCache {
    /// Get the cache file path for a given node_modules directory.
    pub fn cache_path(node_modules_path: &Path) -> PathBuf {
        let parent = node_modules_path.parent().unwrap_or(node_modules_path);
        parent.join(".jatin-lean").join("cache.bin")
    }

    /// Load the cache from disk, or create a new one.
    pub fn load(node_modules_path: &Path) -> Self {
        MappedScanCache::load(node_modules_path)
            .and_then(|mapped| mapped.to_memory())
            .ok()
            .filter(|cache| cache.version == CACHE_VERSION)
            .unwrap_or_default()
    }

    /// Save the cache to disk.
    pub fn save(&mut self, node_modules_path: &Path) -> Result<()> {
        self.last_updated = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let path = Self::cache_path(node_modules_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create cache directory: {}", parent.display())
            })?;
        }

        let bytes = rkyv::to_bytes::<_, 256>(&*self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize scan cache: {:?}", e))?;
        let tmp_path = path.with_extension("bin.tmp");
        fs::write(&tmp_path, bytes.as_slice())
            .with_context(|| format!("Failed to write cache: {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &path)
            .with_context(|| format!("Failed to replace cache: {}", path.display()))?;
        Ok(())
    }

    /// Compute a fast hash of a package directory.
    /// Uses file count + sum of modification timestamps as a fingerprint.
    pub fn compute_package_hash(pkg_path: &Path) -> u64 {
        fn mix(mut hash: u64, value: u64) -> u64 {
            hash ^= value;
            hash = hash.wrapping_mul(0x100000001b3);
            hash
        }

        fn visit(path: &Path, hash: &mut u64, file_count: &mut u64) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };

            *file_count += 1;
            *hash = mix(*hash, metadata.len());
            if let Ok(modified) = metadata.modified() {
                let nanos = modified
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                *hash = mix(*hash, nanos);
            }

            if metadata.is_dir() {
                let Ok(entries) = fs::read_dir(path) else {
                    return;
                };
                let mut entries: Vec<_> = entries.flatten().collect();
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    let name = entry.file_name();
                    for byte in name.to_string_lossy().bytes() {
                        *hash = mix(*hash, byte as u64);
                    }
                    visit(&entry.path(), hash, file_count);
                }
            }
        }

        let mut hash = 0xcbf29ce484222325;
        let mut file_count = 0;
        visit(pkg_path, &mut hash, &mut file_count);
        mix(hash, file_count)
    }

    /// Check if a package has changed since it was last cached.
    pub fn is_package_changed(&self, pkg_path: &Path) -> bool {
        let key = pkg_path.display().to_string();
        match self.packages.get(&key) {
            Some(entry) => {
                let current_hash = Self::compute_package_hash(pkg_path);
                current_hash != entry.hash
            }
            None => true, // Not in cache, treat as changed
        }
    }

    /// Update the cache entry for a package.
    pub fn update_package(&mut self, pkg_path: &Path, candidate_count: u64, candidate_size: u64) {
        self.update_package_scan(
            pkg_path,
            0,
            0,
            candidate_count,
            candidate_size,
            0,
            0,
            Vec::new(),
        );
    }

    /// Update the cache entry with full scan metadata.
    pub fn update_package_scan(
        &mut self,
        pkg_path: &Path,
        file_count: u64,
        total_size: u64,
        candidate_count: u64,
        candidate_size: u64,
        total_packages: usize,
        whitelisted_count: u64,
        candidates: Vec<CachedPruneCandidate>,
    ) {
        let key = pkg_path.display().to_string();
        let hash = Self::compute_package_hash(pkg_path);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.packages.insert(
            key,
            PackageCacheEntry {
                hash,
                file_count,
                total_size,
                candidate_count,
                candidate_size,
                total_packages,
                whitelisted_count,
                candidates,
                cached_at: now,
            },
        );
    }

    /// Get cached results for a package if it hasn't changed.
    pub fn get_cached(&self, pkg_path: &Path) -> Option<&PackageCacheEntry> {
        if !self.is_package_changed(pkg_path) {
            let key = pkg_path.display().to_string();
            self.packages.get(&key)
        } else {
            None
        }
    }

    /// Remove stale entries (packages that no longer exist).
    pub fn prune_stale(&mut self) {
        self.packages.retain(|path, _| Path::new(path).exists());
    }

    /// Get the number of cached packages.
    pub fn cached_count(&self) -> usize {
        self.packages.len()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.packages.clear();
    }

    /// Get cache age in seconds.
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.last_updated)
    }
}

/// A memory-mapped cache file validated by rkyv before use.
pub struct MappedScanCache {
    mmap: Mmap,
}

impl MappedScanCache {
    /// Load and validate a cache file by memory-mapping its bytes.
    pub fn load(node_modules_path: &Path) -> Result<Self> {
        let path = ScanCache::cache_path(node_modules_path);
        let file = File::open(&path)
            .with_context(|| format!("Failed to open cache: {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap cache: {}", path.display()))?;
        rkyv::check_archived_root::<ScanCache>(&mmap[..])
            .map_err(|e| anyhow::anyhow!("Invalid scan cache: {:?}", e))?;
        Ok(Self { mmap })
    }

    /// Deserialize the validated archive into the in-memory cache layer.
    pub fn to_memory(&self) -> Result<ScanCache> {
        let archived = rkyv::check_archived_root::<ScanCache>(&self.mmap[..])
            .map_err(|e| anyhow::anyhow!("Invalid scan cache: {:?}", e))?;
        let mut deserializer = rkyv::Infallible;
        archived
            .deserialize(&mut deserializer)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize scan cache: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_scan_cache_default() {
        let cache = ScanCache::default();
        assert_eq!(cache.version, CACHE_VERSION);
        assert!(cache.packages.is_empty());
    }

    #[test]
    fn test_compute_package_hash_empty_dir() -> Result<()> {
        let temp = TempDir::new()?;
        let hash = ScanCache::compute_package_hash(temp.path());
        assert_ne!(hash, 0);
        Ok(())
    }

    #[test]
    fn test_compute_package_hash_with_files() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(temp.path().join("file1.txt"), "hello")?;
        fs::write(temp.path().join("file2.txt"), "world")?;

        let hash = ScanCache::compute_package_hash(temp.path());
        assert!(hash > 0);
        Ok(())
    }

    #[test]
    fn test_is_package_changed_not_cached() {
        let cache = ScanCache::default();
        let temp = TempDir::new().unwrap();
        assert!(cache.is_package_changed(temp.path()));
    }

    #[test]
    fn test_update_and_check_package() -> Result<()> {
        let mut cache = ScanCache::default();
        let temp = TempDir::new()?;
        fs::write(temp.path().join("index.js"), "module.exports = {}")?;

        cache.update_package(temp.path(), 5, 1024);
        assert!(!cache.is_package_changed(temp.path()));

        // Modify the directory
        fs::write(temp.path().join("new_file.js"), "new content")?;
        assert!(cache.is_package_changed(temp.path()));

        Ok(())
    }

    #[test]
    fn test_save_and_load_cache() -> Result<()> {
        let temp = TempDir::new()?;
        let nm_path = temp.path().join("node_modules");
        fs::create_dir_all(&nm_path)?;

        let mut cache = ScanCache::default();
        cache.update_package(&nm_path.join("test-pkg"), 10, 2048);
        cache.save(&nm_path)?;

        let loaded = ScanCache::load(&nm_path);
        assert_eq!(loaded.cached_count(), 1);

        Ok(())
    }

    #[test]
    fn test_prune_stale_entries() {
        let mut cache = ScanCache::default();
        cache.packages.insert(
            "/nonexistent/path/package".to_string(),
            PackageCacheEntry {
                hash: 12345,
                file_count: 0,
                total_size: 0,
                candidate_count: 5,
                candidate_size: 1024,
                total_packages: 0,
                whitelisted_count: 0,
                candidates: Vec::new(),
                cached_at: 0,
            },
        );

        assert_eq!(cache.cached_count(), 1);
        cache.prune_stale();
        assert_eq!(cache.cached_count(), 0);
    }
}
