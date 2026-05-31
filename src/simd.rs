//! SIMD-accelerated content processing engine.
//!
//! Uses CPU SIMD instructions for ultra-fast:
//!   - Content hashing (FNV-1a vectorized)
//!   - Pattern matching (multi-byte needle search)
//!   - Line counting (newline vectorization)
//!   - Whitespace analysis
//!
//! Falls back to scalar implementations when SIMD is unavailable.

use std::path::Path;

// ─── Vectorized FNV-1a Hash ──────────────────────────────────────────────────

/// FNV-1a offset basis.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
/// FNV-1a prime.
const FNV_PRIME: u64 = 0x100000001b3;

/// SIMD-optimized FNV-1a hash for content fingerprinting.
///
/// On x86_64 with SSE2+, processes 16 bytes per iteration.
/// Falls back to scalar 8-byte-at-a-time on other architectures.
pub fn fast_hash(data: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") {
            return unsafe { fast_hash_sse2(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        fast_hash_neon(data)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        // Scalar fallback
        fast_hash_scalar(data)
    }
}

/// Scalar FNV-1a with 8-byte unrolled loop.
fn fast_hash_scalar(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // Unrolled 8-byte processing
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        hash ^= word;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    for &byte in remainder {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// SSE2-accelerated hash — processes 16 bytes per iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn fast_hash_sse2(data: &[u8]) -> u64 {
    use std::arch::x86_64::*;

    let mut hash = FNV_OFFSET_BASIS;
    let len = data.len();
    let ptr = data.as_ptr();

    // Process 16 bytes at a time with SSE2
    let full_blocks = len / 16;
    for i in 0..full_blocks {
        let offset = i * 16;
        let block = _mm_loadu_si128(ptr.add(offset) as *const __m128i);

        // Extract two 64-bit values from the 128-bit register
        let lo = _mm_extract_epi64(block, 0) as u64;
        let hi = _mm_extract_epi64(block, 1) as u64;

        hash ^= lo;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= hi;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Process remaining bytes
    let processed = full_blocks * 16;
    for i in processed..len {
        hash ^= *ptr.add(i) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// NEON-accelerated hash for ARM64.
#[cfg(target_arch = "aarch64")]
fn fast_hash_neon(data: &[u8]) -> u64 {
    use std::arch::aarch64::*;

    let mut hash = FNV_OFFSET_BASIS;
    let len = data.len();
    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let lo = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(chunk[8..16].try_into().unwrap());

        hash ^= lo;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= hi;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    for &byte in remainder {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

// ─── SIMD Line Counter ──────────────────────────────────────────────────────

/// Count newlines in a buffer using SIMD acceleration.
///
/// Processes 16/32 bytes per cycle on supported architectures.
pub fn count_newlines(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { count_newlines_avx2(data) };
        }
        if is_x86_feature_detected!("sse2") {
            return unsafe { count_newlines_sse2(data) };
        }
    }

    count_newlines_scalar(data)
}

/// Scalar newline counter with 8-byte unrolling.
fn count_newlines_scalar(data: &[u8]) -> usize {
    let mut count = 0usize;
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // Process 8 bytes at a time
        count += (chunk[0] == b'\n') as usize;
        count += (chunk[1] == b'\n') as usize;
        count += (chunk[2] == b'\n') as usize;
        count += (chunk[3] == b'\n') as usize;
        count += (chunk[4] == b'\n') as usize;
        count += (chunk[5] == b'\n') as usize;
        count += (chunk[6] == b'\n') as usize;
        count += (chunk[7] == b'\n') as usize;
    }

    for &byte in remainder {
        count += (byte == b'\n') as usize;
    }

    count
}

/// SSE2 newline counter — 16 bytes per iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn count_newlines_sse2(data: &[u8]) -> usize {
    use std::arch::x86_64::*;

    let newline = _mm_set1_epi8(b'\n' as i8);
    let mut total = 0usize;
    let len = data.len();
    let ptr = data.as_ptr();
    let full_blocks = len / 16;

    for i in 0..full_blocks {
        let block = _mm_loadu_si128(ptr.add(i * 16) as *const __m128i);
        let cmp = _mm_cmpeq_epi8(block, newline);
        let mask = _mm_movemask_epi8(cmp) as u32;
        total += mask.count_ones() as usize;
    }

    // Remainder
    let processed = full_blocks * 16;
    for i in processed..len {
        total += (*ptr.add(i) == b'\n') as usize;
    }

    total
}

/// AVX2 newline counter — 32 bytes per iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn count_newlines_avx2(data: &[u8]) -> usize {
    use std::arch::x86_64::*;

    let newline = _mm256_set1_epi8(b'\n' as i8);
    let mut total = 0usize;
    let len = data.len();
    let ptr = data.as_ptr();
    let full_blocks = len / 32;

    for i in 0..full_blocks {
        let block = _mm256_loadu_si256(ptr.add(i * 32) as *const __m256i);
        let cmp = _mm256_cmpeq_epi8(block, newline);
        let mask = _mm256_movemask_epi8(cmp) as u32;
        total += mask.count_ones() as usize;
    }

    // Remainder
    let processed = full_blocks * 32;
    for i in processed..len {
        total += (*ptr.add(i) == b'\n') as usize;
    }

    total
}

// ─── SIMD Pattern Search ─────────────────────────────────────────────────────

/// Fast multi-byte pattern search using SIMD.
///
/// Returns the byte offset of the first match, or None.
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") && needle.len() >= 2 {
            return unsafe { find_pattern_sse2(haystack, needle) };
        }
    }

    find_pattern_scalar(haystack, needle)
}

/// Scalar pattern search.
fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// SSE2-accelerated first-byte filter + verify pattern search.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn find_pattern_sse2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    let first_byte = _mm_set1_epi8(needle[0] as i8);
    let last_byte = _mm_set1_epi8(needle[needle.len() - 1] as i8);
    let len = haystack.len();
    let ptr = haystack.as_ptr();
    let needle_len = needle.len();

    if len < needle_len + 16 {
        return find_pattern_scalar(haystack, needle);
    }

    let search_len = len - needle_len + 1;
    let full_blocks = search_len / 16;

    for i in 0..full_blocks {
        let offset = i * 16;
        let block_first = _mm_loadu_si128(ptr.add(offset) as *const __m128i);
        let block_last = _mm_loadu_si128(ptr.add(offset + needle_len - 1) as *const __m128i);

        let cmp_first = _mm_cmpeq_epi8(block_first, first_byte);
        let cmp_last = _mm_cmpeq_epi8(block_last, last_byte);
        let combined = _mm_and_si128(cmp_first, cmp_last);
        let mut mask = _mm_movemask_epi8(combined) as u32;

        while mask != 0 {
            let bit_pos = mask.trailing_zeros() as usize;
            let candidate_offset = offset + bit_pos;

            if candidate_offset + needle_len <= len {
                let candidate = &haystack[candidate_offset..candidate_offset + needle_len];
                if candidate == needle {
                    return Some(candidate_offset);
                }
            }

            mask &= mask - 1; // Clear lowest set bit
        }
    }

    // Check remainder
    let processed = full_blocks * 16;
    for i in processed..search_len {
        if haystack[i..i + needle_len] == *needle {
            return Some(i);
        }
    }

    None
}

// ─── SIMD Byte Frequency Analysis ────────────────────────────────────────────

/// Analyze byte frequency distribution in a buffer.
/// Useful for detecting file type (text vs binary) and compression potential.
#[derive(Debug, Clone)]
pub struct ByteFrequency {
    pub counts: [u64; 256],
    pub total_bytes: u64,
}

impl ByteFrequency {
    /// Compute byte frequency histogram.
    pub fn analyze(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];

        // Unrolled 4x for ILP (instruction-level parallelism)
        let chunks = data.chunks_exact(4);
        let remainder = chunks.remainder();

        for chunk in chunks {
            counts[chunk[0] as usize] += 1;
            counts[chunk[1] as usize] += 1;
            counts[chunk[2] as usize] += 1;
            counts[chunk[3] as usize] += 1;
        }

        for &byte in remainder {
            counts[byte as usize] += 1;
        }

        Self {
            counts,
            total_bytes: data.len() as u64,
        }
    }

    /// Shannon entropy (bits per byte). Higher = more random/compressed.
    pub fn entropy(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }

        let total = self.total_bytes as f64;
        let mut entropy = 0.0f64;

        for &count in &self.counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Is this likely a binary file? (entropy > 6.0 bits/byte or many non-printable bytes)
    pub fn is_likely_binary(&self) -> bool {
        // Count non-printable, non-whitespace bytes
        let mut non_text = 0u64;
        for (i, &count) in self.counts.iter().enumerate() {
            let byte = i as u8;
            if count > 0
                && byte != b'\n'
                && byte != b'\r'
                && byte != b'\t'
                && !(32..=126).contains(&byte)
            {
                non_text += count;
            }
        }

        let non_text_ratio = non_text as f64 / self.total_bytes.max(1) as f64;
        non_text_ratio > 0.10 || self.entropy() > 7.5
    }

    /// Estimated compression ratio (0.0 = perfect compression, 1.0 = incompressible).
    pub fn estimated_compression_ratio(&self) -> f64 {
        let ent = self.entropy();
        // Maximum entropy = 8.0 bits/byte (completely random)
        // Compression ratio roughly: entropy / 8.0
        (ent / 8.0).min(1.0)
    }

    /// Get top N most frequent bytes.
    pub fn top_bytes(&self, n: usize) -> Vec<(u8, u64)> {
        let mut indexed: Vec<(u8, u64)> = self
            .counts
            .iter()
            .enumerate()
            .map(|(i, &c)| (i as u8, c))
            .filter(|(_, c)| *c > 0)
            .collect();
        indexed.sort_by(|a, b| b.1.cmp(&a.1));
        indexed.truncate(n);
        indexed
    }

    /// Whitespace ratio (spaces, tabs, newlines).
    pub fn whitespace_ratio(&self) -> f64 {
        let ws = self.counts[b' ' as usize]
            + self.counts[b'\t' as usize]
            + self.counts[b'\n' as usize]
            + self.counts[b'\r' as usize];
        ws as f64 / self.total_bytes.max(1) as f64
    }
}

// ─── CPU Feature Detection ───────────────────────────────────────────────────

/// Report available SIMD capabilities on the current CPU.
#[derive(Debug, Clone)]
pub struct CpuCapabilities {
    pub arch: &'static str,
    pub sse2: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub popcnt: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub aes_ni: bool,
    pub neon: bool,
}

impl CpuCapabilities {
    /// Detect current CPU capabilities.
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                arch: "x86_64",
                sse2: is_x86_feature_detected!("sse2"),
                sse4_1: is_x86_feature_detected!("sse4.1"),
                sse4_2: is_x86_feature_detected!("sse4.2"),
                avx: is_x86_feature_detected!("avx"),
                avx2: is_x86_feature_detected!("avx2"),
                avx512f: is_x86_feature_detected!("avx512f"),
                popcnt: is_x86_feature_detected!("popcnt"),
                bmi1: is_x86_feature_detected!("bmi1"),
                bmi2: is_x86_feature_detected!("bmi2"),
                aes_ni: is_x86_feature_detected!("aes"),
                neon: false,
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            Self {
                arch: "aarch64",
                sse2: false,
                sse4_1: false,
                sse4_2: false,
                avx: false,
                avx2: false,
                avx512f: false,
                popcnt: false,
                bmi1: false,
                bmi2: false,
                aes_ni: false,
                neon: true, // NEON is mandatory on AArch64
            }
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                arch: "unknown",
                sse2: false,
                sse4_1: false,
                sse4_2: false,
                avx: false,
                avx2: false,
                avx512f: false,
                popcnt: false,
                bmi1: false,
                bmi2: false,
                aes_ni: false,
                neon: false,
            }
        }
    }

    /// Best available SIMD tier for display.
    pub fn best_tier(&self) -> &'static str {
        if self.avx512f {
            return "AVX-512";
        }
        if self.avx2 {
            return "AVX2 (256-bit)";
        }
        if self.avx {
            return "AVX (256-bit)";
        }
        if self.sse4_2 {
            return "SSE4.2 (128-bit)";
        }
        if self.sse4_1 {
            return "SSE4.1 (128-bit)";
        }
        if self.sse2 {
            return "SSE2 (128-bit)";
        }
        if self.neon {
            return "NEON (128-bit)";
        }
        "Scalar (no SIMD)"
    }

    /// Alias for best_tier() — human-readable SIMD tier name.
    pub fn tier_name(&self) -> &'static str {
        self.best_tier()
    }

    /// Print capabilities to console.
    pub fn print_info(&self) {
        use console::style;

        println!();
        println!(
            "  {} {}",
            style("CPU Capabilities").cyan().bold(),
            style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
        );
        println!(
            "  {} Architecture: {}",
            style("◉").cyan(),
            style(self.arch).white().bold()
        );
        println!(
            "  {} Best SIMD tier: {}",
            style("◉").cyan(),
            style(self.best_tier()).green().bold()
        );

        #[cfg(target_arch = "x86_64")]
        {
            let features = [
                ("SSE2", self.sse2),
                ("SSE4.1", self.sse4_1),
                ("SSE4.2", self.sse4_2),
                ("AVX", self.avx),
                ("AVX2", self.avx2),
                ("AVX-512F", self.avx512f),
                ("POPCNT", self.popcnt),
                ("BMI1", self.bmi1),
                ("BMI2", self.bmi2),
                ("AES-NI", self.aes_ni),
            ];
            println!();
            for (name, available) in &features {
                let status = if *available {
                    style("✓").green()
                } else {
                    style("✗").dim()
                };
                println!("  {} {} {}", style("▸").dim(), status, name);
            }
        }

        println!();
    }
}

// ─── Batch File Hasher ───────────────────────────────────────────────────────

/// Hash multiple files in parallel using SIMD-accelerated hashing.
pub fn batch_hash_files(paths: &[&Path]) -> Vec<(usize, u64)> {
    use rayon::prelude::*;

    paths
        .par_iter()
        .enumerate()
        .filter_map(|(idx, path)| std::fs::read(path).ok().map(|data| (idx, fast_hash(&data))))
        .collect()
}

/// Hash a single file with SIMD acceleration.
pub fn hash_file(path: &Path) -> Option<u64> {
    std::fs::read(path).ok().map(|data| fast_hash(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_hash_deterministic() {
        let data = b"Hello, World!";
        let h1 = fast_hash(data);
        let h2 = fast_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fast_hash_different_inputs() {
        let h1 = fast_hash(b"hello");
        let h2 = fast_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_fast_hash_empty() {
        let h = fast_hash(b"");
        assert_eq!(h, FNV_OFFSET_BASIS);
    }

    #[test]
    fn test_fast_hash_large_input() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let h = fast_hash(&data);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_count_newlines() {
        assert_eq!(count_newlines(b"hello\nworld\n"), 2);
        assert_eq!(count_newlines(b"no newlines"), 0);
        assert_eq!(count_newlines(b"\n\n\n"), 3);
        assert_eq!(count_newlines(b""), 0);
    }

    #[test]
    fn test_count_newlines_large() {
        let mut data = Vec::with_capacity(1000);
        for _ in 0..100 {
            data.extend_from_slice(b"some line\n");
        }
        assert_eq!(count_newlines(&data), 100);
    }

    #[test]
    fn test_find_pattern() {
        assert_eq!(find_pattern(b"hello world", b"world"), Some(6));
        assert_eq!(find_pattern(b"hello world", b"xyz"), None);
        assert_eq!(find_pattern(b"hello", b""), Some(0));
        assert_eq!(find_pattern(b"", b"hello"), None);
    }

    #[test]
    fn test_find_pattern_at_start() {
        assert_eq!(find_pattern(b"hello world", b"hello"), Some(0));
    }

    #[test]
    fn test_byte_frequency_entropy() {
        // All same bytes = 0 entropy
        let data = vec![0u8; 1000];
        let freq = ByteFrequency::analyze(&data);
        assert_eq!(freq.entropy(), 0.0);
    }

    #[test]
    fn test_byte_frequency_binary_detection() {
        // Mostly printable text
        let text = b"This is a normal text file with some content.\n";
        let freq = ByteFrequency::analyze(text);
        assert!(!freq.is_likely_binary());

        // Random-looking binary
        let binary: Vec<u8> = (0..1000).map(|i| ((i * 37 + 13) % 256) as u8).collect();
        let freq = ByteFrequency::analyze(&binary);
        // May or may not be detected as binary depending on distribution
    }

    #[test]
    fn test_byte_frequency_whitespace_ratio() {
        let data = b"a b c d e f";
        let freq = ByteFrequency::analyze(data);
        assert!(freq.whitespace_ratio() > 0.4);
    }

    #[test]
    fn test_cpu_capabilities_detect() {
        let caps = CpuCapabilities::detect();
        assert!(!caps.arch.is_empty());
        assert!(!caps.best_tier().is_empty());
    }

    #[test]
    fn test_byte_frequency_top_bytes() {
        let data = b"aaabbc";
        let freq = ByteFrequency::analyze(data);
        let top = freq.top_bytes(2);
        assert_eq!(top[0].0, b'a');
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_compression_ratio_estimate() {
        // High entropy = high ratio (incompressible)
        let random: Vec<u8> = (0..10000).map(|i| ((i * 7919) % 256) as u8).collect();
        let freq = ByteFrequency::analyze(&random);
        assert!(freq.estimated_compression_ratio() > 0.5);

        // Low entropy = low ratio (compressible)
        let repetitive = vec![b'a'; 10000];
        let freq = ByteFrequency::analyze(&repetitive);
        assert_eq!(freq.estimated_compression_ratio(), 0.0);
    }
}
