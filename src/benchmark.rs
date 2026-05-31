//! Built-in micro-benchmark engine for performance validation.
//!
//! Provides:
//!   - Warm-up + measured iteration benchmarks
//!   - Statistical analysis (mean, median, stddev, percentiles)
//!   - Throughput calculation (ops/sec, MB/s)
//!   - Comparison between runs
//!   - Hardware timer resolution detection

use console::style;
use std::time::{Duration, Instant};

use crate::scanner::format_size;

// ─── Benchmark Runner ────────────────────────────────────────────────────────

/// Configuration for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Number of warm-up iterations.
    pub warmup_iters: u32,
    /// Number of measured iterations.
    pub measure_iters: u32,
    /// Minimum duration for the benchmark (auto-scales iterations).
    pub min_duration: Duration,
    /// Maximum duration cap.
    pub max_duration: Duration,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            warmup_iters: 3,
            measure_iters: 10,
            min_duration: Duration::from_millis(100),
            max_duration: Duration::from_secs(30),
        }
    }
}

/// Result of a single benchmark.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub name: String,
    pub samples: Vec<f64>, // nanoseconds per iteration
    pub total_time: Duration,
    pub iterations: u32,
    pub items_per_iter: u64,
    pub bytes_per_iter: u64,
}

impl BenchResult {
    /// Mean time per iteration (nanoseconds).
    pub fn mean_ns(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }

    /// Median time per iteration (nanoseconds).
    pub fn median_ns(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    /// Standard deviation (nanoseconds).
    pub fn stddev_ns(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let mean = self.mean_ns();
        let variance = self.samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>()
            / (self.samples.len() - 1) as f64;
        variance.sqrt()
    }

    /// Minimum time (nanoseconds).
    pub fn min_ns(&self) -> f64 {
        self.samples.iter().cloned().fold(f64::INFINITY, f64::min)
    }

    /// Maximum time (nanoseconds).
    pub fn max_ns(&self) -> f64 {
        self.samples
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max)
    }

    /// P95 percentile (nanoseconds).
    pub fn p95_ns(&self) -> f64 {
        percentile(&self.samples, 95.0)
    }

    /// P99 percentile (nanoseconds).
    pub fn p99_ns(&self) -> f64 {
        percentile(&self.samples, 99.0)
    }

    /// Operations per second.
    pub fn ops_per_sec(&self) -> f64 {
        let mean_secs = self.mean_ns() / 1_000_000_000.0;
        if mean_secs > 0.0 {
            1.0 / mean_secs
        } else {
            0.0
        }
    }

    /// Items throughput (items/sec).
    pub fn items_per_sec(&self) -> f64 {
        self.ops_per_sec() * self.items_per_iter as f64
    }

    /// Bytes throughput (bytes/sec).
    pub fn bytes_per_sec(&self) -> f64 {
        self.ops_per_sec() * self.bytes_per_iter as f64
    }

    /// Format time for display.
    pub fn format_time(ns: f64) -> String {
        if ns < 1_000.0 {
            format!("{:.1} ns", ns)
        } else if ns < 1_000_000.0 {
            format!("{:.1} µs", ns / 1_000.0)
        } else if ns < 1_000_000_000.0 {
            format!("{:.2} ms", ns / 1_000_000.0)
        } else {
            format!("{:.3} s", ns / 1_000_000_000.0)
        }
    }
}

/// Calculate percentile from samples.
fn percentile(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Run a benchmark with the given function.
pub fn bench<F: FnMut()>(name: &str, config: &BenchConfig, mut f: F) -> BenchResult {
    // Warm-up
    for _ in 0..config.warmup_iters {
        f();
    }

    // Measured runs
    let mut samples = Vec::with_capacity(config.measure_iters as usize);
    let total_start = Instant::now();

    for _ in 0..config.measure_iters {
        if total_start.elapsed() > config.max_duration {
            break;
        }

        let start = Instant::now();
        f();
        let elapsed = start.elapsed();
        samples.push(elapsed.as_nanos() as f64);
    }

    let total_time = total_start.elapsed();

    BenchResult {
        name: name.to_string(),
        samples,
        total_time,
        iterations: config.measure_iters,
        items_per_iter: 0,
        bytes_per_iter: 0,
    }
}

/// Run a benchmark with item count tracking.
pub fn bench_with_items<F: FnMut() -> u64>(
    name: &str,
    config: &BenchConfig,
    mut f: F,
) -> BenchResult {
    // Warm-up
    for _ in 0..config.warmup_iters {
        f();
    }

    let mut samples = Vec::with_capacity(config.measure_iters as usize);
    let mut total_items = 0u64;
    let total_start = Instant::now();

    for _ in 0..config.measure_iters {
        if total_start.elapsed() > config.max_duration {
            break;
        }

        let start = Instant::now();
        let items = f();
        let elapsed = start.elapsed();

        total_items += items;
        samples.push(elapsed.as_nanos() as f64);
    }

    let total_time = total_start.elapsed();
    let avg_items = if !samples.is_empty() {
        total_items / samples.len() as u64
    } else {
        0
    };

    BenchResult {
        name: name.to_string(),
        samples,
        total_time,
        iterations: config.measure_iters,
        items_per_iter: avg_items,
        bytes_per_iter: 0,
    }
}

/// Run a benchmark with bytes processed tracking.
pub fn bench_with_bytes<F: FnMut() -> u64>(
    name: &str,
    config: &BenchConfig,
    mut f: F,
) -> BenchResult {
    for _ in 0..config.warmup_iters {
        f();
    }

    let mut samples = Vec::with_capacity(config.measure_iters as usize);
    let mut total_bytes = 0u64;
    let total_start = Instant::now();

    for _ in 0..config.measure_iters {
        if total_start.elapsed() > config.max_duration {
            break;
        }

        let start = Instant::now();
        let bytes = f();
        let elapsed = start.elapsed();

        total_bytes += bytes;
        samples.push(elapsed.as_nanos() as f64);
    }

    let total_time = total_start.elapsed();
    let avg_bytes = if !samples.is_empty() {
        total_bytes / samples.len() as u64
    } else {
        0
    };

    BenchResult {
        name: name.to_string(),
        samples,
        total_time,
        iterations: config.measure_iters,
        items_per_iter: 0,
        bytes_per_iter: avg_bytes,
    }
}

// ─── Benchmark Suite ─────────────────────────────────────────────────────────

/// A collection of benchmarks to run together.
pub struct BenchSuite {
    name: String,
    results: Vec<BenchResult>,
}

impl BenchSuite {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            results: Vec::new(),
        }
    }

    pub fn add(&mut self, result: BenchResult) {
        self.results.push(result);
    }

    pub fn results(&self) -> &[BenchResult] {
        &self.results
    }

    /// Print suite results.
    pub fn print_results(&self) {
        println!();
        println!(
            "  {} {}",
            style("Benchmark Suite").cyan().bold(),
            style(format!(
                "━━ {} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                self.name
            ))
            .dim()
        );
        println!();

        // Header
        println!(
            "  {:25} {:>12} {:>12} {:>10} {:>12} {:>12}",
            style("Benchmark").white().bold(),
            style("Mean").dim(),
            style("Median").dim(),
            style("Stddev").dim(),
            style("P95").dim(),
            style("Ops/sec").dim(),
        );
        println!("  {}", style("─".repeat(85)).dim());

        for result in &self.results {
            let mean = BenchResult::format_time(result.mean_ns());
            let median = BenchResult::format_time(result.median_ns());
            let stddev = BenchResult::format_time(result.stddev_ns());
            let p95 = BenchResult::format_time(result.p95_ns());
            let ops = format!("{:.0}", result.ops_per_sec());

            println!(
                "  {:25} {:>12} {:>12} {:>10} {:>12} {:>12}",
                style(&result.name).white(),
                style(&mean).green(),
                &median,
                style(&stddev).yellow(),
                &p95,
                style(&ops).cyan().bold(),
            );

            // Show throughput if available
            if result.items_per_iter > 0 {
                println!(
                    "  {:25} {:>12}",
                    "",
                    style(format!("{:.0} items/s", result.items_per_sec())).dim(),
                );
            }
            if result.bytes_per_iter > 0 {
                println!(
                    "  {:25} {:>12}",
                    "",
                    style(format!("{}/s", format_size(result.bytes_per_sec() as u64))).dim(),
                );
            }
        }

        println!();
    }
}

// ─── Timer Resolution Detection ──────────────────────────────────────────────

/// Detect the timer resolution on the current platform.
pub fn detect_timer_resolution() -> Duration {
    let mut min_delta = Duration::from_secs(1);

    for _ in 0..100 {
        let start = Instant::now();
        loop {
            let now = Instant::now();
            let delta = now.duration_since(start);
            if delta > Duration::ZERO {
                if delta < min_delta {
                    min_delta = delta;
                }
                break;
            }
        }
    }

    min_delta
}

/// Print timer information.
pub fn print_timer_info() {
    let resolution = detect_timer_resolution();

    println!();
    println!(
        "  {} {}",
        style("Timer Info").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    println!(
        "  {} Resolution: {} ns",
        style("◉").cyan(),
        style(resolution.as_nanos()).white().bold()
    );

    #[cfg(target_arch = "x86_64")]
    {
        println!("  {} Timer source: RDTSC / clock_gettime", style("◉").dim());
    }

    #[cfg(target_arch = "aarch64")]
    {
        println!(
            "  {} Timer source: cntvct_el0 / clock_gettime",
            style("◉").dim()
        );
    }

    println!();
}

// ─── Built-in Benchmarks ─────────────────────────────────────────────────────

/// Run built-in benchmarks for jatin-lean components.
pub fn run_builtin_benchmarks() -> BenchSuite {
    let config = BenchConfig::default();
    let mut suite = BenchSuite::new("jatin-lean internals");

    // 1. SIMD hash benchmark
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let data_clone = data.clone();
    let mut hash_result = bench_with_bytes("SIMD hash (1MB)", &config, || {
        crate::simd::fast_hash(&data_clone);
        data_clone.len() as u64
    });
    hash_result.bytes_per_iter = data.len() as u64;
    suite.add(hash_result);

    // 2. Newline counting benchmark
    let text_data: Vec<u8> = "some typical line of JavaScript code;\n"
        .repeat(50_000)
        .into_bytes();
    let text_clone = text_data.clone();
    let mut nl_result = bench_with_bytes("SIMD newline count", &config, || {
        crate::simd::count_newlines(&text_clone);
        text_clone.len() as u64
    });
    nl_result.bytes_per_iter = text_data.len() as u64;
    suite.add(nl_result);

    // 3. Pattern search benchmark
    let search_data: Vec<u8> = "const express = require('express');\nconst app = express();\n"
        .repeat(20_000)
        .into_bytes();
    let search_clone = search_data.clone();
    let pattern = b"require".to_vec();
    let pattern_clone = pattern.clone();
    let mut pat_result = bench_with_bytes("SIMD pattern search", &config, || {
        crate::simd::find_pattern(&search_clone, &pattern_clone);
        search_clone.len() as u64
    });
    pat_result.bytes_per_iter = search_data.len() as u64;
    suite.add(pat_result);

    // 4. String interner benchmark
    let strings: Vec<String> = (0..10_000)
        .map(|i| format!("package-{}", i % 500))
        .collect();
    let strings_clone = strings.clone();
    let interner_result = bench_with_items("String interning", &config, || {
        let mut interner = crate::allocator::StringInterner::new();
        for s in &strings_clone {
            interner.intern(s);
        }
        strings_clone.len() as u64
    });
    suite.add(interner_result);

    // 5. Byte frequency analysis benchmark
    let freq_data: Vec<u8> = (0..500_000).map(|i| (i % 128 + 32) as u8).collect();
    let freq_clone = freq_data.clone();
    let mut freq_result = bench_with_bytes("Byte frequency analysis", &config, || {
        crate::simd::ByteFrequency::analyze(&freq_clone);
        freq_clone.len() as u64
    });
    freq_result.bytes_per_iter = freq_data.len() as u64;
    suite.add(freq_result);

    suite
}

/// Print a comparison between two bench results.
pub fn print_comparison(baseline: &BenchResult, candidate: &BenchResult) {
    let speedup = baseline.mean_ns() / candidate.mean_ns().max(1.0);
    let pct_change = (1.0 - candidate.mean_ns() / baseline.mean_ns().max(1.0)) * 100.0;

    let trend = if pct_change > 5.0 {
        style(format!("↑ {:.1}% faster", pct_change)).green().bold()
    } else if pct_change < -5.0 {
        style(format!("↓ {:.1}% slower", -pct_change)).red().bold()
    } else {
        style("≈ no significant change".to_string()).dim()
    };

    println!();
    println!(
        "  {} {} vs {}",
        style("Comparison").cyan().bold(),
        style(&baseline.name).dim(),
        style(&candidate.name).white().bold()
    );
    println!(
        "  {} Baseline: {}",
        style("▸").dim(),
        BenchResult::format_time(baseline.mean_ns())
    );
    println!(
        "  {} Candidate: {}",
        style("▸").dim(),
        BenchResult::format_time(candidate.mean_ns())
    );
    println!(
        "  {} Speedup: {:.2}x — {}",
        style("◉").cyan(),
        speedup,
        trend
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bench_basic() {
        let config = BenchConfig {
            warmup_iters: 1,
            measure_iters: 5,
            ..Default::default()
        };

        let result = bench("test", &config, || {
            let _sum: u64 = (0..1000).sum();
        });

        assert_eq!(result.name, "test");
        assert_eq!(result.samples.len(), 5);
        assert!(result.mean_ns() > 0.0);
        assert!(result.median_ns() > 0.0);
    }

    #[test]
    fn test_bench_result_statistics() {
        let result = BenchResult {
            name: "test".to_string(),
            samples: vec![100.0, 200.0, 300.0, 400.0, 500.0],
            total_time: Duration::from_millis(1),
            iterations: 5,
            items_per_iter: 0,
            bytes_per_iter: 0,
        };

        assert_eq!(result.mean_ns(), 300.0);
        assert_eq!(result.median_ns(), 300.0);
        assert_eq!(result.min_ns(), 100.0);
        assert_eq!(result.max_ns(), 500.0);
        assert!(result.stddev_ns() > 0.0);
    }

    #[test]
    fn test_format_time() {
        assert_eq!(BenchResult::format_time(500.0), "500.0 ns");
        assert_eq!(BenchResult::format_time(1500.0), "1.5 µs");
        assert_eq!(BenchResult::format_time(1_500_000.0), "1.50 ms");
        assert_eq!(BenchResult::format_time(1_500_000_000.0), "1.500 s");
    }

    #[test]
    fn test_percentile() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(percentile(&samples, 50.0), 5.0);
        assert_eq!(percentile(&samples, 90.0), 9.0);
    }

    #[test]
    fn test_bench_suite() {
        let mut suite = BenchSuite::new("test suite");
        suite.add(BenchResult {
            name: "bench1".to_string(),
            samples: vec![100.0],
            total_time: Duration::from_millis(1),
            iterations: 1,
            items_per_iter: 0,
            bytes_per_iter: 0,
        });
        assert_eq!(suite.results().len(), 1);
    }

    #[test]
    fn test_timer_resolution() {
        let res = detect_timer_resolution();
        assert!(res.as_nanos() > 0);
        assert!(res < Duration::from_millis(10));
    }

    #[test]
    fn test_ops_per_sec() {
        let result = BenchResult {
            name: "test".to_string(),
            samples: vec![1_000_000.0], // 1ms per op
            total_time: Duration::from_millis(1),
            iterations: 1,
            items_per_iter: 100,
            bytes_per_iter: 1_000_000,
        };
        assert!((result.ops_per_sec() - 1000.0).abs() < 1.0);
        assert!((result.items_per_sec() - 100_000.0).abs() < 100.0);
    }
}
