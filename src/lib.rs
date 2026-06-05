//! jatin-lean — library crate for programmatic access.
//!
//! This module re-exports all public APIs so that integration tests
//! and downstream Rust code can use jatin-lean as a library.

#![allow(
    clippy::too_many_arguments,
    clippy::mut_from_ref,
    clippy::unnecessary_sort_by,
    clippy::new_without_default,
    clippy::doc_lazy_continuation,
    clippy::if_same_then_else
)]
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

pub mod adaptive_engine;
pub mod allocator;
pub mod analytics;
pub mod analyzer;
pub mod benchmark;
pub mod bpf_verifier;
pub mod cache;
pub mod compress;
pub mod config;
pub mod cpu_cache;
pub mod dedup;
pub mod deleter;
pub mod display;
pub mod distributed_cache;
pub mod hardware_tuning;
pub mod health;
pub mod hedging;
pub mod io_uring;
pub mod lockfile;
pub mod maglev;
pub mod memory_pool;
pub mod mmap;
pub mod mmap_ipc;
pub mod network;
pub mod pcie_bottleneck;
pub mod plugin;
pub mod policy;
pub mod profiler;
pub mod request_coalescing;
pub mod ringbuffer;
pub mod rules;
pub mod scanner;
pub mod shared_memory_ipc;
pub mod simd;
pub mod simd_json;
pub mod snapshot;
pub mod static_plugins;
pub mod strategy;
pub mod syscall;
pub mod tracer;
pub mod treeshake;
pub mod unified_gateway;
pub mod visualizer;
pub mod watcher;
pub mod xdp_middleware;
pub mod zero_copy_serde;

// New modules for actionable optimizations
pub mod impact_measurement;
pub mod optimization;
pub mod system_apply;

// Node.js bindings
#[cfg(feature = "napi")]
pub mod node_bindings;
pub mod network_trace;
