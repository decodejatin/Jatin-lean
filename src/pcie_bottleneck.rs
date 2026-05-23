//! PCIe Bottleneck Quantifier & CUDA Memory Transfer Simulator
//!
//! From Sections 5.1-5.3: Models PCIe bandwidth limits, CUDA memory
//! paradigms (pageable, pinned, unified, HW-coherent), prefetch
//! scheduling, and VRAM layer offloading for LLM inference.

// ─── PCIe Specifications ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieGen {
    Gen3,
    Gen4,
    Gen5,
    NvLinkC2C,
}

impl PcieGen {
    /// Bidirectional bandwidth in GB/s.
    pub fn bandwidth_gbps(&self) -> f64 {
        match self {
            Self::Gen3 => 32.0,
            Self::Gen4 => 64.0,
            Self::Gen5 => 128.0,
            Self::NvLinkC2C => 900.0,
        }
    }

    /// Per-lane bandwidth (GT/s).
    pub fn per_lane_gts(&self) -> f64 {
        match self {
            Self::Gen3 => 8.0,
            Self::Gen4 => 16.0,
            Self::Gen5 => 32.0,
            Self::NvLinkC2C => 900.0,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Gen3 => "PCIe Gen3 x16",
            Self::Gen4 => "PCIe Gen4 x16",
            Self::Gen5 => "PCIe Gen5 x16",
            Self::NvLinkC2C => "NVLink-C2C",
        }
    }
}

// ─── CUDA Memory Paradigm Simulator ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CudaMemoryType {
    /// Standard pageable — worst performance
    Pageable,
    /// Pinned (page-locked) — saturates PCIe
    Pinned,
    /// cudaMallocManaged — page fault migration
    UnifiedManaged,
    /// Grace Hopper hardware-coherent unified
    HardwareCoherent,
}

impl CudaMemoryType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pageable => "Pageable (malloc)",
            Self::Pinned => "Pinned (cudaHostAlloc)",
            Self::UnifiedManaged => "Unified (cudaMallocManaged)",
            Self::HardwareCoherent => "HW-Coherent (GH200 NVLink-C2C)",
        }
    }

    /// Effective bandwidth as percentage of theoretical PCIe max.
    pub fn bandwidth_efficiency(&self) -> f64 {
        match self {
            Self::Pageable => 0.40,
            Self::Pinned => 0.95,
            Self::UnifiedManaged => 0.55,
            Self::HardwareCoherent => 0.98,
        }
    }

    /// First-access latency (ns).
    pub fn first_access_latency_ns(&self) -> f64 {
        match self {
            Self::Pageable => 15000.0,       // Copy + page staging
            Self::Pinned => 5000.0,          // DMA setup
            Self::UnifiedManaged => 50000.0, // Page fault + 8KB migration
            Self::HardwareCoherent => 200.0, // Hardware cache coherency
        }
    }

    /// Programming complexity (1-10).
    pub fn complexity(&self) -> u8 {
        match self {
            Self::Pageable => 2,
            Self::Pinned => 7,
            Self::UnifiedManaged => 3,
            Self::HardwareCoherent => 2,
        }
    }
}

/// Simulate a CUDA memory transfer.
#[derive(Debug, Clone)]
pub struct TransferSimulation {
    pub mem_type: CudaMemoryType,
    pub interconnect: PcieGen,
    pub data_size_bytes: u64,
    pub transfer_time_us: f64,
    pub effective_bandwidth_gbps: f64,
    pub first_access_latency_ns: f64,
    pub page_faults: u64,
}

/// Simulate a memory transfer between CPU and GPU.
pub fn simulate_transfer(
    mem_type: CudaMemoryType,
    interconnect: PcieGen,
    data_size_bytes: u64,
) -> TransferSimulation {
    let bw = interconnect.bandwidth_gbps() * mem_type.bandwidth_efficiency();
    let transfer_time_us = (data_size_bytes as f64) / (bw * 1e3); // GB/s → bytes/µs
    let page_faults = if mem_type == CudaMemoryType::UnifiedManaged {
        data_size_bytes / 8192 // 8KB page size for CUDA UM
    } else {
        0
    };

    TransferSimulation {
        mem_type,
        interconnect,
        data_size_bytes,
        transfer_time_us,
        effective_bandwidth_gbps: bw,
        first_access_latency_ns: mem_type.first_access_latency_ns(),
        page_faults,
    }
}

// ─── PCIe Hardware Performance Counter Profiler ──────────────────────────────

/// Simulated Hardware Performance Counters for PCIe.
#[derive(Debug, Clone, Default)]
pub struct HardwarePerfCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_tlp_count: u64,
    pub rx_tlp_count: u64,
    pub correctable_errors: u32,
    pub uncorrectable_errors: u32,
    pub active_lanes: u8,
    pub link_speed_gts: f64,
}

/// PCIe Bottleneck Profiler report.
#[derive(Debug, Clone)]
pub struct ProfilerReport {
    pub utilization_pct: f64,
    pub severity: String,
    pub tlp_overhead_bytes: u64,
    pub is_bottleneck: bool,
    pub recommendation: String,
}

/// PCIe Bottleneck Profiler that analyzes hardware performance counters.
#[derive(Debug, Clone)]
pub struct PcieProfiler {
    pub counters: HardwarePerfCounters,
    pub interconnect: PcieGen,
}

impl PcieProfiler {
    pub fn new(interconnect: PcieGen) -> Self {
        Self {
            counters: HardwarePerfCounters {
                active_lanes: 16,
                link_speed_gts: interconnect.per_lane_gts(),
                ..Default::default()
            },
            interconnect,
        }
    }

    /// Simulate reading performance counters after a workload.
    pub fn record_workload(&mut self, sim: &TransferSimulation) {
        self.counters.tx_bytes += sim.data_size_bytes;
        // Assume 1 TLP per 256 bytes payload + 24 bytes overhead
        self.counters.tx_tlp_count += sim.data_size_bytes / 256;
        
        // Simulate minor errors on high utilization
        if sim.effective_bandwidth_gbps > self.interconnect.bandwidth_gbps() * 0.9 {
            self.counters.correctable_errors += 1;
        }
    }

    /// Calculate the theoretical max throughput in bytes per second for the active link.
    pub fn theoretical_max_throughput(&self) -> f64 {
        self.interconnect.bandwidth_gbps() * 1_000_000_000.0 * (self.counters.active_lanes as f64 / 16.0)
    }

    /// Calculate link utilization given an elapsed time in seconds.
    pub fn link_utilization_pct(&self, elapsed_sec: f64) -> f64 {
        if elapsed_sec <= 0.0 {
            return 0.0;
        }
        let max_bytes = self.theoretical_max_throughput() * elapsed_sec;
        let total_bytes = self.counters.tx_bytes + self.counters.rx_bytes;
        ((total_bytes as f64) / max_bytes) * 100.0
    }

    /// Identify if a bottleneck exists based on TLP overhead and utilization.
    pub fn analyze_bottleneck(&self, elapsed_sec: f64) -> ProfilerReport {
        let util = self.link_utilization_pct(elapsed_sec);
        let tlp_overhead = self.counters.tx_tlp_count * 24; // 24 bytes overhead per TLP
        
        let is_bottleneck = util > 85.0;
        let severity = if util > 95.0 {
            "CRITICAL"
        } else if util > 85.0 {
            "WARNING"
        } else {
            "HEALTHY"
        };

        ProfilerReport {
            utilization_pct: util,
            severity: severity.to_string(),
            tlp_overhead_bytes: tlp_overhead,
            is_bottleneck,
            recommendation: if is_bottleneck {
                "Increase PCIe generation, use pinned memory, or implement data compression."
            } else {
                "Link operates within acceptable parameters."
            }.to_string(),
        }
    }
}

// ─── cudaMemPrefetchAsync Simulation ─────────────────────────────────────────

/// Prefetch schedule entry.
#[derive(Debug, Clone)]
pub struct PrefetchEntry {
    pub offset: u64,
    pub size: u64,
    pub target_device: PrefetchTarget,
    pub stream_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PrefetchTarget {
    Gpu(u32), // GPU device ID
    Cpu,
}

/// Schedule prefetch operations to mask transfer latency.
pub fn schedule_prefetch(
    total_bytes: u64,
    chunk_size: u64,
    target: PrefetchTarget,
) -> Vec<PrefetchEntry> {
    let mut schedule = Vec::new();
    let mut offset = 0;
    let mut stream = 0u32;

    while offset < total_bytes {
        let size = chunk_size.min(total_bytes - offset);
        schedule.push(PrefetchEntry {
            offset,
            size,
            target_device: target,
            stream_id: stream % 4, // Round-robin 4 CUDA streams
        });
        offset += size;
        stream += 1;
    }
    schedule
}

// ─── VRAM Layer Offloading Controller ────────────────────────────────────────

/// LLM layer offloading decision.
#[derive(Debug, Clone)]
pub struct LayerOffload {
    pub layer_id: usize,
    pub layer_name: String,
    pub size_bytes: u64,
    pub placement: LayerPlacement,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerPlacement {
    Vram,
    SystemRam,
    NvLinkUnified,
}

impl LayerPlacement {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Vram => "GPU VRAM (HBM3)",
            Self::SystemRam => "CPU System RAM (LPDDR5X)",
            Self::NvLinkUnified => "NVLink Unified Memory",
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Vram => "🟢",
            Self::SystemRam => "🔵",
            Self::NvLinkUnified => "🟡",
        }
    }
}

/// Offload controller for LLM layer placement.
pub struct VramOffloadController {
    pub vram_capacity_bytes: u64,
    pub system_ram_bytes: u64,
    pub has_nvlink: bool,
    pub vram_used: u64,
}

impl VramOffloadController {
    pub fn new(vram_gb: u64, sys_ram_gb: u64, has_nvlink: bool) -> Self {
        Self {
            vram_capacity_bytes: vram_gb * 1024 * 1024 * 1024,
            system_ram_bytes: sys_ram_gb * 1024 * 1024 * 1024,
            has_nvlink,
            vram_used: 0,
        }
    }

    pub fn grace_hopper() -> Self {
        Self::new(96, 512, true) // 96GB HBM3 + 512GB LPDDR5X
    }

    pub fn discrete_gpu() -> Self {
        Self::new(80, 256, false) // A100 80GB + 256GB DDR5
    }

    /// Place LLM layers optimally across VRAM and system RAM.
    pub fn place_layers(&mut self, layers: &[(String, u64)]) -> Vec<LayerOffload> {
        let mut placements = Vec::new();
        self.vram_used = 0;

        for (i, (name, size)) in layers.iter().enumerate() {
            let placement = if self.vram_used + size <= self.vram_capacity_bytes {
                self.vram_used += size;
                LayerOffload {
                    layer_id: i,
                    layer_name: name.clone(),
                    size_bytes: *size,
                    placement: LayerPlacement::Vram,
                    reason: format!(
                        "Fits in VRAM ({:.1}/{:.1} GB used)",
                        self.vram_used as f64 / 1e9,
                        self.vram_capacity_bytes as f64 / 1e9
                    ),
                }
            } else if self.has_nvlink {
                LayerOffload {
                    layer_id: i,
                    layer_name: name.clone(),
                    size_bytes: *size,
                    placement: LayerPlacement::NvLinkUnified,
                    reason: "VRAM full → NVLink unified memory (900 GB/s)".into(),
                }
            } else {
                LayerOffload {
                    layer_id: i,
                    layer_name: name.clone(),
                    size_bytes: *size,
                    placement: LayerPlacement::SystemRam,
                    reason: "VRAM full → CPU offload (PCIe bottleneck)".into(),
                }
            };
            placements.push(placement);
        }
        placements
    }
}

pub fn print_pcie_report(sims: &[TransferSimulation]) {
    use console::style;
    println!();
    println!(
        "  {} {}",
        style("PCIe & CUDA Memory Transfer Analysis").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    for s in sims {
        println!(
            "  {} {} via {} | {:.1} GB",
            style("▸").dim(),
            style(s.mem_type.label()).yellow(),
            s.interconnect.label(),
            s.data_size_bytes as f64 / 1e9
        );
        println!(
            "    Transfer: {:.1} µs | BW: {:.1} GB/s | 1st access: {:.0} ns | Faults: {}",
            s.transfer_time_us,
            s.effective_bandwidth_gbps,
            s.first_access_latency_ns,
            s.page_faults
        );
    }
    println!();
}

pub fn print_profiler_report(report: &ProfilerReport) {
    use console::style;
    println!();
    println!(
        "  {} {}",
        style("PCIe Bottleneck Profiler").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    let sev_style = if report.is_bottleneck { style(&report.severity).red().bold() } else { style(&report.severity).green().bold() };
    println!(
        "  {} Status: {} | Utilization: {:.1}%",
        style("▸").dim(),
        sev_style,
        report.utilization_pct
    );
    println!(
        "  {} TLP Overhead: {:.1} MB",
        style("▸").dim(),
        report.tlp_overhead_bytes as f64 / 1_000_000.0
    );
    println!(
        "  {} Recommendation: {}",
        style("▸").dim(),
        style(&report.recommendation).yellow()
    );
    println!();
}

pub fn print_offload_report(placements: &[LayerOffload]) {
    use console::style;
    println!();
    println!(
        "  {} {}",
        style("VRAM Layer Offloading Plan").cyan().bold(),
        style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
    );
    let mut vram_total = 0u64;
    let mut sys_total = 0u64;
    let mut nvlink_total = 0u64;
    for p in placements {
        match p.placement {
            LayerPlacement::Vram => vram_total += p.size_bytes,
            LayerPlacement::SystemRam => sys_total += p.size_bytes,
            LayerPlacement::NvLinkUnified => nvlink_total += p.size_bytes,
        }
        println!(
            "  {} Layer {}: {} → {} ({:.1} GB) — {}",
            p.placement.icon(),
            p.layer_id,
            style(&p.layer_name).white(),
            p.placement.label(),
            p.size_bytes as f64 / 1e9,
            style(&p.reason).dim()
        );
    }
    println!();
    println!(
        "  {} VRAM: {:.1} GB | NVLink: {:.1} GB | System RAM: {:.1} GB",
        style("📊").yellow(),
        vram_total as f64 / 1e9,
        nvlink_total as f64 / 1e9,
        sys_total as f64 / 1e9
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_sim() {
        let sim = simulate_transfer(CudaMemoryType::Pinned, PcieGen::Gen5, 1024 * 1024 * 1024);
        assert!(sim.effective_bandwidth_gbps > 100.0);
        assert_eq!(sim.page_faults, 0);
    }

    #[test]
    fn test_unified_page_faults() {
        let sim = simulate_transfer(CudaMemoryType::UnifiedManaged, PcieGen::Gen4, 1024 * 1024);
        assert!(sim.page_faults > 0);
    }

    #[test]
    fn test_nvlink_bandwidth() {
        let sim = simulate_transfer(
            CudaMemoryType::HardwareCoherent,
            PcieGen::NvLinkC2C,
            1024 * 1024 * 1024,
        );
        assert!(sim.effective_bandwidth_gbps > 800.0);
    }

    #[test]
    fn test_prefetch_schedule() {
        let schedule = schedule_prefetch(1024 * 1024 * 100, 1024 * 1024, PrefetchTarget::Gpu(0));
        assert_eq!(schedule.len(), 100);
        assert_eq!(schedule[0].stream_id, 0);
        assert_eq!(schedule[3].stream_id, 3);
    }

    #[test]
    fn test_vram_offload_gh() {
        let mut ctrl = VramOffloadController::grace_hopper();
        let layers: Vec<(String, u64)> = (0..100)
            .map(|i| {
                (
                    format!("transformer.layer.{}", i),
                    2u64 * 1024 * 1024 * 1024,
                )
            })
            .collect();
        let plan = ctrl.place_layers(&layers);
        assert_eq!(plan.len(), 100);
        let vram_count = plan
            .iter()
            .filter(|p| p.placement == LayerPlacement::Vram)
            .count();
        assert!(vram_count > 0 && vram_count < 100);
        let nvlink_count = plan
            .iter()
            .filter(|p| p.placement == LayerPlacement::NvLinkUnified)
            .count();
        assert!(nvlink_count > 0); // Some layers overflow to NVLink
    }

    #[test]
    fn test_discrete_offload() {
        let mut ctrl = VramOffloadController::discrete_gpu();
        let layers: Vec<(String, u64)> = (0..50)
            .map(|i| (format!("layer.{}", i), 4u64 * 1024 * 1024 * 1024))
            .collect();
        let plan = ctrl.place_layers(&layers);
        let sys_count = plan
            .iter()
            .filter(|p| p.placement == LayerPlacement::SystemRam)
            .count();
        assert!(sys_count > 0); // No NVLink, must use system RAM
    }

    #[test]
    fn test_pcie_profiler() {
        let sim = simulate_transfer(CudaMemoryType::Pinned, PcieGen::Gen3, 30_000_000_000); // 30GB transfer
        let mut profiler = PcieProfiler::new(PcieGen::Gen3);
        profiler.record_workload(&sim);
        
        // Simulating that the transfer took exactly 1 second (100% of 30GB/s Gen3 BW)
        let report = profiler.analyze_bottleneck(1.0);
        
        assert!(report.is_bottleneck);
        assert_eq!(report.severity, "WARNING"); // 30GB/s on 32GB/s max = 93.75% utilization
        assert!(report.tlp_overhead_bytes > 0);
    }
}
