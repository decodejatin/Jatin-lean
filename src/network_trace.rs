use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};


/// eBPF Network Trace Collector
/// Collects and aggregates network traces.
#[derive(Debug, Default)]
pub struct NetworkTraceCollector {
    packets_traced: AtomicU64,
    bytes_traced: AtomicU64,
}

impl NetworkTraceCollector {
    pub fn new() -> Self {
        Self {
            packets_traced: AtomicU64::new(0),
            bytes_traced: AtomicU64::new(0),
        }
    }

    pub fn trace_packet(&self, src_ip: IpAddr, dst_ip: IpAddr, size: usize) {
        self.packets_traced.fetch_add(1, Ordering::Relaxed);
        self.bytes_traced.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn report(&self) -> (u64, u64) {
        (
            self.packets_traced.load(Ordering::Relaxed),
            self.bytes_traced.load(Ordering::Relaxed),
        )
    }
}
