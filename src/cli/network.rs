//! Network & eBPF commands.

use crate::output::OutputContext;
use anyhow::Result;
use clap::Subcommand;
use console::style;

#[derive(Subcommand, Debug)]
pub enum NetworkCommands {
    /// XDP/eBPF network middleware analysis and benchmarks
    Xdp {
        /// Show architecture comparison table
        #[arg(long)]
        compare: bool,

        /// Run packet processing benchmark
        #[arg(long)]
        bench: bool,

        /// Number of simulated packets
        #[arg(long, default_value = "1000000")]
        packets: u64,

        /// Obfuscation mode: none, udp-to-tcp, xor, tls, http
        #[arg(long, default_value = "none")]
        obfuscation: String,
    },

    /// BPF verifier simulation & DPI evasion analysis
    Bpf {
        /// Run verifier on sample XDP programs
        #[arg(long)]
        verify: bool,

        /// Show DPI evasion technique matrix
        #[arg(long)]
        dpi: bool,

        /// Calculate sk_buff elimination savings
        #[arg(long, value_name = "PACKETS")]
        skbuff: Option<u64>,
    },

    /// Unified 6-stage gateway pipeline benchmark
    Gateway {
        /// Run full pipeline benchmark
        #[arg(long)]
        bench: bool,

        /// Number of requests to process
        #[arg(long, default_value = "10000")]
        requests: u64,

        /// Payload size in bytes
        #[arg(long, default_value = "1024")]
        payload_size: usize,
    },

    /// eBPF Network Trace Collector
    Trace {
        /// Number of packets to simulate tracing
        #[arg(long, default_value = "1000")]
        packets: usize,
    },
}

pub fn handle_command(command: NetworkCommands, ctx: &OutputContext) -> Result<()> {
    if !ctx.json {
        crate::display::print_banner();
    }

    match command {
        NetworkCommands::Xdp {
            compare,
            bench,
            packets,
            obfuscation,
        } => {
            use crate::xdp_middleware::*;

            if !ctx.json {
                println!(
                    "  {} {}",
                    style("eBPF/XDP Network Middleware").cyan().bold(),
                    style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
                );
            }

            let mut json_out = serde_json::Map::new();

            if compare {
                if !ctx.json {
                    print_architecture_comparison();
                }
            }

            if bench {
                let obfs_mode = match obfuscation.as_str() {
                    "udp-to-tcp" | "udp" => ObfuscationMode::UdpToTcp,
                    "xor" => ObfuscationMode::XorScramble,
                    "tls" => ObfuscationMode::TlsMimicry,
                    "http" => ObfuscationMode::HttpInject,
                    _ => ObfuscationMode::None,
                };

                if !ctx.json {
                    println!(
                        "  {} Running XDP benchmark: {} packets, obfuscation: {}",
                        style("⚡").yellow(),
                        style(packets).green().bold(),
                        style(obfs_mode.label()).white()
                    );
                }

                let config = XdpLoadBalancerConfig::default();
                let cp = XdpControlPlane::new(config);
                let start = std::time::Instant::now();

                let dummy_packet = vec![0u8; 1500];
                for _ in 0..packets {
                    cp.inject_live_frame(&dummy_packet, "eth0");
                }

                let elapsed = start.elapsed();
                let pps = packets as f64 / elapsed.as_secs_f64();
                let gbps = (packets as f64 * 1500.0 * 8.0) / (elapsed.as_secs_f64() * 1e9);

                if ctx.json {
                    json_out.insert(
                        "benchmark".to_string(),
                        serde_json::json!({
                            "throughput_mpps": pps / 1e6,
                            "bandwidth_gbps": gbps,
                            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
                            "obfuscation_mode": obfs_mode.label(),
                        }),
                    );
                } else {
                    println!();
                    println!(
                        "  {} Throughput: {} Mpps",
                        style("🚀").yellow(),
                        style(format!("{:.2}", pps / 1e6)).green().bold()
                    );
                    println!(
                        "  {} Bandwidth: {} Gbps",
                        style("🚀").yellow(),
                        style(format!("{:.2}", gbps)).green().bold()
                    );
                    println!(
                        "  {} Elapsed:   {} ms",
                        style("▸").dim(),
                        style(format!("{:.2}", elapsed.as_secs_f64() * 1000.0)).white()
                    );

                    if obfs_mode == ObfuscationMode::XorScramble {
                        let mut payload = b"Hello, XDP!".to_vec();
                        println!("  {} XOR scramble demo:", style("▸").dim());
                        println!(
                            "    Original:   {:?}",
                            std::str::from_utf8(&payload).unwrap()
                        );
                        XdpControlPlane::xor_scramble(&mut payload, 0xDEADBEEF);
                        println!("    Scrambled:  {:02x?}", &payload);
                        XdpControlPlane::xor_scramble(&mut payload, 0xDEADBEEF);
                        println!(
                            "    Recovered:  {:?}",
                            std::str::from_utf8(&payload).unwrap()
                        );
                    }
                    println!();
                }
            }

            if !compare && !bench {
                if !ctx.json {
                    print_architecture_comparison();
                    println!(
                        "  {} Use {} for packet benchmark",
                        style("→").dim(),
                        style("jatin-lean network xdp --bench").yellow()
                    );
                    println!(
                        "  {} Use {} for obfuscation modes",
                        style("→").dim(),
                        style("--obfuscation udp-to-tcp|xor|tls|http").yellow()
                    );
                }
            }

            if ctx.json {
                crate::output::output_result(
                    "network xdp",
                    &serde_json::Value::Object(json_out),
                    ctx,
                )?;
            }
            Ok(())
        }

        NetworkCommands::Bpf {
            verify,
            dpi,
            skbuff,
        } => {
            use crate::bpf_verifier::*;

            if !ctx.json {
                println!(
                    "  {} {}",
                    style("BPF Verifier & DPI Engine").cyan().bold(),
                    style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
                );
            }

            let mut json_out = serde_json::Map::new();

            if verify {
                let programs = vec![
                    BpfProgram {
                        name: "xdp_tunnel_ingress".into(),
                        prog_type: BpfProgType::XdpIngress,
                        instruction_count: 2_500,
                        max_loop_depth: 256,
                        call_depth: 3,
                        map_accesses: 12,
                        packet_accesses: 45,
                        tail_calls: 2,
                        helper_calls: vec![
                            "bpf_xdp_adjust_head".into(),
                            "bpf_map_lookup_elem".into(),
                        ],
                    },
                    BpfProgram {
                        name: "xdp_ddos_filter".into(),
                        prog_type: BpfProgType::XdpIngress,
                        instruction_count: 15_000,
                        max_loop_depth: 1024,
                        call_depth: 5,
                        map_accesses: 30,
                        packet_accesses: 80,
                        tail_calls: 4,
                        helper_calls: vec!["bpf_ktime_get_ns".into(), "bpf_map_update_elem".into()],
                    },
                    BpfProgram {
                        name: "tc_protocol_obfuscator".into(),
                        prog_type: BpfProgType::TcEgress,
                        instruction_count: 800_000,
                        max_loop_depth: 4096,
                        call_depth: 6,
                        map_accesses: 50,
                        packet_accesses: 120,
                        tail_calls: 8,
                        helper_calls: vec!["bpf_skb_change_proto".into()],
                    },
                ];

                let mut verify_results = Vec::new();
                for prog in &programs {
                    let result = prog.verify();
                    if ctx.json {
                        verify_results.push(serde_json::json!({
                            "name": prog.name,
                            "passed": result.accepted,
                            "complexity": result.complexity_score,
                        }));
                    } else {
                        print_verifier_report(prog, &result);
                    }
                }

                if ctx.json {
                    json_out.insert(
                        "verify".to_string(),
                        serde_json::Value::Array(verify_results),
                    );
                }
            }

            if dpi {
                if !ctx.json {
                    println!();
                    println!("  {} DPI Evasion Matrix:", style("🛡️").yellow());
                }

                let methods = [
                    DpiMethod::ProtocolWhitelist,
                    DpiMethod::SniInspection,
                    DpiMethod::PayloadSignature,
                    DpiMethod::DnsFilter,
                    DpiMethod::StatisticalAnalysis,
                ];

                let mut evasion_list = Vec::new();
                for evasion in DpiEvasion::all() {
                    let bypassed: Vec<&str> = methods
                        .iter()
                        .filter(|m| evasion.bypasses(m))
                        .map(|_| "✓")
                        .collect();

                    if ctx.json {
                        evasion_list.push(serde_json::json!({
                            "method": evasion.label(),
                            "overhead_bytes": evasion.overhead_bytes(),
                            "bypassed_count": bypassed.len(),
                        }));
                    } else {
                        println!(
                            "    {} ({} overhead) — bypasses {} DPI methods",
                            style(evasion.label()).yellow(),
                            style(format!("{}B", evasion.overhead_bytes())).dim(),
                            style(bypassed.len()).green().bold()
                        );
                    }
                }

                if ctx.json {
                    json_out.insert(
                        "dpi_evasion".to_string(),
                        serde_json::Value::Array(evasion_list),
                    );
                } else {
                    println!();
                }
            }

            if let Some(packets) = skbuff {
                let model = SkbuffModel::default();
                let savings = model.savings(packets);

                if ctx.json {
                    json_out.insert(
                        "skbuff".to_string(),
                        serde_json::json!({
                            "packets": packets,
                            "cpu_time_saved_ms": savings.total_ns_saved / 1e6,
                            "memory_saved_mb": savings.memory_bytes_saved as f64 / 1e6,
                            "cache_pollution_avoided_mb": savings.cache_bytes_saved as f64 / 1e6,
                            "throughput_gain_pct": savings.equivalent_throughput_gain_pct,
                        }),
                    );
                } else {
                    println!();
                    println!(
                        "  {} sk_buff Elimination for {} packets:",
                        style("📊").yellow(),
                        style(packets).green().bold()
                    );
                    println!(
                        "    CPU time saved:   {:.1} ms",
                        savings.total_ns_saved / 1e6
                    );
                    println!(
                        "    Memory saved:     {:.1} MB",
                        savings.memory_bytes_saved as f64 / 1e6
                    );
                    println!(
                        "    Cache pollution:  {:.1} MB avoided",
                        savings.cache_bytes_saved as f64 / 1e6
                    );
                    println!(
                        "    Throughput gain:  {:.1}%",
                        savings.equivalent_throughput_gain_pct
                    );
                    println!();
                }
            }

            if !verify && !dpi && skbuff.is_none() {
                if !ctx.json {
                    println!();
                    println!(
                        "  {} Use {} for verifier",
                        style("→").dim(),
                        style("jatin-lean network bpf --verify").yellow()
                    );
                    println!(
                        "  {} Use {} for DPI matrix",
                        style("→").dim(),
                        style("jatin-lean network bpf --dpi").yellow()
                    );
                    println!(
                        "  {} Use {} for savings",
                        style("→").dim(),
                        style("jatin-lean network bpf --skbuff 1000000").yellow()
                    );
                    println!();
                }
            }

            if ctx.json {
                crate::output::output_result(
                    "network bpf",
                    &serde_json::Value::Object(json_out),
                    ctx,
                )?;
            }
            Ok(())
        }

        NetworkCommands::Gateway {
            bench,
            requests,
            payload_size,
        } => {
            use crate::unified_gateway::*;

            if !ctx.json {
                println!(
                    "  {} {}",
                    style("Unified Gateway Pipeline").cyan().bold(),
                    style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
                );
            }

            let gw = UnifiedGateway::new();

            let mut json_out = serde_json::Map::new();

            if bench {
                if !ctx.json {
                    println!(
                        "  {} Benchmark: {} requests × {} byte payloads",
                        style("⚡").yellow(),
                        style(requests).green().bold(),
                        style(payload_size).white()
                    );
                }

                let result = gw.benchmark(requests, payload_size);

                if ctx.json {
                    json_out.insert(
                        "benchmark".to_string(),
                        serde_json::json!({
                            "rps": result.rps,
                            "avg_latency_ns": result.avg_latency_ns,
                            "elapsed_ms": result.elapsed.as_secs_f64() * 1000.0,
                        }),
                    );
                } else {
                    println!();
                    println!(
                        "  {} RPS:         {}",
                        style("🚀").yellow(),
                        style(format!("{:.0}", result.rps)).green().bold()
                    );
                    println!(
                        "  {} Avg latency: {:.0} ns",
                        style("⚡").yellow(),
                        result.avg_latency_ns
                    );
                    println!(
                        "  {} Elapsed:     {:.2} ms",
                        style("▸").dim(),
                        result.elapsed.as_secs_f64() * 1000.0
                    );
                    for (stage, ns) in &result.stage_latencies {
                        println!("    {} {} → {:.0} ns", stage.icon(), stage.label(), ns);
                    }
                }
            }

            if ctx.json {
                crate::output::output_result(
                    "network gateway",
                    &serde_json::Value::Object(json_out),
                    ctx,
                )?;
            } else {
                println!();
                print_gateway_report(&gw);
            }
            Ok(())
        }

        NetworkCommands::Trace { packets } => {
            use crate::network_trace::NetworkTraceCollector;
            use std::net::{IpAddr, Ipv4Addr};

            if !ctx.json {
                println!(
                    "  {} {}",
                    style("eBPF Network Trace Collector").cyan().bold(),
                    style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").dim()
                );
            }

            let collector = NetworkTraceCollector::new();

            for i in 0..packets {
                collector.trace_packet(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 255) as u8)),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    64 + (i % 1000),
                );
            }

            let (pkts, bytes) = collector.report();

            if ctx.json {
                let json_out = serde_json::json!({
                    "traced_packets": pkts,
                    "traced_bytes": bytes,
                });
                crate::output::output_result("network trace", &json_out, ctx)?;
            } else {
                println!();
                println!("  {} Traced Packets: {}", style("📊").yellow(), style(pkts).green().bold());
                println!("  {} Traced Bytes:   {}", style("💾").yellow(), style(bytes).white());
                println!();
            }
            Ok(())
        }
    }
}
