use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunTimings {
    pub run_tag: String,
    pub dataset_source: String,
    pub num_parties: usize,
    pub threshold: usize,
    pub num_common_ips: usize,
    pub party_set_size: usize,
    pub num_bloom_bits: usize,
    pub num_hash_funcs: usize,

    pub circuit_num_terms: Option<usize>,
    pub circuit_and_per_bit: Option<usize>,
    pub circuit_or_per_bit: Option<usize>,

    pub load_dataset_s: Option<f64>,
    pub build_bloom_filters_s: Option<f64>,
    pub circuit_build_s: Option<f64>,
    pub plaintext_eval_s: Option<f64>,
    pub plaintext_extract_s: Option<f64>,

    pub fhe_backend: Option<String>,
    pub fhe_keygen_s: Option<f64>,
    pub fhe_encrypt_s: Option<f64>,
    pub fhe_evaluate_s: Option<f64>,
    pub fhe_decrypt_s: Option<f64>,
    pub fhe_extract_s: Option<f64>,
    pub fhe_total_s: Option<f64>,

    pub transcipher_name: Option<String>,

    pub transcipher_backend: Option<String>,
    pub transcipher_sym_keygen_s: Option<f64>,
    pub transcipher_sym_encrypt_s: Option<f64>,

    pub transcipher_fhe_keygen_s: Option<f64>,
    pub transcipher_key_encrypt_s: Option<f64>,

    pub transcipher_homomorphic_decrypt_s: Option<f64>,

    pub transcipher_init_s: Option<f64>,

    pub transcipher_per_bit_total_s: Option<f64>,

    pub transcipher_bits_evaluated: Option<usize>,

    pub transcipher_throughput_bps: Option<f64>,

    pub transcipher_pbs_per_output_bit: Option<f64>,
    pub transcipher_multiplicative_depth: Option<usize>,
    pub transcipher_fixed_init_pbs: Option<usize>,
    pub transcipher_total_s: Option<f64>,
    pub transcipher_matches_plaintext: Option<bool>,

    pub transcipher_sym_ciphertext_bits: Option<usize>,

    pub transcipher_parties_transciphered: Option<usize>,

    pub transcipher_sop_evaluate_s: Option<f64>,

    pub transcipher_sop_decrypt_s: Option<f64>,

    pub transcipher_sop_total_s: Option<f64>,

    pub transcipher_sop_matches_plaintext: Option<bool>,

    pub transcipher_num_recovered: Option<usize>,

    pub payload_plain_bytes: Option<usize>,

    pub payload_fhe_direct_bytes: Option<usize>,

    pub payload_transcipher_bytes: Option<usize>,

    pub expansion_fhe_direct: Option<f64>,

    pub expansion_transcipher: Option<f64>,

    pub bandwidth_savings_ratio: Option<f64>,

    pub transcipher_ms_per_bit: Option<f64>,

    pub transcipher_full_payload_est_s: Option<f64>,

    pub fhe_bits_evaluated: Option<usize>,

    pub fhe_eval_full_est_s: Option<f64>,

    pub encrypted_matches_plaintext: Option<bool>,
    pub num_recovered: Option<usize>,
    pub num_exact: Option<usize>,

    pub candidate_pool_size: Option<usize>,

    pub plaintext_recovered: Option<usize>,

    pub false_positives: Option<usize>,

    pub fpr_observed: Option<f64>,

    pub peak_rss_bytes: Option<usize>,
}

pub fn peak_rss_bytes() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: usize = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

pub fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5\n");
}

pub fn fmt_secs(v: Option<f64>) -> String {
    match v {
        Some(s) => format!("{:.3}s", s),
        None => "n/a".to_string(),
    }
}

pub fn render_timing_table(title: &str, rows: &[RunTimings]) {
    println!("\n{}", "=".repeat(78));
    println!("{}", title);
    println!("{}", "=".repeat(78));
    println!(
        "{:<24} {:<9} {:<9} {:<9} {:<9} {:<9} {:<9}",
        "run", "load", "bloom", "plain", "fhe_enc", "fhe_eval", "fhe_dec"
    );
    println!("{}", "-".repeat(78));
    for r in rows {
        println!(
            "{:<24} {:<9} {:<9} {:<9} {:<9} {:<9} {:<9}",
            truncate(&r.run_tag, 24),
            fmt_secs(r.load_dataset_s),
            fmt_secs(r.build_bloom_filters_s),
            fmt_secs(r.plaintext_eval_s),
            fmt_secs(r.fhe_encrypt_s),
            fmt_secs(r.fhe_evaluate_s),
            fmt_secs(r.fhe_decrypt_s),
        );
    }

    let any_tc = rows.iter().any(|r| r.transcipher_name.is_some());
    if any_tc {
        println!("\n{}", "-".repeat(102));
        println!(
            "{:<22} {:<22} {:<9} {:<8} {:<8} {:<10} {:<8} {:<10} {:<6}",
            "transcipher",
            "cipher",
            "backend",
            "init",
            "per-bit",
            "ms/bit",
            "bits",
            "thrpt b/s",
            "match",
        );
        println!("{}", "-".repeat(102));
        for r in rows {
            if r.transcipher_name.is_none() {
                continue;
            }
            let m = match r.transcipher_matches_plaintext {
                Some(true) => "PASS",
                Some(false) => "FAIL",
                None => "-",
            };
            println!(
                "{:<22} {:<22} {:<9} {:<8} {:<8} {:<10} {:<8} {:<10} {:<6}",
                truncate(&r.run_tag, 22),
                truncate(&r.transcipher_name.clone().unwrap_or_default(), 22),
                r.transcipher_backend.clone().unwrap_or_else(|| "?".into()),
                fmt_secs(r.transcipher_init_s),
                fmt_secs(r.transcipher_per_bit_total_s),
                r.transcipher_ms_per_bit
                    .map(|v| format!("{:.1}", v))
                    .unwrap_or_else(|| "n/a".into()),
                r.transcipher_bits_evaluated
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                r.transcipher_throughput_bps
                    .map(|v| format!("{:.1}", v))
                    .unwrap_or_else(|| "n/a".into()),
                m,
            );
        }

        println!("\n{}", "-".repeat(94));
        println!(
            "{:<22} {:<12} {:>16} {:>10} {:>16}",
            "cipher metadata", "cipher", "PBS/out_bit", "depth", "fixed_init_PBS"
        );
        println!("{}", "-".repeat(94));
        for r in rows {
            if r.transcipher_name.is_none() {
                continue;
            }
            println!(
                "{:<22} {:<12} {:>16} {:>10} {:>16}",
                truncate(&r.run_tag, 22),
                r.transcipher_name.clone().unwrap_or_default(),
                r.transcipher_pbs_per_output_bit
                    .map(|v| format!("{:.2}", v))
                    .unwrap_or_else(|| "n/a".into()),
                r.transcipher_multiplicative_depth
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                r.transcipher_fixed_init_pbs
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".into()),
            );
        }

        let any_sop = rows.iter().any(|r| r.transcipher_sop_total_s.is_some());
        if any_sop {
            println!("\n{}", "-".repeat(94));
            println!(
                "{:<22} {:>8} {:>10} {:>10} {:>10} {:>8} {:>10}",
                "transcipher TPSI SOP",
                "parties",
                "sop_eval",
                "sop_dec",
                "sop_total",
                "sop_ok",
                "recovered",
            );
            println!("{}", "-".repeat(94));
            for r in rows {
                if r.transcipher_sop_total_s.is_none() {
                    continue;
                }
                let ok = match r.transcipher_sop_matches_plaintext {
                    Some(true) => "PASS",
                    Some(false) => "FAIL",
                    None => "-",
                };
                println!(
                    "{:<22} {:>8} {:>10} {:>10} {:>10} {:>8} {:>10}",
                    truncate(&r.run_tag, 22),
                    r.transcipher_parties_transciphered
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "n/a".into()),
                    fmt_secs(r.transcipher_sop_evaluate_s),
                    fmt_secs(r.transcipher_sop_decrypt_s),
                    fmt_secs(r.transcipher_sop_total_s),
                    ok,
                    r.transcipher_num_recovered
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "n/a".into()),
                );
            }
        }
    }

    let any_size = rows.iter().any(|r| r.payload_plain_bytes.is_some());
    if any_size {
        println!("\n{}", "-".repeat(78));
        println!(
            "{:<24} {:>10} {:>12} {:>12} {:>8} {:>8}",
            "size / bandwidth", "plain", "fhe_direct", "transcipher", "exp_fhe", "exp_tc"
        );
        println!("{}", "-".repeat(78));
        for r in rows {
            if r.payload_plain_bytes.is_none() {
                continue;
            }
            println!(
                "{:<24} {:>10} {:>12} {:>12} {:>8} {:>8}",
                truncate(&r.run_tag, 24),
                fmt_bytes(r.payload_plain_bytes),
                fmt_bytes(r.payload_fhe_direct_bytes),
                fmt_bytes(r.payload_transcipher_bytes),
                fmt_ratio(r.expansion_fhe_direct),
                fmt_ratio(r.expansion_transcipher),
            );
        }
        for r in rows {
            if let Some(savings) = r.bandwidth_savings_ratio {
                println!(
                    "  {} bandwidth savings (fhe_direct / transcipher) = {:.1}x",
                    truncate(&r.run_tag, 24),
                    savings,
                );
            }
            if let Some(ms) = r.transcipher_ms_per_bit {
                println!(
                    "  {} transcipher cost = {:.2} ms/bit; full filter est. {:.1}s",
                    truncate(&r.run_tag, 24),
                    ms,
                    r.transcipher_full_payload_est_s.unwrap_or(0.0),
                );
            }
        }
    }

    for r in rows {
        if let Some(rss) = r.peak_rss_bytes {
            println!(
                "  {} peak RSS = {}",
                truncate(&r.run_tag, 24),
                fmt_bytes(Some(rss))
            );
        }
    }
    println!("{}", "=".repeat(78));
}

fn fmt_bytes(v: Option<usize>) -> String {
    match v {
        Some(b) if b >= 1 << 30 => format!("{:.2} GiB", b as f64 / (1u64 << 30) as f64),
        Some(b) if b >= 1 << 20 => format!("{:.2} MiB", b as f64 / (1u64 << 20) as f64),
        Some(b) if b >= 1 << 10 => format!("{:.2} KiB", b as f64 / (1u64 << 10) as f64),
        Some(b) => format!("{} B", b),
        None => "n/a".to_string(),
    }
}

fn fmt_ratio(v: Option<f64>) -> String {
    match v {
        Some(x) if x >= 1.0 => format!("{:.1}x", x),
        Some(x) => format!("{:.3}x", x),
        None => "n/a".to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
