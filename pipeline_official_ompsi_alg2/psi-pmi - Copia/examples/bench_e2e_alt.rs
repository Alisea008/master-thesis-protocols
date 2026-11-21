//! Benchmark CLI for psi-pmi — Algorithm 2 (no TEE, simulated CMUX, multi-block).
//!
//! Usage:
//!   cargo run --release --example bench_e2e_alt -- [OPTIONS]
//!
//! Options:
//!   --n <N>           Data owners (default: 2)
//!   --u <U>           Hash families / OT choices (default: 4)
//!   --n-bits <B>      Bloom filter size in bits (default: 128; no limit)
//!   --hash-k <K>      Hash functions per family (default: 3)
//!   --degree <D>      FHE degree; 0 = secure (default: 8192)
//!   --runs <R>        Runs per invocation (default: 3)
//!   --set-size <S>    Elements per DO (default: 10)
//!   --overlap <O>     Shared elements (default: set_size/3)
//!   --out <PATH>      CSV output (default: bench_alg2.csv)
//!   --append          Append to the CSV
//!   --help, -h        Help
//!

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process;

use psi_pmi::psi::{run_e2e_pasta_alt, DataOwnerInput, E2eConfig, E2eResultAlt};
use transieve::cipher::bfv::pasta::PASTA3;

// Benchmark configuration parsed from CLI arguments
#[derive(Clone)]
struct BenchConfig {
    n: usize,
    u: usize,
    n_bits: usize,
    hash_k: usize,
    degree: Option<usize>,
    runs: usize,
    set_size: usize,
    overlap: usize,
    out: PathBuf,
    append: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            n: 2,
            u: 4,
            n_bits: 128,
            hash_k: 3,
            degree: Some(8192),
            runs: 3,
            set_size: 10,
            overlap: 0,
            out: PathBuf::from("bench_alg2.csv"),
            append: false,
        }
    }
}

// Print the CLI usage message to stderr
fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {prog} [OPTIONS]\n\
         \n\
         Options:\n\
           --n <N>        Number of data owners (default: 2)\n\
           --u <U>        Hash families / OT choices (default: 4)\n\
           --n-bits <B>   Bloom filter size in bits (default: 128)\n\
           --hash-k <K>   Hash functions per family (default: 3)\n\
           --degree <D>   FHE degree, 0 = secure (default: 8192)\n\
           --runs <R>     Number of runs (default: 3)\n\
           --set-size <S> Elements per DO (default: 10)\n\
           --overlap <O>  Shared elements (default: set_size/3)\n\
           --out <PATH>   CSV output (default: bench_alg2.csv)\n\
           --append       Append to existing CSV\n\
           --help, -h     Show this help\n\
         \n\
         Multi-block: n_bits and index matrix are split into blocks of PASTA3.t=128."
    );
}

// Parse command-line arguments into a BenchConfig
fn parse_args() -> BenchConfig {
    let mut cfg = BenchConfig::default();
    let args: Vec<String> = std::env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "bench_e2e_alt".into());
    // Track whether --overlap was explicitly set
    let mut overlap_set = false;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "--help" | "-h" => { print_usage(&prog); process::exit(0); }
            "--append" => { cfg.append = true; }
            other => {
                // Helper closure to consume the next argument as a value
                let take = |i: &mut usize, name: &str| -> String {
                    *i += 1;
                    args.get(*i).cloned().unwrap_or_else(|| {
                        eprintln!("error: {name} requires a value");
                        print_usage(&prog);
                        process::exit(1);
                    })
                };
                match other {
                    "--n" => cfg.n = take(&mut i, other).parse().expect("--n"),
                    "--u" => cfg.u = take(&mut i, other).parse().expect("--u"),
                    "--n-bits" => cfg.n_bits = take(&mut i, other).parse().expect("--n-bits"),
                    "--hash-k" => cfg.hash_k = take(&mut i, other).parse().expect("--hash-k"),
                    "--degree" => {
                        let d: usize = take(&mut i, other).parse().expect("--degree");
                        // 0 means "secure" (None); anything else is a forced degree
                        cfg.degree = if d == 0 { None } else { Some(d) };
                    }
                    "--runs" => cfg.runs = take(&mut i, other).parse().expect("--runs"),
                    "--set-size" => cfg.set_size = take(&mut i, other).parse().expect("--set-size"),
                    "--overlap" => { cfg.overlap = take(&mut i, other).parse().expect("--overlap"); overlap_set = true; }
                    "--out" => cfg.out = PathBuf::from(take(&mut i, other)),
                    _ => { eprintln!("error: unknown argument {other}"); print_usage(&prog); process::exit(1); }
                }
            }
        }
        i += 1;
    }
    // Default overlap to a third of the set size if not specified
    if !overlap_set { cfg.overlap = (cfg.set_size / 3).max(1); }
    cfg
}

// Build a deterministic 32-byte seed from a single byte
fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() { *b = i.wrapping_add(j as u8); }
    s
}

// Generate synthetic, deterministic inputs for every data owner
fn generate_inputs(cfg: &BenchConfig) -> Vec<DataOwnerInput> {
    let overlap = cfg.overlap.min(cfg.set_size);
    let private = cfg.set_size - overlap;
    // Shared elements common to all data owners
    let common: Vec<Vec<u8>> = (0..overlap).map(|i| format!("common_{i}").into_bytes()).collect();
    (0..cfg.n)
        .map(|a| {
            let mut elements = common.clone();
            // Per-DO private elements
            for i in 0..private { elements.push(format!("private_{a}_{i}").into_bytes()); }
            DataOwnerInput {
                elements,
                // Deterministic symmetric key per DO
                k_sym: vec![(a as u8).wrapping_add(7); 32],
            }
        })
        .collect()
}

const CSV_HEADER: &str = "run,n,u,n_bits,hash_k,degree,set_size,overlap,backend,\
n_b_blocks,n_a_blocks,sigma,\
total_s,fhe_setup_s,pack_key_s,sim_enc_s,ot_s,transcipher_s,eval_and_s,cmux_sim_s,\
expected_intersection_size,found_intersection_size,false_positives,false_negatives,match,\
ct_size_bytes,comm_total_bytes";

// Human-readable degree label for the CSV
fn degree_label(cfg: &BenchConfig) -> String {
    match cfg.degree { Some(d) => d.to_string(), None => "secure".to_string() }
}

// Write a successful run as a CSV row
fn write_run(w: &mut impl Write, run: usize, cfg: &BenchConfig, r: &E2eResultAlt) -> std::io::Result<()> {
    // A run "matched" if there are no false positives or false negatives
    let matched = r.false_positives == 0 && r.false_negatives == 0;
    writeln!(
        w,
        "{run},{n},{u},{n_bits},{hash_k},{deg},{set_size},{overlap},bfv+pasta3-alt,\
         {nb},{na},{sigma},\
         {total:.6},{fhe:.6},{pack:.6},{sim:.6},{ot:.6},{trans:.6},{and:.6},{cmux:.6},\
         {exp},{found},{fp},{fn},{matched},{ct},{comm}",
        n = cfg.n,
        u = cfg.u,
        n_bits = cfg.n_bits,
        hash_k = cfg.hash_k,
        deg = degree_label(cfg),
        set_size = cfg.set_size,
        overlap = cfg.overlap,
        nb = r.n_b_blocks,
        na = r.n_a_blocks,
        sigma = r.sigma,
        total = r.total_s,
        fhe = r.fhe_setup_s,
        pack = r.pack_key_s,
        sim = r.sim_enc_s,
        ot = r.ot_s,
        trans = r.transcipher_s,
        and = r.eval_and_s,
        cmux = r.cmux_sim_s,
        exp = r.expected_intersection.len(),
        found = r.found_intersection.len(),
        fp = r.false_positives,
        fn = r.false_negatives,
        matched = matched,
        ct = r.ct_size_bytes,
        comm = r.comm_total_bytes,
    )
}

// Write a failed run as a CSV row filled with FAILED placeholders
fn write_failed(w: &mut impl Write, run: usize, cfg: &BenchConfig) -> std::io::Result<()> {
    writeln!(
        w,
        "{run},{n},{u},{n_bits},{hash_k},{deg},{set_size},{overlap},bfv+pasta3-alt,\
         FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,\
         FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED",
        n = cfg.n,
        u = cfg.u,
        n_bits = cfg.n_bits,
        hash_k = cfg.hash_k,
        deg = degree_label(cfg),
        set_size = cfg.set_size,
        overlap = cfg.overlap,
    )
}

// Compute the mean and standard deviation of a series of f64 values
fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() { return (0.0, 0.0); }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    // Sample variance (Bessel-corrected); 0 when there's only one sample
    let var = if xs.len() > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else { 0.0 };
    (mean, var.sqrt())
}

// Print a human-readable summary of all successful runs
fn print_summary(cfg: &BenchConfig, results: &[E2eResultAlt]) {
    println!();
    println!("=== summary ALG2 ({} run{}) ===", results.len(), if results.len() == 1 { "" } else { "s" });
    println!(
        "n={} u={} n_bits={} hash_k={} degree={:?} set_size={} overlap={}",
        cfg.n, cfg.u, cfg.n_bits, cfg.hash_k, cfg.degree, cfg.set_size, cfg.overlap
    );
    if let Some(r) = results.first() {
        println!("n_b_blocks={} n_a_blocks={}", r.n_b_blocks, r.n_a_blocks);
    }

    // Collect each timing metric across all runs
    let series: [(&str, Vec<f64>); 8] = [
        ("total_s", results.iter().map(|r| r.total_s).collect()),
        ("fhe_setup_s", results.iter().map(|r| r.fhe_setup_s).collect()),
        ("pack_key_s", results.iter().map(|r| r.pack_key_s).collect()),
        ("sim_enc_s", results.iter().map(|r| r.sim_enc_s).collect()),
        ("ot_s", results.iter().map(|r| r.ot_s).collect()),
        ("transcipher_s", results.iter().map(|r| r.transcipher_s).collect()),
        ("eval_and_s", results.iter().map(|r| r.eval_and_s).collect()),
        ("cmux_sim_s", results.iter().map(|r| r.cmux_sim_s).collect()),
    ];
    println!("{:<18} {:>14} {:>14}", "phase", "mean (s)", "stddev (s)");
    for (name, xs) in series {
        let (m, s) = mean_std(&xs);
        println!("{name:<18} {m:>14.6} {s:>14.6}");
    }

    println!();
    println!("sigma:                      {:?}", results.iter().map(|r| r.sigma).collect::<Vec<_>>());
    println!("expected intersection size: {:?}", results.iter().map(|r| r.expected_intersection.len()).collect::<Vec<_>>());
    println!("found intersection size:    {:?}", results.iter().map(|r| r.found_intersection.len()).collect::<Vec<_>>());
    println!("false positives:            {:?}", results.iter().map(|r| r.false_positives).collect::<Vec<_>>());
    println!("false negatives:            {:?}", results.iter().map(|r| r.false_negatives).collect::<Vec<_>>());
    println!();
    println!("CSV written to: {}", cfg.out.display());
}

fn main() -> anyhow::Result<()> {
    let cfg = parse_args();
    // Validate basic invariants
    if cfg.n < 2 { anyhow::bail!("--n must be >= 2"); }
    if cfg.u < 1 { anyhow::bail!("--u must be >= 1"); }
    if cfg.n_bits < 1 { anyhow::bail!("--n-bits must be >= 1"); }
    if cfg.hash_k < 1 { anyhow::bail!("--hash-k must be >= 1"); }

    // Write the header unless appending to an existing file
    let write_header = !cfg.append || !cfg.out.exists();
    let file = if cfg.append {
        OpenOptions::new().create(true).append(true).open(&cfg.out)?
    } else {
        File::create(&cfg.out)?
    };
    let mut w = BufWriter::new(file);
    if write_header { writeln!(w, "{CSV_HEADER}")?; }
    w.flush()?;
    eprintln!("[bench-alt] writing CSV to {}", cfg.out.display());

    let mut results: Vec<E2eResultAlt> = Vec::with_capacity(cfg.runs);
    for run in 0..cfg.runs {
        eprintln!(
            "[bench-alt] run {}/{} (n={} u={} n_bits={} set_size={} degree={:?})",
            run + 1, cfg.runs, cfg.n, cfg.u, cfg.n_bits, cfg.set_size, cfg.degree
        );
        // Fresh inputs and config for each run
        let inputs = generate_inputs(&cfg);
        let e2e_cfg = E2eConfig {
            u: cfg.u,
            n_bits: cfg.n_bits,
            hash_k: cfg.hash_k,
            seeds: (0..cfg.u).map(|i| seed((i as u8).wrapping_add(1))).collect(),
        };
        match run_e2e_pasta_alt(PASTA3, cfg.degree, &e2e_cfg, inputs) {
            Ok(r) => {
                write_run(&mut w, run, &cfg, &r)?;
                w.flush()?;
                eprintln!(
                    "[bench-alt] run {run}: total={:.3}s sigma={} match={} (FP={}, FN={}) n_b={} n_a={}",
                    r.total_s, r.sigma,
                    r.false_positives == 0 && r.false_negatives == 0,
                    r.false_positives, r.false_negatives,
                    r.n_b_blocks, r.n_a_blocks,
                );
                results.push(r);
            }
            Err(e) => {
                // Record the failure in the CSV but continue with later runs
                eprintln!("[bench-alt] run {run} FAILED: {e}");
                write_failed(&mut w, run, &cfg)?;
                w.flush()?;
            }
        }
    }

    w.flush()?;
    if !results.is_empty() { print_summary(&cfg, &results); }
    Ok(())
}
