//! Uso:
//!   cargo run --release --example bench_e2e -- [OPZIONI]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process;

use psi_pmi::psi::{run_e2e_pasta, DataOwnerInput, E2eConfig, E2eResult};
use transieve::cipher::bfv::pasta::PASTA3;

#[derive(Clone)]
struct BenchConfig {
    n: usize, u: usize, n_bits: usize, hash_k: usize,
    degree: Option<usize>, runs: usize, set_size: usize, overlap: usize,
    out: PathBuf, append: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            n: 2, u: 4, n_bits: 128, hash_k: 3,
            degree: Some(8192), runs: 3, set_size: 10, overlap: 0,
            out: PathBuf::from("bench_results.csv"), append: false,
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {prog} [OPTIONS]\n\
         \n\
         Options:\n\
           --n <N>        Number of data owners (default: 2)\n\
           --u <U>        Hash families / OT choices (default: 4)\n\
           --n-bits <B>   Bloom filter bits (default: 128). Multi-block if > 128\n\
           --hash-k <K>   Hash functions per family (default: 3)\n\
           --degree <D>   FHE degree, 0 = secure/32768 (default: 8192)\n\
           --runs <R>     Number of runs (default: 3)\n\
           --set-size <S> Elements per DO (default: 10)\n\
           --overlap <O>  Shared elements (default: set_size/3)\n\
           --out <PATH>   CSV output (default: bench_results.csv)\n\
           --append       Append to existing CSV\n\
           --help, -h     Show this help\n\
         \n\
                  Multi-block (PASTA3, t=128):\n\
           n_bits is divided in groups of `lanes` blocks (lanes = degree/512):\n\
           degree 8192 -> 16 lane (2048 bit per ciphertext), 16384 -> 32, 32768 -> 64.\n\
           Other then the limits, it is used more ciphertext ( RAM is the limit).\n"
    );
}

fn parse_args() -> BenchConfig {
    let mut cfg = BenchConfig::default();
    let args: Vec<String> = std::env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "bench_e2e".into());
    let mut overlap_set = false;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "--help" | "-h" => { print_usage(&prog); process::exit(0); }
            "--append" => { cfg.append = true; }
            other => {
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
                        cfg.degree = if d == 0 { None } else { Some(d) };
                    }
                    "--runs" => cfg.runs = take(&mut i, other).parse().expect("--runs"),
                    "--set-size" => cfg.set_size = take(&mut i, other).parse().expect("--set-size"),
                    "--overlap" => {
                        cfg.overlap = take(&mut i, other).parse().expect("--overlap");
                        overlap_set = true;
                    }
                    "--out" => cfg.out = PathBuf::from(take(&mut i, other)),
                    _ => {
                        eprintln!("error: unknown argument {other}");
                        print_usage(&prog);
                        process::exit(1);
                    }
                }
            }
        }
        i += 1;
    }
    if !overlap_set { cfg.overlap = (cfg.set_size / 3).max(1); }
    cfg
}

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() { *b = i.wrapping_add(j as u8); }
    s
}

fn generate_inputs(cfg: &BenchConfig) -> Vec<DataOwnerInput> {
    let overlap = cfg.overlap.min(cfg.set_size);
    let private = cfg.set_size - overlap;
    let common: Vec<Vec<u8>> = (0..overlap)
        .map(|i| format!("common_{i}").into_bytes())
        .collect();
    (0..cfg.n).map(|a| {
        let mut elements = common.clone();
        for i in 0..private {
            elements.push(format!("private_{a}_{i}").into_bytes());
        }
        DataOwnerInput { elements, k_sym: vec![(a as u8).wrapping_add(7); 32] }
    }).collect()
}

const CSV_HEADER: &str = "run,n,u,n_bits,num_blocks,hash_k,degree,set_size,overlap,backend,\
total_s,fhe_setup_s,pack_key_s,sim_enc_s,ot_s,transcipher_s,eval_and_s,tee_s,\
ct_size_bytes,m_sigma_len,comm_total_bytes,\
expected_intersection_size,found_intersection_size,false_positives,false_negatives,match";

fn degree_label(cfg: &BenchConfig) -> String {
    match cfg.degree { Some(d) => d.to_string(), None => "secure".to_string() }
}

fn write_run(w: &mut impl Write, run: usize, cfg: &BenchConfig, r: &E2eResult) -> std::io::Result<()> {
    let matched = r.false_positives == 0 && r.false_negatives == 0;
    writeln!(w,
        "{run},{n},{u},{n_bits},{nb},{hash_k},{deg},{set_size},{overlap},bfv+pasta3,\
         {total:.6},{fhe:.6},{pack:.6},{sim:.6},{ot:.6},{trans:.6},{and:.6},{tee:.6},\
         {ct},{msig},{comm},\
         {exp},{found},{fp},{fn},{matched}",
        n = cfg.n, u = cfg.u, n_bits = cfg.n_bits, nb = r.comm.num_blocks,
        hash_k = cfg.hash_k, deg = degree_label(cfg),
        set_size = cfg.set_size, overlap = cfg.overlap,
        total = r.timings.total_s, fhe = r.timings.fhe_setup_s,
        pack = r.timings.pack_key_s, sim = r.timings.sim_enc_s,
        ot = r.timings.ot_s, trans = r.timings.transcipher_s,
        and = r.timings.eval_and_s, tee = r.timings.tee_s,
        ct = r.comm.ct_size_bytes, msig = r.comm.m_sigma_len,
        comm = r.comm.total_bytes,
        exp = r.expected_intersection.len(), found = r.found_intersection.len(),
        fp = r.false_positives, fn = r.false_negatives, matched = matched,
    )
}

fn write_failed(w: &mut impl Write, run: usize, cfg: &BenchConfig) -> std::io::Result<()> {
    writeln!(w,
        "{run},{n},{u},{n_bits},,,{hash_k},{deg},{set_size},{overlap},bfv+pasta3,\
         FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,FAILED,\
         ,,,,,,,,",
        n = cfg.n, u = cfg.u, n_bits = cfg.n_bits, hash_k = cfg.hash_k,
        deg = degree_label(cfg), set_size = cfg.set_size, overlap = cfg.overlap,
    )
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() { return (0.0, 0.0); }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = if xs.len() > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else { 0.0 };
    (mean, var.sqrt())
}

fn print_summary(cfg: &BenchConfig, results: &[E2eResult]) {
    println!();
    println!("=== summary ({} run{}) ===", results.len(),
             if results.len() == 1 { "" } else { "s" });
    println!("n={} u={} n_bits={} ({} blocks) hash_k={} degree={:?} set_size={} overlap={}",
        cfg.n, cfg.u, cfg.n_bits,
        results[0].comm.num_blocks,
        cfg.hash_k, cfg.degree, cfg.set_size, cfg.overlap);
    let series: [(&str, Vec<f64>); 8] = [
        ("total_s", results.iter().map(|r| r.timings.total_s).collect()),
        ("fhe_setup_s", results.iter().map(|r| r.timings.fhe_setup_s).collect()),
        ("pack_key_s", results.iter().map(|r| r.timings.pack_key_s).collect()),
        ("sim_enc_s", results.iter().map(|r| r.timings.sim_enc_s).collect()),
        ("ot_s", results.iter().map(|r| r.timings.ot_s).collect()),
        ("transcipher_s", results.iter().map(|r| r.timings.transcipher_s).collect()),
        ("eval_and_s", results.iter().map(|r| r.timings.eval_and_s).collect()),
        ("tee_s", results.iter().map(|r| r.timings.tee_s).collect()),
    ];
    println!("{:<18} {:>14} {:>14}", "phase", "mean (s)", "stddev (s)");
    for (name, xs) in series {
        let (m, s) = mean_std(&xs);
        println!("{name:<18} {m:>14.6} {s:>14.6}");
    }
    println!();
    println!("expected ∩: {:?}", results.iter().map(|r| r.expected_intersection.len()).collect::<Vec<_>>());
    println!("found ∩:    {:?}", results.iter().map(|r| r.found_intersection.len()).collect::<Vec<_>>());
    println!("FP:         {:?}", results.iter().map(|r| r.false_positives).collect::<Vec<_>>());
    println!("FN:         {:?}", results.iter().map(|r| r.false_negatives).collect::<Vec<_>>());
    println!();
    println!("CSV written to: {}", cfg.out.display());
}

fn main() -> anyhow::Result<()> {
    let cfg = parse_args();
    if cfg.n < 2 { anyhow::bail!("--n must be >= 2"); }
    if cfg.u < 1 { anyhow::bail!("--u must be >= 1"); }

    let num_blocks = (cfg.n_bits + PASTA3.t - 1) / PASTA3.t;
    eprintln!(
        "[bench] n_bits={} -> {} block(s) of {} bits each",
        cfg.n_bits, num_blocks, PASTA3.t
    );
    

    let write_header = !cfg.append || !cfg.out.exists();
    let file = if cfg.append {
        OpenOptions::new().create(true).append(true).open(&cfg.out)?
    } else { File::create(&cfg.out)? };
    let mut w = BufWriter::new(file);
    if write_header { writeln!(w, "{CSV_HEADER}")?; }
    w.flush()?;
    eprintln!("[bench] writing CSV to {}", cfg.out.display());

    let mut results: Vec<E2eResult> = Vec::with_capacity(cfg.runs);
    for run in 0..cfg.runs {
        eprintln!(
            "[bench] run {}/{} (n={} u={} n_bits={} set_size={} degree={:?})",
            run + 1, cfg.runs, cfg.n, cfg.u, cfg.n_bits, cfg.set_size, cfg.degree
        );
        let inputs = generate_inputs(&cfg);
        let e2e_cfg = E2eConfig {
            u: cfg.u, n_bits: cfg.n_bits, hash_k: cfg.hash_k,
            seeds: (0..cfg.u).map(|i| seed((i as u8).wrapping_add(1))).collect(),
        };
        match run_e2e_pasta(PASTA3, cfg.degree, &e2e_cfg, inputs) {
            Ok(r) => {
                write_run(&mut w, run, &cfg, &r)?;
                w.flush()?;
                eprintln!("[bench] run {run}: total={:.3}s match={} (FP={}, FN={})",
                    r.timings.total_s,
                    r.false_positives == 0 && r.false_negatives == 0,
                    r.false_positives, r.false_negatives);
                results.push(r);
            }
            Err(e) => {
                eprintln!("[bench] run {run} FAILED: {e}");
                write_failed(&mut w, run, &cfg)?;
                w.flush()?;
            }
        }
    }
    w.flush()?;
    if !results.is_empty() { print_summary(&cfg, &results); }
    Ok(())
}
