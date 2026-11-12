//! Benchmark CLI per psi-pmi — Algorithm 2 (senza TEE, CMUX simulato).
//!
//! Uso:
//!   cargo run --release --example bench_e2e_alt -- [OPZIONI]
//!
//! Opzioni:
//!   --n <N>           Numero di data owner (default: 2)
//!   --u <U>           Numero di hash family / scelte OT (default: 4)
//!   --n-bits <B>      Dimensione Bloom filter in bit (default: 128)
//!   --hash-k <K>      Funzioni hash per family (default: 3)
//!   --degree <D>      Grado FHE; 0 = secure (default: 8192)
//!   --runs <R>        Numero di run (default: 3)
//!   --set-size <S>    Elementi per DO (default: 6, vedi vincolo sotto)
//!   --overlap <O>     Elementi condivisi (default: set_size/3)
//!   --out <PATH>      File CSV di output (default: bench_alg2.csv)
//!   --append          Appende al CSV esistente
//!   --help, -h        Mostra questo aiuto
//!
//! ⚠️ Vincolo del protocollo alternativo: la matrice di indici di DO_1 deve
//! stare in un lane Pasta:
//!     set_size · hash_k · ceil(log2(n_bits))  ≤  PASTA3.t (=128)
//! Esempi validi:
//!     n_bits=128, hash_k=3 → set_size ≤ 6
//!     n_bits=128, hash_k=2 → set_size ≤ 9
//!     n_bits=64,  hash_k=3 → set_size ≤ 7
//!     n_bits=32,  hash_k=2 → set_size ≤ 12

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use psi_pmi::psi::{run_e2e_pasta_alt, DataOwnerInput, E2eConfig, E2eResultAlt};
use transieve::cipher::bfv::pasta::PASTA3;

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
            set_size: 6,
            overlap: 0,
            out: PathBuf::from("bench_alg2.csv"),
            append: false,
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
           --n-bits <B>   Bloom filter size in bits (default: 128)\n\
           --hash-k <K>   Hash functions per family (default: 3)\n\
           --degree <D>   FHE degree, 0 = secure (default: 8192)\n\
           --runs <R>     Number of runs (default: 3)\n\
           --set-size <S> Elements per DO (default: 6, must fit Pasta lane)\n\
           --overlap <O>  Shared elements (default: set_size/3)\n\
           --out <PATH>   CSV output (default: bench_alg2.csv)\n\
           --append       Append to existing CSV\n\
           --help, -h     Show this help\n\
         \n\
         Constraint (Algorithm 2): set_size * hash_k * ceil(log2(n_bits)) <= 128"
    );
}

fn parse_args() -> BenchConfig {
    let mut cfg = BenchConfig::default();
    let args: Vec<String> = std::env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "bench_e2e_alt".into());
    let mut overlap_set = false;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage(&prog);
                process::exit(0);
            }
            "--append" => {
                cfg.append = true;
            }
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
                    "--set-size" => {
                        cfg.set_size = take(&mut i, other).parse().expect("--set-size")
                    }
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
    if !overlap_set {
        cfg.overlap = (cfg.set_size / 3).max(1);
    }
    cfg
}

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() {
        *b = i.wrapping_add(j as u8);
    }
    s
}

fn generate_inputs(cfg: &BenchConfig) -> Vec<DataOwnerInput> {
    let overlap = cfg.overlap.min(cfg.set_size);
    let private = cfg.set_size - overlap;

    let common: Vec<Vec<u8>> = (0..overlap)
        .map(|i| format!("common_{i}").into_bytes())
        .collect();

    (0..cfg.n)
        .map(|a| {
            let mut elements = common.clone();
            for i in 0..private {
                elements.push(format!("private_{a}_{i}").into_bytes());
            }
            DataOwnerInput {
                elements,
                k_sym: vec![(a as u8).wrapping_add(7); 32],
            }
        })
        .collect()
}

const CSV_HEADER: &str = "run,n,u,n_bits,hash_k,degree,set_size,overlap,backend,\
total_s,sigma,expected_intersection_size,found_intersection_size,\
false_positives,false_negatives,match";

fn degree_label(cfg: &BenchConfig) -> String {
    match cfg.degree {
        Some(d) => d.to_string(),
        None => "secure".to_string(),
    }
}

fn write_run(
    w: &mut impl Write,
    run: usize,
    cfg: &BenchConfig,
    r: &E2eResultAlt,
    total_s: f64,
) -> std::io::Result<()> {
    let matched = r.false_positives == 0 && r.false_negatives == 0;
    writeln!(
        w,
        "{run},{n},{u},{n_bits},{hash_k},{deg},{set_size},{overlap},bfv+pasta3-alt,\
         {total:.6},{sigma},{exp},{found},{fp},{fn},{matched}",
        n = cfg.n,
        u = cfg.u,
        n_bits = cfg.n_bits,
        hash_k = cfg.hash_k,
        deg = degree_label(cfg),
        set_size = cfg.set_size,
        overlap = cfg.overlap,
        total = total_s,
        sigma = r.sigma,
        exp = r.expected_intersection.len(),
        found = r.found_intersection.len(),
        fp = r.false_positives,
        fn = r.false_negatives,
        matched = matched,
    )
}

fn write_failed(w: &mut impl Write, run: usize, cfg: &BenchConfig) -> std::io::Result<()> {
    writeln!(
        w,
        "{run},{n},{u},{n_bits},{hash_k},{deg},{set_size},{overlap},bfv+pasta3-alt,\
         FAILED,,,,,,,,",
        n = cfg.n,
        u = cfg.u,
        n_bits = cfg.n_bits,
        hash_k = cfg.hash_k,
        deg = degree_label(cfg),
        set_size = cfg.set_size,
        overlap = cfg.overlap,
    )
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = if xs.len() > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    (mean, var.sqrt())
}

fn print_summary(cfg: &BenchConfig, results: &[(f64, E2eResultAlt)]) {
    println!();
    println!(
        "=== summary ALG2 ({} run{}) ===",
        results.len(),
        if results.len() == 1 { "" } else { "s" }
    );
    println!(
        "n={} u={} n_bits={} hash_k={} degree={:?} set_size={} overlap={}",
        cfg.n, cfg.u, cfg.n_bits, cfg.hash_k, cfg.degree, cfg.set_size, cfg.overlap
    );

    let totals: Vec<f64> = results.iter().map(|(t, _)| *t).collect();
    let (m, s) = mean_std(&totals);
    println!();
    println!("{:<18} {:>14} {:>14}", "phase", "mean (s)", "stddev (s)");
    println!("{:<18} {:>14.6} {:>14.6}", "total_s", m, s);

    println!();
    println!(
        "sigma:                      {:?}",
        results.iter().map(|(_, r)| r.sigma).collect::<Vec<_>>()
    );
    println!(
        "expected intersection size: {:?}",
        results.iter().map(|(_, r)| r.expected_intersection.len()).collect::<Vec<_>>()
    );
    println!(
        "found intersection size:    {:?}",
        results.iter().map(|(_, r)| r.found_intersection.len()).collect::<Vec<_>>()
    );
    println!(
        "false positives:            {:?}",
        results.iter().map(|(_, r)| r.false_positives).collect::<Vec<_>>()
    );
    println!(
        "false negatives:            {:?}",
        results.iter().map(|(_, r)| r.false_negatives).collect::<Vec<_>>()
    );
    println!();
    println!("CSV written to: {}", cfg.out.display());
}

fn main() -> anyhow::Result<()> {
    let cfg = parse_args();

    if cfg.n < 2 {
        anyhow::bail!("--n must be >= 2");
    }
    if cfg.u < 1 {
        anyhow::bail!("--u must be >= 1");
    }
    if cfg.n_bits > PASTA3.t {
        anyhow::bail!(
            "--n-bits ({}) exceeds PASTA3.t ({})",
            cfg.n_bits,
            PASTA3.t
        );
    }

    // --- Vincolo specifico del protocollo alternativo ---
    let bits_per_idx = (cfg.n_bits as f64).log2().ceil() as usize;
    let per_elem = cfg.hash_k * bits_per_idx;
    let capacity = PASTA3.t / per_elem.max(1);
    if cfg.set_size > capacity {
        anyhow::bail!(
            "Algorithm 2 constraint violated: set_size ({}) * hash_k ({}) * \
             bits_per_idx ({}) = {} > PASTA3.t ({}).\n\
             Maximum set_size with these n_bits/hash_k: {}.\n\
             Options: reduce --set-size, or --hash-k, or --n-bits.",
            cfg.set_size,
            cfg.hash_k,
            bits_per_idx,
            cfg.set_size * per_elem,
            PASTA3.t,
            capacity,
        );
    }

    let write_header = !cfg.append || !cfg.out.exists();
    let file = if cfg.append {
        OpenOptions::new().create(true).append(true).open(&cfg.out)?
    } else {
        File::create(&cfg.out)?
    };
    let mut w = BufWriter::new(file);
    if write_header {
        writeln!(w, "{CSV_HEADER}")?;
    }
    w.flush()?;
    eprintln!("[bench-alt] writing CSV to {}", cfg.out.display());

    let mut results: Vec<(f64, E2eResultAlt)> = Vec::with_capacity(cfg.runs);
    for run in 0..cfg.runs {
        eprintln!(
            "[bench-alt] run {}/{} (n={} u={} n_bits={} set_size={} degree={:?})",
            run + 1,
            cfg.runs,
            cfg.n,
            cfg.u,
            cfg.n_bits,
            cfg.set_size,
            cfg.degree
        );
        let inputs = generate_inputs(&cfg);
        let e2e_cfg = E2eConfig {
            u: cfg.u,
            n_bits: cfg.n_bits,
            hash_k: cfg.hash_k,
            seeds: (0..cfg.u)
                .map(|i| seed((i as u8).wrapping_add(1)))
                .collect(),
        };
        let t0 = Instant::now();
        match run_e2e_pasta_alt(PASTA3, cfg.degree, &e2e_cfg, inputs) {
            Ok(r) => {
                let total_s = t0.elapsed().as_secs_f64();
                write_run(&mut w, run, &cfg, &r, total_s)?;
                w.flush()?;
                eprintln!(
                    "[bench-alt] run {run}: total={:.3}s sigma={} match={} (FP={}, FN={})",
                    total_s,
                    r.sigma,
                    r.false_positives == 0 && r.false_negatives == 0,
                    r.false_positives,
                    r.false_negatives,
                );
                results.push((total_s, r));
            }
            Err(e) => {
                eprintln!("[bench-alt] run {run} FAILED: {e}");
                write_failed(&mut w, run, &cfg)?;
                w.flush()?;
            }
        }
    }

    w.flush()?;
    if !results.is_empty() {
        print_summary(&cfg, &results);
    }
    Ok(())
}