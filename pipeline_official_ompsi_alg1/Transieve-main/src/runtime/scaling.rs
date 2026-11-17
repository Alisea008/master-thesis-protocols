use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::app::Application;
use crate::cipher::CipherSpec;
use crate::config::{SampleConfig, ScalingConfig};
use crate::pipeline::{run_sample, BaselineBackend, RunOptions};
use crate::timing::RunTimings;

pub enum Sweep {
    All,
    Parties,
    Threshold,
    SetSize,
    CommonIps,
}

impl Sweep {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "all" => Sweep::All,
            "parties" => Sweep::Parties,
            "threshold" => Sweep::Threshold,
            "set_size" | "set-size" => Sweep::SetSize,
            "common_ips" | "common-ips" => Sweep::CommonIps,
            _ => return None,
        })
    }
}

struct SweepCtx<'a> {
    app: &'a dyn Application,
    cfg: &'a ScalingConfig,
    party_sets_root: &'a Path,
    outdir: &'a Path,
    baseline_backend: BaselineBackend,
    transcipher: Option<CipherSpec>,
    plaintext_only: bool,

    parties_override: Option<Vec<usize>>,

    sample_bits_override: Option<usize>,

    tag: Option<String>,
}

impl<'a> SweepCtx<'a> {
    fn run_options(&self) -> RunOptions<'a> {
        RunOptions {
            app: self.app,
            party_sets_root: self.party_sets_root,
            sample_bits_cap: self
                .sample_bits_override
                .unwrap_or(self.cfg.sample_bits_cap),
            skip_fhe: self.plaintext_only,

            baseline_backend: self.baseline_backend,
            transcipher: self.transcipher,

            boolean_microbench: false,
        }
    }

    fn suffix(&self) -> String {
        let base = match self.transcipher {
            None => format!("_base-{}", self.baseline_backend.as_str()),
            Some(c) => format!("_tc-{}", c.slug()),
        };
        match &self.tag {
            Some(t) if !t.is_empty() => format!("{base}_{t}"),
            _ => base,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    sweep: Sweep,
    app: &dyn Application,
    cfg: &ScalingConfig,
    party_sets_root: &Path,
    baseline_backend: BaselineBackend,
    transcipher: Option<CipherSpec>,
    plaintext_only: bool,
    parties_override: Option<Vec<usize>>,
    sample_bits_override: Option<usize>,
    tag: Option<String>,
) -> Result<()> {
    fs::create_dir_all(&cfg.output_dir)?;
    let outdir = Path::new(&cfg.output_dir);
    let ctx = SweepCtx {
        app,
        cfg,
        party_sets_root,
        outdir,
        baseline_backend,
        transcipher,
        plaintext_only,
        parties_override,
        sample_bits_override,
        tag,
    };

    match sweep {
        Sweep::All => {
            run_parties(&ctx)?;
            run_threshold(&ctx)?;
            run_set_size(&ctx)?;
            run_common_ips(&ctx)?;
        }
        Sweep::Parties => run_parties(&ctx)?,
        Sweep::Threshold => run_threshold(&ctx)?,
        Sweep::SetSize => run_set_size(&ctx)?,
        Sweep::CommonIps => run_common_ips(&ctx)?,
    }
    Ok(())
}

fn run_parties(ctx: &SweepCtx<'_>) -> Result<()> {
    let s = &ctx.cfg.scaling_sweeps.parties;
    let n_values = match &ctx.parties_override {
        Some(v) => v.clone(),
        None => s.n_values.resolve()?,
    };
    if ctx.parties_override.is_some() {
        println!("[SWEEP] parties: using --n-values override {:?}", n_values);
    }
    let csv = csv_name(ctx, "parties");
    init_csv(ctx.outdir, &csv)?;

    for n in n_values {
        let t = match s.threshold_mode.as_str() {
            "half" => ((n as f64) / 2.0).ceil() as usize,
            _ => n.max(1),
        };
        let sample = SampleConfig {
            num_parties: n,
            threshold: t,
            num_common_ips: s.num_common_ips,
            party_set_size: s.party_set_size,
        };
        println!("\n[SWEEP parties] N={} T={}", n, t);
        let row = run_sample(&sample, ctx.run_options())?;
        append_csv(ctx.outdir, &csv, &row)?;
    }

    Ok(())
}

fn run_threshold(ctx: &SweepCtx<'_>) -> Result<()> {
    let s = &ctx.cfg.scaling_sweeps.threshold;
    let csv = csv_name(ctx, "threshold");
    init_csv(ctx.outdir, &csv)?;
    let t_values = s.t_values.resolve()?;

    for t in t_values {
        if t == 0 || t > s.n_fixed {
            continue;
        }
        let sample = SampleConfig {
            num_parties: s.n_fixed,
            threshold: t,
            num_common_ips: s.num_common_ips,
            party_set_size: s.party_set_size,
        };
        println!("\n[SWEEP threshold] N={} T={}", s.n_fixed, t);
        let row = run_sample(&sample, ctx.run_options())?;
        append_csv(ctx.outdir, &csv, &row)?;
    }

    Ok(())
}

fn run_set_size(ctx: &SweepCtx<'_>) -> Result<()> {
    let s = &ctx.cfg.scaling_sweeps.set_size;
    let csv = csv_name(ctx, "set_size");
    init_csv(ctx.outdir, &csv)?;

    for &size in &s.set_sizes {
        let sample = SampleConfig {
            num_parties: s.num_parties,
            threshold: s.threshold,
            num_common_ips: s.num_common_ips,
            party_set_size: size,
        };
        println!("\n[SWEEP set_size] S={}", size);
        let row = run_sample(&sample, ctx.run_options())?;
        append_csv(ctx.outdir, &csv, &row)?;
    }

    Ok(())
}

fn run_common_ips(ctx: &SweepCtx<'_>) -> Result<()> {
    let s = &ctx.cfg.scaling_sweeps.common_ips;
    let csv = csv_name(ctx, "common_ips");
    init_csv(ctx.outdir, &csv)?;

    for &c in &s.common_values {
        let sample = SampleConfig {
            num_parties: s.num_parties,
            threshold: s.threshold,
            num_common_ips: c,
            party_set_size: s.party_set_size,
        };
        println!("\n[SWEEP common_ips] C={}", c);
        let row = run_sample(&sample, ctx.run_options())?;
        append_csv(ctx.outdir, &csv, &row)?;
    }

    Ok(())
}

fn csv_name(ctx: &SweepCtx<'_>, sweep_name: &str) -> String {
    format!("sweep_{}{}.csv", sweep_name, ctx.suffix())
}

fn csv_header() -> &'static str {
    concat!(
        "run_tag,dataset_source,num_parties,threshold,num_common_ips,party_set_size,",
        "num_bloom_bits,num_hash_funcs,",
        "circuit_num_terms,circuit_and_per_bit,circuit_or_per_bit,",
        "load_dataset_s,build_bloom_filters_s,circuit_build_s,plaintext_eval_s,plaintext_extract_s,",
        "fhe_keygen_s,fhe_encrypt_s,fhe_evaluate_s,fhe_decrypt_s,fhe_extract_s,fhe_total_s,",
        "fhe_bits_evaluated,fhe_eval_full_est_s,encrypted_matches_plaintext,num_recovered,num_exact,",
        "transcipher_name,transcipher_backend,transcipher_sym_encrypt_s,transcipher_fhe_keygen_s,",
        "transcipher_key_encrypt_s,transcipher_init_s,transcipher_per_bit_total_s,",
        "transcipher_bits_evaluated,transcipher_throughput_bps,",
        "transcipher_homomorphic_decrypt_s,transcipher_total_s,transcipher_matches_plaintext,",
        "transcipher_pbs_per_output_bit,transcipher_multiplicative_depth,transcipher_fixed_init_pbs,",
        "transcipher_sym_ciphertext_bits,",
        "payload_plain_bytes,payload_fhe_direct_bytes,payload_transcipher_bytes,",
        "expansion_fhe_direct,expansion_transcipher,bandwidth_savings_ratio,",
        "transcipher_ms_per_bit,transcipher_full_payload_est_s,",
        "transcipher_parties_transciphered,transcipher_sop_evaluate_s,transcipher_sop_decrypt_s,",
        "transcipher_sop_total_s,transcipher_sop_matches_plaintext,transcipher_num_recovered,",
        "candidate_pool_size,plaintext_recovered,false_positives,fpr_observed,fhe_backend,peak_rss_bytes\n",
    )
}

fn csv_row(r: &RunTimings) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        r.run_tag,
        r.dataset_source,
        r.num_parties,
        r.threshold,
        r.num_common_ips,
        r.party_set_size,
        r.num_bloom_bits,
        r.num_hash_funcs,
        csv_u(r.circuit_num_terms),
        csv_u(r.circuit_and_per_bit),
        csv_u(r.circuit_or_per_bit),
        csv_f(r.load_dataset_s),
        csv_f(r.build_bloom_filters_s),
        csv_f(r.circuit_build_s),
        csv_f(r.plaintext_eval_s),
        csv_f(r.plaintext_extract_s),
        csv_f(r.fhe_keygen_s),
        csv_f(r.fhe_encrypt_s),
        csv_f(r.fhe_evaluate_s),
        csv_f(r.fhe_decrypt_s),
        csv_f(r.fhe_extract_s),
        csv_f(r.fhe_total_s),
        csv_u(r.fhe_bits_evaluated),
        csv_f(r.fhe_eval_full_est_s),
        csv_b(r.encrypted_matches_plaintext),
        csv_u(r.num_recovered),
        csv_u(r.num_exact),
        r.transcipher_name.clone().unwrap_or_default(),
        r.transcipher_backend.clone().unwrap_or_default(),
        csv_f(r.transcipher_sym_encrypt_s),
        csv_f(r.transcipher_fhe_keygen_s),
        csv_f(r.transcipher_key_encrypt_s),
        csv_f(r.transcipher_init_s),
        csv_f(r.transcipher_per_bit_total_s),
        csv_u(r.transcipher_bits_evaluated),
        csv_f(r.transcipher_throughput_bps),
        csv_f(r.transcipher_homomorphic_decrypt_s),
        csv_f(r.transcipher_total_s),
        csv_b(r.transcipher_matches_plaintext),
        csv_f(r.transcipher_pbs_per_output_bit),
        csv_u(r.transcipher_multiplicative_depth),
        csv_u(r.transcipher_fixed_init_pbs),
        csv_u(r.transcipher_sym_ciphertext_bits),
        csv_u(r.payload_plain_bytes),
        csv_u(r.payload_fhe_direct_bytes),
        csv_u(r.payload_transcipher_bytes),
        csv_f(r.expansion_fhe_direct),
        csv_f(r.expansion_transcipher),
        csv_f(r.bandwidth_savings_ratio),
        csv_f(r.transcipher_ms_per_bit),
        csv_f(r.transcipher_full_payload_est_s),
        csv_u(r.transcipher_parties_transciphered),
        csv_f(r.transcipher_sop_evaluate_s),
        csv_f(r.transcipher_sop_decrypt_s),
        csv_f(r.transcipher_sop_total_s),
        csv_b(r.transcipher_sop_matches_plaintext),
        csv_u(r.transcipher_num_recovered),
        csv_u(r.candidate_pool_size),
        csv_u(r.plaintext_recovered),
        csv_u(r.false_positives),
        csv_f(r.fpr_observed),
        r.fhe_backend.clone().unwrap_or_default(),
        csv_u(r.peak_rss_bytes),
    )
}

fn init_csv(outdir: &Path, name: &str) -> Result<()> {
    let path = outdir.join(name);
    fs::write(&path, csv_header())?;
    println!("[CSV] initialised {} (header only)", path.display());
    Ok(())
}

fn append_csv(outdir: &Path, name: &str, r: &RunTimings) -> Result<()> {
    let path = outdir.join(name);
    let mut f = fs::OpenOptions::new().append(true).open(&path)?;
    f.write_all(csv_row(r).as_bytes())?;
    f.flush()?;
    println!("[CSV] appended row -> {}", path.display());
    Ok(())
}

fn csv_f(v: Option<f64>) -> String {
    v.map(|x| format!("{:.6}", x)).unwrap_or_default()
}
fn csv_u(v: Option<usize>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}
fn csv_b(v: Option<bool>) -> String {
    v.map(|x| if x { "true" } else { "false" }.to_string())
        .unwrap_or_default()
}
