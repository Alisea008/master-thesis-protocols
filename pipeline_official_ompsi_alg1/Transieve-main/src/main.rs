use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use transieve::{
    app,
    cipher::CipherSpec,
    config::{self, SampleConfig, ScalingConfig},
    dataset::{self, DatasetParams},
    pipeline::{run_sample, BaselineBackend, RunOptions},
    scaling::{self, Sweep},
    timing::render_timing_table,
    verify,
};

#[derive(Parser)]
#[command(
    name = "tpsi",
    about = "Threshold PSI over Bloom filters — native Rust pipeline",
    version
)]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate,

    Sample {
        #[arg(long = "app", default_value = "tpsi")]
        application: String,

        #[arg(long)]
        parties: Option<usize>,

        #[arg(long)]
        threshold: Option<usize>,

        #[arg(long)]
        common: Option<usize>,

        #[arg(long)]
        size: Option<usize>,

        #[arg(long)]
        plaintext_only: bool,

        #[arg(long, default_value = "boolean")]
        baseline: String,

        #[arg(long)]
        transcipher: Option<String>,

        #[arg(long)]
        microbench: bool,

        #[arg(long)]
        sample_bits: Option<usize>,
    },

    Scaling {
        #[arg(long = "app", default_value = "tpsi")]
        application: String,

        #[arg(long, default_value = "all")]
        sweep: String,

        #[arg(long, default_value = "boolean")]
        baseline: String,

        #[arg(long)]
        transcipher: Option<String>,

        #[arg(long)]
        plaintext_only: bool,

        #[arg(long)]
        n_values: Option<String>,

        #[arg(long)]
        sample_bits: Option<usize>,

        #[arg(long)]
        tag: Option<String>,
    },

    Verify {
        #[arg(long)]
        name: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::load_runtime_config(&cli.root).context(
        "failed to load runtime config — expected party_sets/party_sets_meta.json under --root",
    )?;
    let party_sets_root = config::party_sets_dir(&cli.root);
    std::fs::create_dir_all(&party_sets_root).ok();

    match cli.cmd {
        Command::Generate => {
            cmd_generate(&cfg.sample_config, &cfg.scaling_config, &party_sets_root)?
        }
        Command::Sample {
            application,
            parties,
            threshold,
            common,
            size,
            plaintext_only,
            baseline,
            transcipher,
            microbench,
            sample_bits,
        } => {
            let app = app::parse(&application)
                .with_context(|| format!("unknown app: {}", application))?;
            let mut sample = cfg.sample_config.clone();
            if let Some(v) = parties {
                sample.num_parties = v;
            }
            if let Some(v) = threshold {
                sample.threshold = v;
            }
            if let Some(v) = common {
                sample.num_common_ips = v;
            }
            if let Some(v) = size {
                sample.party_set_size = v;
            }
            let cipher = match transcipher {
                Some(s) => Some(parse_transcipher(&s)?),
                None => None,
            };
            let baseline_backend = BaselineBackend::parse(&baseline)
                .with_context(|| format!("unknown baseline backend: {}", baseline))?;
            let row = run_sample(
                &sample,
                RunOptions {
                    app: app.as_ref(),
                    party_sets_root: &party_sets_root,
                    sample_bits_cap: sample_bits.unwrap_or(cfg.scaling_config.sample_bits_cap),
                    skip_fhe: plaintext_only,
                    baseline_backend,
                    transcipher: cipher,
                    boolean_microbench: microbench,
                },
            )?;
            render_timing_table("Sample run", std::slice::from_ref(&row));
        }
        Command::Scaling {
            application,
            sweep,
            baseline,
            transcipher,
            plaintext_only,
            n_values,
            sample_bits,
            tag,
        } => {
            let app = app::parse(&application)
                .with_context(|| format!("unknown app: {}", application))?;
            let s = Sweep::parse(&sweep).with_context(|| format!("unknown sweep: {}", sweep))?;
            let parties_override = match n_values {
                Some(list) => Some(
                    list.split(',')
                        .map(|x| x.trim().parse::<usize>())
                        .collect::<Result<Vec<_>, _>>()
                        .with_context(|| format!("invalid --n-values: {}", list))?,
                ),
                None => None,
            };

            let cipher = if plaintext_only {
                None
            } else {
                match transcipher {
                    Some(s) => Some(parse_transcipher(&s)?),
                    None => None,
                }
            };
            let baseline_backend = BaselineBackend::parse(&baseline)
                .with_context(|| format!("unknown baseline backend: {}", baseline))?;
            scaling::run(
                s,
                app.as_ref(),
                &cfg.scaling_config,
                &party_sets_root,
                baseline_backend,
                cipher,
                plaintext_only,
                parties_override,
                sample_bits,
                tag,
            )?;
        }
        Command::Verify { name } => match name {
            Some(n) => verify::verify_single(&party_sets_root, &n)?,
            None => verify::verify_all(&party_sets_root)?,
        },
    }
    Ok(())
}

fn parse_transcipher(raw: &str) -> Result<CipherSpec> {
    let spec = CipherSpec::parse(raw).with_context(|| format!("unknown cipher: {}", raw))?;
    if let Some(hint) = spec.shortint_shadow_hint(raw) {
        eprintln!(
            "[cipher] \"{raw}\" resolved to the Boolean backend (the default); \
             use \"{hint}\" for the shortint variant."
        );
    }
    Ok(spec)
}

fn cmd_generate(
    sample: &SampleConfig,
    scaling_cfg: &ScalingConfig,
    party_sets_root: &std::path::Path,
) -> Result<()> {
    let mut combos: Vec<DatasetParams> = Vec::new();

    combos.push(DatasetParams {
        num_parties: sample.num_parties,
        threshold: sample.threshold,
        num_common_ips: sample.num_common_ips,
        party_set_size: sample.party_set_size,
    });

    let p = &scaling_cfg.scaling_sweeps.parties;
    for n in p.n_values.resolve()? {
        let t = match p.threshold_mode.as_str() {
            "half" => ((n as f64) / 2.0).ceil() as usize,
            _ => n.max(1),
        };
        combos.push(DatasetParams {
            num_parties: n,
            threshold: t,
            num_common_ips: p.num_common_ips,
            party_set_size: p.party_set_size,
        });
    }

    let th = &scaling_cfg.scaling_sweeps.threshold;
    for t in th.t_values.resolve()? {
        if t == 0 || t > th.n_fixed {
            continue;
        }
        combos.push(DatasetParams {
            num_parties: th.n_fixed,
            threshold: t,
            num_common_ips: th.num_common_ips,
            party_set_size: th.party_set_size,
        });
    }

    let ss = &scaling_cfg.scaling_sweeps.set_size;
    for &size in &ss.set_sizes {
        combos.push(DatasetParams {
            num_parties: ss.num_parties,
            threshold: ss.threshold,
            num_common_ips: ss.num_common_ips,
            party_set_size: size,
        });
    }

    let ci = &scaling_cfg.scaling_sweeps.common_ips;
    for &c in &ci.common_values {
        combos.push(DatasetParams {
            num_parties: ci.num_parties,
            threshold: ci.threshold,
            num_common_ips: c,
            party_set_size: ci.party_set_size,
        });
    }

    combos.sort_by_key(|p| p.tag());
    combos.dedup_by_key(|p| p.tag());

    println!(
        "generating / confirming {} dataset(s) under {}",
        combos.len(),
        party_sets_root.display()
    );
    for params in combos {
        let loaded = dataset::load_or_create_party_sets(params, party_sets_root)?;
        println!("  {:7}  {}", loaded.source.as_str(), params.tag(),);
    }
    Ok(())
}
