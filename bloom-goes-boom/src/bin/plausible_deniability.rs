//! Empirical validation of the plausible-deniability claim for U Bloom filters.
//!
//! The data owner builds U Bloom filters BF_0 .. BF_{U-1}, each with a
//! DIFFERENT hash family, all over the same victim set X_2. The STTP picks
//! sigma ~ Uniform{0..U-1} and the attacker only ever observes BF_sigma.
//!
//! Three attacker strategies are compared:
//!   * `single_u`     - craft X_1 for family 0 and hope sigma == 0
//!   * `union`        - union of the U per-family attack sets
//!   * `same_target`  - attack the SAME element across all families
//!                     (equivalent to inserting it into one's own set)

use std::time::Instant;

use rand::seq::index::sample;
use rand::thread_rng;
use rand::Rng;
use rayon::prelude::*;
use structopt::StructOpt;

use bloom_goes_boom::{snipe, BloomFilter, BloomFilterParams, Confusion};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "BF-MPSI plausible deniability",
    about = "Empirical evaluation of the U-filter deniability countermeasure"
)]
struct Opt {
    #[structopt(short, long)]
    universe_size: usize,

    #[structopt(long)]
    universe_client_factor: usize,

    #[structopt(short = "s", long)]
    max_set_size: usize,

    #[structopt(long)]
    client_set_size: usize,

    #[structopt(short = "e", long)]
    false_positives: isize,

    #[structopt(short, long, default_value = "100000")]
    trials: usize,

    /// Number of Bloom filters U >= 1 built by the data owner.
    #[structopt(short = "u", long, default_value = "1")]
    num_filters: usize,

    /// Attacker strategy: `single_u`, `union`, `same_target`.
    #[structopt(long, default_value = "single_u")]
    strategy: String,

    #[structopt(short, parse(from_occurrences))]
    verbose: u8,
}

/// Derive U distinct hash families from a base parameter set.
/// Family `u` uses seeds `u * 1_000_003 + i` (1_000_003 is prime).
fn build_families(base: &BloomFilterParams, u_count: usize) -> Vec<BloomFilterParams> {
    (0..u_count)
        .map(|u| {
            let mut p = base.clone();
            p.seeds = (0..base.seeds.len())
                .map(|i| (u as u64) * 1_000_003 + (i as u64))
                .collect();
            p
        })
        .collect()
}

fn main() {
    let opt = Opt::from_args();
    let u_size: usize = 1 << opt.universe_size;
    let k: usize = 1 << opt.max_set_size;
    let u2_size: usize = k * opt.universe_client_factor;
    assert!(u2_size < u_size);
    let x2_size: usize = 1 << opt.client_set_size;
    assert!(x2_size < u2_size);
    assert!(x2_size <= k);
    let e_pow: isize = -opt.false_positives;
    let verbose: u8 = opt.verbose;
    let trials = opt.trials;
    let u_count = opt.num_filters;
    let strategy = opt.strategy.clone();
    assert!(u_count >= 1);

    let base = BloomFilterParams::new(k, e_pow);
    let families = build_families(&base, u_count);
    let u2 = 0..u2_size;
    let u1 = u2_size..u_size;
    let num_threads = num_cpus::get().saturating_sub(2).max(1);

    if verbose >= 1 {
        println!("% Base parameters: {:?}", base);
        println!("% U = {}, strategy = {}", u_count, strategy);
        println!("% Threads: {}", num_threads);
    }

    // 1. Pre-compute U attack sets, one per hash family.
    let start = Instant::now();
    let snipes: Vec<(Vec<usize>, usize)> = families
        .par_iter()
        .map(|fam| snipe(fam, u1.clone(), k, u2.clone(), x2_size, num_threads, false, verbose))
        .collect();
    let attack_sets: Vec<Vec<usize>> = snipes.iter().map(|(s, _)| s.clone()).collect();
    let targets: Vec<usize> = snipes.iter().map(|(_, t)| *t).collect();

    if verbose >= 1 {
        println!("% Pre-computed {} attack sets in {:?}", u_count, start.elapsed());
        for (u, (s, t)) in snipes.iter().enumerate() {
            println!("%   family {}: target = {}, |AS| = {}", u, t, s.len());
        }
    }

    // The element whose membership the attacker is trying to infer.
    let t_star = targets[0];

    // 2. Attacker's X_1 depends on the strategy.
    let x1: Vec<usize> = match strategy.as_str() {
        "single_u" => attack_sets[0].clone(),
        "union" => {
            let mut v: Vec<usize> = attack_sets.iter().flatten().copied().collect();
            v.sort_unstable();
            v.dedup();
            v
        }
        "same_target" => vec![t_star],
        other => panic!("Unknown strategy: {} (expected single_u|union|same_target)", other),
    };

    if verbose >= 1 {
        println!("% |X_1| = {}", x1.len());
    }

    // 3. Evaluate.
    let start = Instant::now();
    let score: Confusion = (0..trials)
        .into_par_iter()
        .fold(
            || Confusion::new(),
            |acc, _| {
                let acc = run_trial(&families, &x1, t_star, u2_size, x2_size, true, acc);
                run_trial(&families, &x1, t_star, u2_size, x2_size, false, acc)
            },
        )
        .reduce(|| Confusion::new(), |a, b| a.merge(b));

    if verbose >= 1 {
        println!("% Ran {} trials in {:?}", trials, start.elapsed());
    }

    let accuracy = (score.entries[3] + score.entries[0]) as f64 / trials as f64;
    let advantage = accuracy - 1.0;
    println!(
        "U={} strategy={} advantage={:.5} \\\\ % {}",
        u_count, strategy, advantage, score
    );
}

fn run_trial(
    families: &[BloomFilterParams],
    x1: &[usize],
    t_star: usize,
    u2_size: usize,
    x2_size: usize,
    with_target: bool,
    mut acc: Confusion,
) -> Confusion {
    let mut rng = thread_rng();

    // Victim set with or without the target.
    let mut victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    while victim_set.contains(&t_star) != with_target {
        victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    }

    // STTP picks sigma uniformly at random.
    let sigma = rng.gen_range(0..families.len());

    // Build ONLY BF_sigma.
    let mut bf = BloomFilter::new(&families[sigma]);
    for e in &victim_set {
        bf.insert(*e);
    }

    // Query BF_sigma with X_1.
    let intersection = x1.iter().any(|e| bf.contains(e));
    let has_target = victim_set.contains(&t_star);

    acc.entries[((intersection as usize) << 1) + has_target as usize] += 1;
    acc
}