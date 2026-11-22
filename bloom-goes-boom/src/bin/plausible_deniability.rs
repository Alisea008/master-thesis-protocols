//! Empirical validation of the plausible-deniability claim for U Bloom filters.
//!
//! The data owner builds U Bloom filters BF_0 .. BF_{U-1}, each with a
//! DIFFERENT hash family, all over the same victim set X_2. The STTP picks
//! sigma ~ Uniform{0..U-1} and the attacker only ever observes BF_sigma.
//!
//! Three attacker strategies are compared:
//!   * `single_u`     - craft X_1 for family 0 and hope sigma == 0
//!   * `split_union`  - union of the U per-family attack sets, budget k/U each
//!   * `same_target`  - fix the target t* (chosen on family 0) and build X_1
//!                      from elements y that snipe t* in ALL U families at
//!                      once (joint candidates), so the attack works
//!                      whatever sigma is

use std::time::Instant;

use rand::seq::index::sample;
use rand::thread_rng;
use rand::Rng;
use rayon::prelude::*;
use structopt::StructOpt;

use bloom_goes_boom::{
    count_joint_candidates, joint_candidates, snipe, BloomFilter, BloomFilterParams, Confusion,
};

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

    /// Attacker strategy: `single_u`, `split_union`, `same_target`.
    #[structopt(long, default_value = "single_u")]
    strategy: String,

    #[structopt(short, parse(from_occurrences))]
    verbose: u8,

    /// Only print |joint candidates| for j = 1..=U, then exit.
    #[structopt(long)]
    joint_count: bool,
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

    // 1. Pre-compute attack sets (one per family when needed).
    let start = Instant::now();
    let needed = if strategy == "split_union" { u_count } else { 1 };
    let budget = if strategy == "split_union" { (k / u_count).max(1) } else { k };

    let snipes: Vec<(Vec<usize>, usize)> = families
        .iter()
        .take(needed)
        .map(|fam| snipe(fam, u1.clone(), budget, u2.clone(), x2_size, num_threads, false, verbose))
        .collect();
    let attack_sets: Vec<Vec<usize>> = snipes.iter().map(|(s, _)| s.clone()).collect();
    let targets: Vec<usize> = snipes.iter().map(|(_, t)| *t).collect();

    if verbose >= 1 {
        println!("% Pre-computed {} attack sets in {:?}", snipes.len(), start.elapsed());
        for (u, (s, t)) in snipes.iter().enumerate() {
            println!("%   family {}: target = {}, |AS| = {}", u, t, s.len());
        }
    }

    // The element whose membership the attacker is trying to infer.
    let t_star = targets[0];

    // Joint-candidate mode: how many y snipe t* in ALL of the first j families?
    if opt.joint_count {
        for j in 1..=u_count {
            let n = count_joint_candidates(&families[..j], u1.clone(), &u2, t_star);
            println!("U={} joint_candidates={}", j, n);
        }
        return;
    }

    // 2. Attacker's X_1 depends on the strategy.
    let x1: Vec<usize> = match strategy.as_str() {
        "single_u" => attack_sets[0].clone(),
        "split_union" => {
            let mut v: Vec<usize> = attack_sets.iter().flatten().copied().collect();
            v.sort_unstable();
            v.dedup();
            v
        }
        "same_target" => {
            // Elements y (outside U2) that snipe t* in every family.
            let mut v = joint_candidates(&families, u1.clone(), &u2, t_star);
            let found = v.len();
            v.truncate(k); // respect the budget
            if verbose >= 1 {
                println!("% same_target: {} joint candidates, using {}", found, v.len());
            }
            if v.is_empty() {
                eprintln!(
                    "% WARNING: no joint candidates for U={}, X_1 is empty (advantage will be 0)",
                    u_count
                );
            }
            v
        }
        other => panic!(
            "Unknown strategy: {} (expected single_u|split_union|same_target)",
            other
        ),
    };
    assert!(x1.len() <= k, "X_1 exceeds the budget k");

    if verbose >= 1 {
        println!("% |X_1| = {}", x1.len());
    }

    // 3. Evaluate.
    let start = Instant::now();
    let score: [Confusion; 2] = (0..trials)
        .into_par_iter()
        .fold(
            || [Confusion::new(), Confusion::new()],
            |acc, _| {
                let acc = run_trial(&families, &x1, t_star, u2_size, x2_size, true, acc);
                run_trial(&families, &x1, t_star, u2_size, x2_size, false, acc)
            },
        )
        .reduce(
            || [Confusion::new(), Confusion::new()],
            |a, b| {
                let [a0, a1] = a;
                let [b0, b1] = b;
                [a0.merge(b0), a1.merge(b1)]
            },
        );

    if verbose >= 1 {
        println!("% Ran {} trials in {:?}", trials, start.elapsed());
    }

    let [c0, c1] = score;
    let (adv_s0, _) = c0.advantage();
    let (adv_other, _) = c1.advantage();
    let total = c0.merge(c1);
    let (advantage, se) = total.advantage();
    println!(
        "U={} strategy={} |X1|={} advantage={:.5} se={:.5} adv_sigma0={:.5} adv_sigma_other={:.5} \\\\ % {}",
        u_count, strategy, x1.len(), advantage, se, adv_s0, adv_other, total
    );
}

fn run_trial(
    families: &[BloomFilterParams],
    x1: &[usize],
    t_star: usize,
    u2_size: usize,
    x2_size: usize,
    with_target: bool,
    mut acc: [Confusion; 2],
) -> [Confusion; 2] {
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

    let class = (sigma != 0) as usize;
    acc[class].entries[((intersection as usize) << 1) + has_target as usize] += 1;
    acc
}
