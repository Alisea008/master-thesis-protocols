//! Dual Bloom filter attack.
//!
//! Runs `snipe` against two independently-keyed Bloom filters, looks for a
//! common target (with retries), and evaluates the resulting inference
//! advantage with a shared evaluation set.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::time::Instant;

use rand::seq::index::sample;
use rand::thread_rng;
use rayon::prelude::*;
use structopt::StructOpt;

use bloom_goes_boom::{snipe, BloomFilter, BloomFilterParams, Confusion};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "attack (dual BF)",
    about = "Dual Bloom-filter attack with common-target retry search"
)]
struct Opt {
    /// log2 of the total number of elements in the universe
    #[structopt(short, long)]
    universe_size: usize,

    #[structopt(long)]
    universe_client_factor: usize,

    /// log2 of the max private set size
    #[structopt(short = "s", long)]
    max_set_size: usize,

    /// log2 of the client's input set
    #[structopt(long)]
    client_set_size: usize,

    /// ln of the false positive probability power
    #[structopt(short = "e", long)]
    false_positives: isize,

    /// Whether the attack should be hidden for the client
    #[structopt(long)]
    covert: bool,

    /// Number of trials that experiment will be run with and without the target set
    #[structopt(short, long, default_value = "100000")]
    trials: usize,

    /// Max number of attempts to find a common target between the two Bloom
    /// filters before falling back to their individually-best targets
    #[structopt(long, default_value = "20")]
    max_target_search_attempts: usize,

    /// Verbosity: -v for parameters, -vv for attack search
    #[structopt(short, parse(from_occurrences))]
    verbose: u8,
}

/// Build a second Bloom-filter parameter set with a different hash family,
/// keeping the same number of seeds as the base (works for any e_pow).
fn with_other_family(base: &BloomFilterParams) -> BloomFilterParams {
    let mut p = base.clone();
    p.seeds = p
        .seeds
        .iter()
        .enumerate()
        .map(|(i, _)| 100 + i as u64)
        .collect();
    p
}

// ---------------------------------------------------------------------------
// Common-target search
// ---------------------------------------------------------------------------

/// Find the element shared between the two attack sets that sits, overall,
/// in the best combined position (rank_1 + rank_2 is minimal).
fn find_common_target(
    attack_set_1: &[usize],
    attack_set_2: &[usize],
) -> Option<usize> {
    let rank_1: HashMap<usize, usize> = attack_set_1
        .iter()
        .enumerate()
        .map(|(rank, &element)| (element, rank))
        .collect();

    let mut best: Option<(usize, usize)> = None;

    for (rank_2, &element) in attack_set_2.iter().enumerate() {
        if let Some(&r1) = rank_1.get(&element) {
            let combined_rank = r1 + rank_2;
            if best.map_or(true, |(b, _)| combined_rank < b) {
                best = Some((combined_rank, element));
            }
        }
    }

    best.map(|(_, element)| element)
}

/// Repeatedly runs the attack against both filters looking for a common
/// target. Returns (AS1, AS2, target1, target2, used_fallback).
#[allow(clippy::too_many_arguments)]
fn find_common_target_with_retries(
    bf_params_1: &BloomFilterParams,
    bf_params_2: &BloomFilterParams,
    u1: &Range<usize>,
    u2: &Range<usize>,
    k: usize,
    x2_size: usize,
    num_threads: usize,
    covert: bool,
    verbose: u8,
    max_attempts: usize,
) -> (Vec<usize>, Vec<usize>, usize, usize, bool) {
    let mut last_1 = vec![];
    let mut last_2 = vec![];
    let mut last_t1 = 0;
    let mut last_t2 = 0;

    for attempt in 1..=max_attempts {
        let (as1, t1) = snipe(
            bf_params_1, u1.clone(), k, u2.clone(), x2_size,
            num_threads, covert, verbose,
        );
        let (as2, t2) = snipe(
            bf_params_2, u1.clone(), k, u2.clone(), x2_size,
            num_threads, covert, verbose,
        );

        if let Some(common) = find_common_target(&as1, &as2) {
            if verbose >= 1 {
                println!("% Common target on attempt {}/{}: {}", attempt, max_attempts, common);
            }
            return (as1, as2, common, common, false);
        }

        if verbose >= 1 {
            println!("% Attempt {}/{}: no common target", attempt, max_attempts);
        }

        last_1 = as1;
        last_2 = as2;
        last_t1 = t1;
        last_t2 = t2;
    }

    if verbose >= 1 {
        println!(
            "% No common target after {} attempts - falling back to ({}, {})",
            max_attempts, last_t1, last_t2
        );
    }
    (last_1, last_2, last_t1, last_t2, true)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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
    let verbose = opt.verbose;
    let trials = opt.trials;
    let covert = opt.covert;

    let bf_params = BloomFilterParams::new(k, e_pow);
    if verbose >= 1 {
        println!("% BF parameters: {:?}", bf_params);
    }

    let num_threads = num_cpus::get().saturating_sub(2).max(1);
    if verbose >= 1 {
        println!("% Threads: {}", num_threads);
    }

    let start = Instant::now();
    let u2 = 0..u2_size;
    let u1 = u2_size..u_size;

    let bf_params_1 = bf_params.clone();
    let bf_params_2 = with_other_family(&bf_params);

    let (as1, as2, t1, t2, used_fallback) = find_common_target_with_retries(
        &bf_params_1, &bf_params_2, &u1, &u2, k, x2_size, num_threads, covert, verbose,
        opt.max_target_search_attempts,
    );
    let targets_are_equal = !used_fallback;

    if verbose >= 1 {
        println!(
            "% Targets: {} / {} (equal: {}, fallback: {})",
            t1, t2, targets_are_equal, used_fallback
        );
    }

    let combined_attack_set: Vec<usize> = as1
        .iter()
        .chain(as2.iter())
        .cloned()
        .collect::<HashSet<usize>>()
        .into_iter()
        .collect();

    if verbose >= 1 {
        println!("% Attack sets built in {:?}", start.elapsed());
        println!("% |X_1 combined| = {}", combined_attack_set.len());
    }

    let start = Instant::now();
    let (s1, s2): (Confusion, Confusion) = (0..trials)
        .into_par_iter()
        .fold(
            || (Confusion::new(), Confusion::new()),
            |(a1, a2), _| {
                let (a1n, a2n) = agg_confusion(
                    u2_size, x2_size, &bf_params_1, &bf_params_2,
                    &as1, &as2, t1, t2, true, a1, a2,
                );
                agg_confusion(
                    u2_size, x2_size, &bf_params_1, &bf_params_2,
                    &as1, &as2, t1, t2, false, a1n, a2n,
                )
            },
        )
        .reduce(
            || (Confusion::new(), Confusion::new()),
            |(a1, a2), (b1, b2)| (a1.merge(b1), a2.merge(b2)),
        );

    if verbose >= 1 {
        println!("% {} trials in {:?}", trials, start.elapsed());
    }

    let acc1 = (s1.entries[3] + s1.entries[0]) as f64 / trials as f64;
    println!("BF1 Advantage: {:.5} \\\\ % {}", acc1 - 1.0, s1);

    let acc2 = (s2.entries[3] + s2.entries[0]) as f64 / trials as f64;
    println!("BF2 Advantage: {:.5} \\\\ % {}", acc2 - 1.0, s2);

    if verbose >= 1 {
        println!("Targets equal: {}", targets_are_equal);
        println!("Fallback used: {}", used_fallback);
    }
}

// ---------------------------------------------------------------------------
// Per-trial aggregation
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn agg_confusion(
    u2_size: usize,
    x2_size: usize,
    bf_params_1: &BloomFilterParams,
    bf_params_2: &BloomFilterParams,
    attack_set_1: &[usize],
    attack_set_2: &[usize],
    target1: usize,
    target2: usize,
    with_target: bool,
    mut acc1: Confusion,
    mut acc2: Confusion,
) -> (Confusion, Confusion) {
    let mut rng = thread_rng();

    let mut victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    while victim_set.contains(&target1) != with_target
        || victim_set.contains(&target2) != with_target
    {
        victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    }

    // Probe both filters with the SAME combined dataset (the first attack set,
    // as in the original code; uncomment the extend to use the union).
    let combined_attack_set = attack_set_1.to_vec();
    // let combined_attack_set: Vec<usize> = attack_set_1.iter()
    //     .chain(attack_set_2.iter()).copied().collect();

    let mut bf1 = BloomFilter::new(bf_params_1);
    let mut bf2 = BloomFilter::new(bf_params_2);

    let v_has_t1 = victim_set.contains(&target1);
    let v_has_t2 = victim_set.contains(&target2);

    for &e in &victim_set {
        bf1.insert(e);
        bf2.insert(e);
    }

    let inter1 = combined_attack_set.iter().any(|&e| bf1.contains(&e));
    let inter2 = combined_attack_set.iter().any(|&e| bf2.contains(&e));

    acc1.entries[((inter1 as usize) << 1) + v_has_t1 as usize] += 1;
    acc2.entries[((inter2 as usize) << 1) + v_has_t2 as usize] += 1;

    // P2 hits
    bf1.clear();
    bf2.clear();
    for &e in attack_set_1 { bf1.insert(e); }
    for &e in attack_set_2 { bf2.insert(e); }

    acc1.p2_hits += victim_set.iter().filter(|e| bf1.contains(e)).count();
    if bf1.contains(&target1) { acc1.p2_hits_target += 1; }
    acc2.p2_hits += victim_set.iter().filter(|e| bf2.contains(e)).count();
    if bf2.contains(&target2) { acc2.p2_hits_target += 1; }

    (acc1, acc2)
}