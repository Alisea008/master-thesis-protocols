//! Single Bloom filter attack.
//!
//! The simplest form of the attack: run `snipe` once against a single Bloom
//! filter and evaluate the inference advantage.

use std::time::Instant;

use rand::seq::index::sample;
use rand::thread_rng;
use rayon::prelude::*;
use structopt::StructOpt;

use bloom_goes_boom::{snipe, BloomFilter, BloomFilterParams, Confusion};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "attack_single",
    about = "Single Bloom-filter attack"
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

    #[structopt(long)]
    covert: bool,

    #[structopt(short, long, default_value = "100000")]
    trials: usize,

    #[structopt(short, parse(from_occurrences))]
    verbose: u8,
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
    let verbose = opt.verbose;
    let trials = opt.trials;
    let covert = opt.covert;

    let bf_params = BloomFilterParams::new(k, e_pow);
    if verbose >= 1 {
        println!("% BF parameters: {:?}", bf_params);
    }

    let u2 = 0..u2_size;
    let u1 = u2_size..u_size;

    let num_threads = num_cpus::get().saturating_sub(2).max(1);
    if verbose >= 1 {
        println!("% Threads: {}", num_threads);
    }

    let start = Instant::now();
    let (attack_set, target) = snipe(
        &bf_params, u1, k, u2, x2_size, num_threads, covert, verbose,
    );
    if verbose >= 1 {
        println!("% Attack set built in {:?}", start.elapsed());
    }

    let start = Instant::now();
    let score: Confusion = (0..trials)
        .into_par_iter()
        .fold(|| Confusion::new(), |acc, _| {
            let acc = agg_confusion(
                u2_size, x2_size, &bf_params, &attack_set, target, true, acc,
            );
            agg_confusion(
                u2_size, x2_size, &bf_params, &attack_set, target, false, acc,
            )
        })
        .reduce(|| Confusion::new(), |a, b| a.merge(b));
    if verbose >= 1 {
        println!("% {} trials in {:?}", trials, start.elapsed());
    }

    let acc = (score.entries[3] + score.entries[0]) as f64 / trials as f64;
    let advantage = acc - 1.0;
    println!("{:.5} \\\\ % {}", advantage, score);
}

fn agg_confusion(
    u2_size: usize,
    x2_size: usize,
    bf_params: &BloomFilterParams,
    attack_set: &[usize],
    target: usize,
    with_target: bool,
    mut acc: Confusion,
) -> Confusion {
    let mut rng = thread_rng();

    let mut victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    while victim_set.contains(&target) == with_target {
        victim_set = sample(&mut rng, u2_size, x2_size).into_vec();
    }

    let mut bf = BloomFilter::new(bf_params);
    let mut victim_has_target = false;
    for &e in &victim_set {
        bf.insert(e);
        if e == target { victim_has_target = true; }
    }

    let intersection = attack_set.iter().any(|e| bf.contains(e));
    acc.entries[((intersection as usize) << 1) + victim_has_target as usize] += 1;

    bf.clear();
    for &e in attack_set { bf.insert(e); }
    acc.p2_hits += victim_set.iter().filter(|e| bf.contains(e)).count();
    if bf.contains(&target) { acc.p2_hits_target += 1; }

    acc
}