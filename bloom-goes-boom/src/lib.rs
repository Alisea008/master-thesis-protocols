//! Shared types and utilities for the Bloom-filter PSI attack.

pub mod combinations;

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::ops::Range;
use std::thread;

use bytevec::ByteEncodable;
use cached::proc_macro::cached;
use num_bigint::BigUint;
use rand::seq::SliceRandom;
use rand::thread_rng;
use topk::FilteredSpaceSaving;
use xxh3::hash64_with_seed;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn hash_element(element: &usize, seed: u64) -> usize {
    let element_bytes = (*element as u64).encode::<u64>().unwrap();
    hash64_with_seed(&element_bytes, seed) as usize
}

// ---------------------------------------------------------------------------
// Bloom filter parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BloomFilterParams {
    pub bin_count: usize,
    pub seeds: Vec<u64>,
}

impl BloomFilterParams {
    pub fn new(element_count: usize, e_pow: isize) -> Self {
        let hash_count = (-e_pow) as usize;

        let funny_looking_thing = 2f64.powf(e_pow as f64 / hash_count as f64);
        let bin_count = (-(hash_count as f64) * (element_count as f64 + 0.5)
            / (1. - funny_looking_thing).ln())
        .ceil()
            + 1.;
        let seeds: Vec<u64> = (0..hash_count).map(|x| x as u64).collect();
        BloomFilterParams {
            bin_count: bin_count as usize,
            seeds,
        }
    }
}

// ---------------------------------------------------------------------------
// Bloom filter
// ---------------------------------------------------------------------------

pub struct BloomFilter {
    pub bins: Vec<bool>,
    pub seeds: Vec<u64>,
}

impl BloomFilter {
    pub fn new(params: &BloomFilterParams) -> Self {
        BloomFilter {
            bins: vec![false; params.bin_count],
            seeds: params.seeds.clone(),
        }
    }

    pub fn insert(&mut self, element: usize) {
        let bin_count = self.bins.len();
        for seed in self.seeds.iter() {
            self.bins[hash_element(&element, *seed) % bin_count] = true;
        }
    }

    pub fn clear(&mut self) {
        self.bins = vec![false; self.bins.len()];
    }

    pub fn contains(&self, element: &usize) -> bool {
        let bin_count = self.bins.len();
        for seed in self.seeds.iter() {
            if !self.bins[hash_element(element, *seed) % bin_count] {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Confusion matrix
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Confusion {
    /// [tn, fn, fp, tp]
    pub entries: [usize; 4],
    pub p2_hits: usize,
    pub p2_hits_target: usize,
}

impl Confusion {
    /// (advantage = TPR - FPR, standard error)
    pub fn advantage(&self) -> (f64, f64) {
        let [tn, fnn, fp, tp] = self.entries.map(|x| x as f64);
        let (p, n) = (tp + fnn, fp + tn);
        if p == 0.0 || n == 0.0 {
            return (f64::NAN, f64::NAN);
        }
        let (tpr, fpr) = (tp / p, fp / n);
        let se = (tpr * (1.0 - tpr) / p + fpr * (1.0 - fpr) / n).sqrt();
        (tpr - fpr, se)
    }
    pub fn new() -> Self {
        Confusion {
            entries: [0; 4],
            p2_hits: 0,
            p2_hits_target: 0,
        }
    }

    pub fn merge(self, other: Confusion) -> Confusion {
        Confusion {
            entries: [
                self.entries[0] + other.entries[0],
                self.entries[1] + other.entries[1],
                self.entries[2] + other.entries[2],
                self.entries[3] + other.entries[3],
            ],
            p2_hits: self.p2_hits + other.p2_hits,
            p2_hits_target: self.p2_hits_target + other.p2_hits_target,
        }
    }
}

impl Display for Confusion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}, {}, {}, {}, {}] = [tp, fn, tn, fp, p2_hits_target]",
            self.entries[3],
            self.entries[1],
            self.entries[0],
            self.entries[2],
            self.p2_hits_target
        )
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

pub fn hash_hits(bf_params: &BloomFilterParams, set: &Range<usize>) -> Vec<Vec<usize>> {
    let mut result: Vec<Vec<usize>> = (0..bf_params.bin_count).map(|_| vec![]).collect();

    for el in set.clone() {
        for seed in bf_params.seeds.iter() {
            result[hash_element(&el, *seed) % bf_params.bin_count].push(el);
        }
    }

    result
}

fn find_non_unique(bins: &[BTreeSet<usize>]) -> Option<usize> {
    let mut seen_elements = BTreeSet::new();

    for bin in bins {
        for element in bin {
            if seen_elements.contains(element) {
                return Some(*element);
            }
            seen_elements.insert(*element);
        }
    }

    None
}

#[cached]
fn compute_exact_score(
    universe_size: usize,
    page_size: usize,
    bins: Vec<BTreeSet<usize>>,
) -> BigUint {
    if universe_size == 0 {
        return BigUint::ZERO;
    }

    for bin in &bins {
        if bin.is_empty() {
            return BigUint::ZERO;
        }
    }

    let split_element = find_non_unique(&bins);

    match split_element {
        Some(element) => {
            let mut bins_remove_element = vec![];
            let mut bins_pick_element = vec![];
            for bin in bins {
                let mut new_bin = bin.clone();
                new_bin.remove(&element);
                bins_remove_element.push(new_bin);

                if !bin.contains(&element) {
                    bins_pick_element.push(bin);
                }
            }

            let score_remove =
                compute_exact_score(universe_size - 1, page_size, bins_remove_element);
            let score_pick =
                compute_exact_score(universe_size - 1, page_size - 1, bins_pick_element);

            score_remove + score_pick
        }
        None => {
            let bin_sizes: Vec<usize> = bins.iter().map(|bin| bin.len()).collect();
            combinations::compute_unique(&bin_sizes, page_size, universe_size)
        }
    }
}

fn compute_approx_score_log2(
    universe_size: usize,
    page_size: usize,
    bins: Vec<BTreeSet<usize>>,
) -> u64 {
    compute_exact_score(universe_size, page_size, bins).bits()
}

// ---------------------------------------------------------------------------
// Attack
// ---------------------------------------------------------------------------

fn search_best_candidates(
    bf_params: &BloomFilterParams,
    mut all_candidates: Vec<usize>,
    x1_size: usize,
    u2_len: usize,
    x2_size: usize,
    hh: &Vec<Vec<usize>>,
    thread_count: usize,
) -> Vec<usize> {
    // Shuffle so that candidates with tied scores are broken differently
    // between calls.
    all_candidates.shuffle(&mut thread_rng());

    let mut topk = FilteredSpaceSaving::new(x1_size);
    let chunk_size = (all_candidates.len() + thread_count - 1) / thread_count;

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(thread_count);

        let hh_ref = &hh;
        for candidate_chunk in all_candidates.chunks(chunk_size) {
            handles.push(s.spawn(move || {
                let mut topk: FilteredSpaceSaving<usize> = FilteredSpaceSaving::new(x1_size);
                for &candidate in candidate_chunk {
                    let candidate_indices: BTreeSet<usize> = BTreeSet::from_iter(
                        bf_params
                            .seeds
                            .iter()
                            .map(|&seed| hash_element(&candidate, seed) % bf_params.bin_count),
                    );
                    let bins: Vec<BTreeSet<usize>> = candidate_indices
                        .iter()
                        .map(|&index| BTreeSet::from_iter(hh_ref[index].iter().copied()))
                        .collect();
                    let score = compute_approx_score_log2(u2_len, x2_size, bins);
                    topk.insert(candidate, score);
                }
                topk
            }));
        }

        for handle in handles {
            let sub_topk = handle.join().expect("Failed to join thread");
            topk.merge(&sub_topk).expect("Merging errored");
        }
    });
    topk.iter().map(|(candidate, _)| *candidate).collect()
}

fn find_all_candidates(
    bf_params: &BloomFilterParams,
    u1: Range<usize>,
    thread_count: usize,
    covert: bool,
    hh: &Vec<Vec<usize>>,
    avoid_bin: usize,
    bins_target: &BTreeSet<usize>,
) -> Vec<usize> {
    let mut all_candidates = vec![];
    let chunk_size = u1.len() / thread_count;

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(thread_count);

        let hh_ref = &hh;
        let bins_target_ref = &bins_target;

        let (u1_start, u1_end) = (u1.start, u1.end);
        for i in 0..thread_count {
            handles.push(s.spawn(move || {
                let mut candidates = vec![];
                let start = u1_start + i * chunk_size;
                let end = if i + 1 == thread_count { u1_end } else { start + chunk_size };
                for y in start..end {
                    let sniped_target;
                    if covert {
                        sniped_target =
                            potential_candidate(bf_params, hh_ref, bins_target_ref, &y, avoid_bin);
                    } else {
                        sniped_target =
                            potential_candidate(bf_params, hh_ref, bins_target_ref, &y, usize::MAX);
                    }
                    if sniped_target {
                        candidates.push(y);
                    }
                }
                candidates
            }));
        }

        for handle in handles {
            let candidates = handle.join().expect("Failed to join thread");
            all_candidates.extend(candidates);
        }
    });
    all_candidates
}

pub fn potential_candidate(
    bf_params: &BloomFilterParams,
    hh_ref: &Vec<Vec<usize>>,
    bins_target_ref: &BTreeSet<usize>,
    y: &usize,
    avoid_bin: usize,
) -> bool {
    let mut sniped_target = false;

    for seed in bf_params.seeds.iter() {
        let bloomf_index = hash_element(y, *seed) % bf_params.bin_count;

        if hh_ref[bloomf_index].is_empty() || bloomf_index == avoid_bin {
            return false;
        } else if hh_ref[bloomf_index].len() == 1 && bins_target_ref.contains(&bloomf_index) {
            sniped_target = true;
        }
    }
    sniped_target
}

fn find_target(
    bf_params: &BloomFilterParams,
    u2: &Range<usize>,
    hash_hits: &Vec<Vec<usize>>,
) -> (usize, usize) {
    let mut best_score = usize::MAX;
    let mut best_x: usize = usize::MAX;

    for x in u2.clone() {
        let score: usize = bf_params
            .seeds
            .iter()
            .map(|seed| hash_hits[hash_element(&x, *seed) % bf_params.bin_count].len())
            .sum();

        if score < best_score {
            best_score = score;
            best_x = x;
        }
    }

    let avoid_bin = bf_params
        .seeds
        .iter()
        .map(|seed| {
            let index = hash_element(&best_x, *seed) % bf_params.bin_count;
            (index, hash_hits[index].len())
        })
        .min_by_key(|&(_, len)| if len == 1 { usize::MAX } else { len })
        .map(|(index, _)| index);

    (best_x, avoid_bin.unwrap())
}

/// Run the snipe attack: return an attack set of size at most `x1_size`
/// optimised against a Bloom filter built over `u2` with parameters `bf_params`,
/// and the target element it aims for.
pub fn snipe(
    bf_params: &BloomFilterParams,
    u1: Range<usize>,
    x1_size: usize,
    u2: Range<usize>,
    x2_size: usize,
    thread_count: usize,
    covert: bool,
    verbose: u8,
) -> (Vec<usize>, usize) {
    let hh = hash_hits(bf_params, &u2);

    let (target, avoid_bin) = find_target(bf_params, &u2, &hh);
    if verbose >= 1 {
        println!("% Targetting element {:?}", target);
    }

    let bins_target: Vec<usize> = bf_params
        .seeds
        .iter()
        .map(|seed| hash_element(&target, *seed) % bf_params.bin_count)
        .collect();
    let bins_target: BTreeSet<usize> = BTreeSet::from_iter(bins_target);

    let u2_len = u2.len();

    let all_candidates: Vec<usize> =
        find_all_candidates(bf_params, u1, thread_count, covert, &hh, avoid_bin, &bins_target);

    if verbose >= 1 {
        println!("% Found {:?} candidates", all_candidates.len());
    }

    if all_candidates.len() <= x1_size {
        return (all_candidates, target);
    }

    let x1 = search_best_candidates(
        bf_params,
        all_candidates,
        x1_size,
        u2_len,
        x2_size,
        &hh,
        thread_count,
    );
    (x1, target)
}

use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// Number of y in `u1` that snipe `target` simultaneously in ALL given families.
pub fn count_joint_candidates(
    fams: &[BloomFilterParams],
    u1: Range<usize>,
    u2: &Range<usize>,
    target: usize,
) -> usize {
    let ctx: Vec<(&BloomFilterParams, Vec<Vec<usize>>, BTreeSet<usize>)> = fams
        .iter()
        .map(|p| {
            let hh = hash_hits(p, u2);
            let bt: BTreeSet<usize> = p
                .seeds
                .iter()
                .map(|s| hash_element(&target, *s) % p.bin_count)
                .collect();
            (p, hh, bt)
        })
        .collect();

    u1.into_par_iter()
        .filter(|y| ctx.iter().all(|(p, hh, bt)| potential_candidate(p, hh, bt, y, usize::MAX)))
        .count()
}