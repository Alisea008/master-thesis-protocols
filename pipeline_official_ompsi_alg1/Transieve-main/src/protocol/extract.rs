use crate::bloom::BloomFilter;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub fn extract_candidates_from_intersection_bloom(
    intersection_bits: &[bool],
    party_sets: &[Vec<Ipv4Addr>],
    reference_filter: &BloomFilter,
) -> Vec<Ipv4Addr> {
    let mut universe: HashSet<Ipv4Addr> = HashSet::new();
    for party in party_sets {
        universe.extend(party.iter().copied());
    }
    let mut candidates: Vec<Ipv4Addr> = universe
        .into_iter()
        .filter(|ip| reference_filter.contains_in(ip, intersection_bits))
        .collect();
    candidates.sort();
    candidates
}
