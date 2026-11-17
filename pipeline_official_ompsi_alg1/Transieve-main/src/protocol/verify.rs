use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::dataset::{list_cached_datasets, parse_dataset_tag};

pub fn verify_all(party_sets_root: &Path) -> Result<()> {
    let dirs = list_cached_datasets(party_sets_root)?;
    if dirs.is_empty() {
        println!("no cached datasets under {}", party_sets_root.display());
        return Ok(());
    }
    let mut passed = 0;
    let mut failed = 0;
    println!("verifying {} cached datasets ...", dirs.len());
    for dir in &dirs {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        match verify_single(party_sets_root, name) {
            Ok(()) => {
                passed += 1;
                println!("  PASS  {}", name);
            }
            Err(e) => {
                failed += 1;
                println!("  FAIL  {}  ({})", name, e);
            }
        }
    }
    println!(
        "summary: {} pass, {} fail, {} total",
        passed,
        failed,
        dirs.len()
    );
    Ok(())
}

pub fn verify_single(party_sets_root: &Path, name: &str) -> Result<()> {
    let dir = party_sets_root.join(name);
    let params = parse_dataset_tag(name)?;

    let mut party_sets: Vec<HashSet<Ipv4Addr>> = Vec::with_capacity(params.num_parties);
    for i in 1..=params.num_parties {
        let path = dir.join(format!("party_{}.txt", i));
        let text = fs::read_to_string(&path)?;
        let mut set = HashSet::new();
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let ip: Ipv4Addr = t.parse()?;
            if !set.insert(ip) {
                anyhow::bail!("party {} has duplicate IP {}", i, ip);
            }
        }
        if set.len() != params.party_set_size {
            anyhow::bail!(
                "party {} size = {}, expected {}",
                i,
                set.len(),
                params.party_set_size,
            );
        }
        party_sets.push(set);
    }

    let mut counts: std::collections::HashMap<Ipv4Addr, usize> = std::collections::HashMap::new();
    for s in &party_sets {
        for ip in s {
            *counts.entry(*ip).or_insert(0) += 1;
        }
    }
    let above_threshold = counts.values().filter(|&&c| c >= params.threshold).count();
    if above_threshold < params.num_common_ips {
        anyhow::bail!(
            "only {} IPs reach threshold, expected >= {} common IPs",
            above_threshold,
            params.num_common_ips,
        );
    }
    Ok(())
}
