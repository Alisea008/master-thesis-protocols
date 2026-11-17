use anyhow::{bail, Context, Result};
use rand::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct DatasetParams {
    pub num_parties: usize,
    pub threshold: usize,
    pub num_common_ips: usize,
    pub party_set_size: usize,
}

impl DatasetParams {
    pub fn tag(&self) -> String {
        format!(
            "n{}_t{}_c{}_s{}",
            self.num_parties, self.threshold, self.num_common_ips, self.party_set_size
        )
    }

    pub fn dir(&self, party_sets_root: &Path) -> PathBuf {
        party_sets_root.join(self.tag())
    }
}

pub struct LoadedDataset {
    pub sets: Vec<Vec<Ipv4Addr>>,
    pub source: DatasetSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetSource {
    Loaded,
    Created,
}

impl DatasetSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatasetSource::Loaded => "loaded",
            DatasetSource::Created => "created",
        }
    }
}

pub fn load_or_create_party_sets(
    params: DatasetParams,
    party_sets_root: &Path,
) -> Result<LoadedDataset> {
    let dir = params.dir(party_sets_root);
    if dir.is_dir() && has_all_party_files(&dir, params.num_parties) {
        let sets = load_party_sets(&dir, params.num_parties)?;
        return Ok(LoadedDataset {
            sets,
            source: DatasetSource::Loaded,
        });
    }
    let sets = generate_party_sets(params);
    write_party_sets(&dir, &sets)?;
    Ok(LoadedDataset {
        sets,
        source: DatasetSource::Created,
    })
}

fn has_all_party_files(dir: &Path, n: usize) -> bool {
    (1..=n).all(|i| dir.join(format!("party_{}.txt", i)).is_file())
}

fn load_party_sets(dir: &Path, n: usize) -> Result<Vec<Vec<Ipv4Addr>>> {
    let mut sets = Vec::with_capacity(n);
    for i in 1..=n {
        let path = dir.join(format!("party_{}.txt", i));
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut ips = Vec::new();
        for line in contents.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            ips.push(
                t.parse::<Ipv4Addr>()
                    .with_context(|| format!("invalid IPv4 in {}: {}", path.display(), t))?,
            );
        }
        sets.push(ips);
    }
    Ok(sets)
}

pub fn generate_party_sets(p: DatasetParams) -> Vec<Vec<Ipv4Addr>> {
    let mut rng = StdRng::seed_from_u64(0xBEEF_0042); // deterministic datasets

    let mut universe: HashSet<Ipv4Addr> = HashSet::new();
    let mut common_assignments: Vec<(Ipv4Addr, Vec<usize>)> = Vec::with_capacity(p.num_common_ips);

    while common_assignments.len() < p.num_common_ips {
        let ip = random_ipv4(&mut rng);
        if !universe.insert(ip) {
            continue;
        }
        let assignees = sample_indices(&mut rng, p.num_parties, p.threshold);
        common_assignments.push((ip, assignees));
    }

    let mut party_sets: Vec<HashSet<Ipv4Addr>> =
        (0..p.num_parties).map(|_| HashSet::new()).collect();
    for (ip, assignees) in &common_assignments {
        for &idx in assignees {
            party_sets[idx].insert(*ip);
        }
    }

    for party in party_sets.iter_mut() {
        while party.len() < p.party_set_size {
            let ip = random_ipv4(&mut rng);
            if universe.contains(&ip) {
                continue;
            }
            universe.insert(ip);
            party.insert(ip);
        }
    }

    party_sets
        .into_iter()
        .map(|s| {
            let mut v: Vec<Ipv4Addr> = s.into_iter().collect();
            v.sort();
            v
        })
        .collect()
}

pub fn write_party_sets(dir: &Path, sets: &[Vec<Ipv4Addr>]) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    for (i, party) in sets.iter().enumerate() {
        let path = dir.join(format!("party_{}.txt", i + 1));
        let f = fs::File::create(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        let mut w = BufWriter::new(f);
        for ip in party {
            writeln!(w, "{}", ip)?;
        }
    }
    Ok(())
}

fn random_ipv4<R: Rng>(rng: &mut R) -> Ipv4Addr {
    Ipv4Addr::from(rng.gen::<u32>())
}

fn sample_indices<R: Rng>(rng: &mut R, n: usize, k: usize) -> Vec<usize> {
    if k > n {
        return (0..n).collect();
    }
    let mut pool: Vec<usize> = (0..n).collect();
    pool.shuffle(rng);
    pool.truncate(k);
    pool.sort();
    pool
}

pub fn exact_threshold_intersection(sets: &[Vec<Ipv4Addr>], threshold: usize) -> Vec<Ipv4Addr> {
    use std::collections::HashMap;
    let mut counts: HashMap<Ipv4Addr, usize> = HashMap::new();
    for party in sets {
        let unique: HashSet<Ipv4Addr> = party.iter().copied().collect();
        for ip in unique {
            *counts.entry(ip).or_insert(0) += 1;
        }
    }
    let mut result: Vec<Ipv4Addr> = counts
        .into_iter()
        .filter_map(|(ip, c)| if c >= threshold { Some(ip) } else { None })
        .collect();
    result.sort();
    result
}

pub fn list_cached_datasets(party_sets_root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !party_sets_root.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(party_sets_root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

pub fn parse_dataset_tag(tag: &str) -> Result<DatasetParams> {
    let mut num_parties = None;
    let mut threshold = None;
    let mut num_common_ips = None;
    let mut party_set_size = None;
    for part in tag.split('_') {
        if let Some(rest) = part.strip_prefix('n') {
            num_parties = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix('t') {
            threshold = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix('c') {
            num_common_ips = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix('s') {
            party_set_size = rest.parse().ok();
        }
    }
    match (num_parties, threshold, num_common_ips, party_set_size) {
        (Some(n), Some(t), Some(c), Some(s)) => Ok(DatasetParams {
            num_parties: n,
            threshold: t,
            num_common_ips: c,
            party_set_size: s,
        }),
        _ => bail!("could not parse dataset tag: {}", tag),
    }
}
