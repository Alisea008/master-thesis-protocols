use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_META_FILE: &str = "party_sets_meta.json";
pub const DEFAULT_PARTY_SETS_DIR: &str = "party_sets";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_script_mode")]
    pub script_mode: String,
    pub sample_config: SampleConfig,
    pub scaling_config: ScalingConfig,
}

fn default_script_mode() -> String {
    "circuit_tpsi".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleConfig {
    pub num_parties: usize,
    pub threshold: usize,
    pub num_common_ips: usize,
    pub party_set_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingConfig {
    #[serde(default = "default_max_parties")]
    pub max_parties: usize,
    #[serde(default = "default_sample_bits_cap")]
    pub sample_bits_cap: usize,
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
    pub scaling_sweeps: ScalingSweeps,
}

fn default_max_parties() -> usize {
    20
}
fn default_sample_bits_cap() -> usize {
    100_000
}
fn default_output_dir() -> String {
    "benchmark_outputs_rs".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingSweeps {
    pub parties: PartiesSweep,
    pub threshold: ThresholdSweep,
    pub set_size: SetSizeSweep,
    pub common_ips: CommonIpsSweep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartiesSweep {
    pub n_values: RangeOrList,
    pub threshold_mode: String, // "half" or "fixed"
    pub party_set_size: usize,
    pub num_common_ips: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSweep {
    pub n_fixed: usize,
    pub t_values: RangeOrList,
    pub party_set_size: usize,
    pub num_common_ips: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSizeSweep {
    pub set_sizes: Vec<usize>,
    pub num_parties: usize,
    pub threshold: usize,
    pub num_common_ips: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonIpsSweep {
    pub common_values: Vec<usize>,
    pub num_parties: usize,
    pub threshold: usize,
    pub party_set_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RangeOrList {
    Map(BTreeMap<String, serde_json::Value>),
    List(Vec<usize>),
}

impl RangeOrList {
    pub fn resolve(&self) -> Result<Vec<usize>> {
        match self {
            RangeOrList::List(v) => Ok(v.clone()),
            RangeOrList::Map(map) => {
                let range = map
                    .get("range")
                    .context("range_or_list map missing 'range'")?;
                parse_range(range)
            }
        }
    }
}

fn parse_range(v: &serde_json::Value) -> Result<Vec<usize>> {
    if let Some(arr) = v.as_array() {
        if arr.len() != 2 {
            anyhow::bail!("range array must have exactly 2 entries");
        }
        let lo = arr[0].as_u64().context("range lo must be integer")? as usize;
        let hi = arr[1].as_u64().context("range hi must be integer")? as usize;
        return Ok((lo..=hi).collect());
    }
    if let Some(s) = v.as_str() {
        let (lo_s, hi_s) = s.split_once("..").context("range string must be 'a..b'")?;
        let lo: usize = lo_s.parse()?;
        let hi: usize = hi_s.parse()?;
        return Ok((lo..=hi).collect());
    }
    anyhow::bail!("range must be [lo,hi] array or 'lo..hi' string")
}

pub fn load_runtime_config(root: &Path) -> Result<RuntimeConfig> {
    let config_path = root.join(DEFAULT_PARTY_SETS_DIR).join(DEFAULT_META_FILE);
    let data = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let cfg: RuntimeConfig = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    Ok(cfg)
}

pub fn party_sets_dir(root: &Path) -> PathBuf {
    root.join(DEFAULT_PARTY_SETS_DIR)
}
