use crate::circuit::ThresholdCircuit;
use crate::config::SampleConfig;
use anyhow::Result;
use std::path::Path;

pub mod tpsi;
pub mod voting;

#[derive(Debug, Clone, Default)]
pub struct Accuracy {
    pub exact: Option<usize>,

    pub candidate_pool: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct EncodingInfo {
    pub num_bits: usize,
    pub num_hash_funcs: usize,
}

pub trait Workload {
    fn operands(&self) -> &[Vec<bool>];

    fn circuit(&self) -> &ThresholdCircuit;

    fn plaintext_result(&self) -> &[bool];

    fn recovered_count(&self, result_bits: &[bool]) -> usize;

    fn accuracy(&self) -> Accuracy;

    fn encoding(&self) -> EncodingInfo;

    fn run_tag(&self) -> String;

    fn summary(&self) -> String;

    fn dataset_source(&self) -> &'static str {
        "created"
    }
}

pub trait Application {
    fn name(&self) -> &'static str;
    fn slug(&self) -> &'static str;
    fn build(&self, cfg: &SampleConfig, root: &Path) -> Result<Box<dyn Workload>>;
}

pub fn parse(name: &str) -> Option<Box<dyn Application>> {
    match name.to_ascii_lowercase().as_str() {
        "tpsi" | "psi" => Some(Box::new(tpsi::TpsiApp)),
        "voting" | "vote" => Some(Box::new(voting::VotingApp)),
        _ => None,
    }
}
