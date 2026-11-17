use super::{Accuracy, Application, EncodingInfo, Workload};
use crate::bloom::{build_party_bloom_filters, fpr_for, BloomFilter};
use crate::circuit::ThresholdCircuit;
use crate::config::SampleConfig;
use crate::dataset::{exact_threshold_intersection, load_or_create_party_sets, DatasetParams};
use crate::extract::extract_candidates_from_intersection_bloom;
use anyhow::Result;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

pub struct TpsiApp;

impl Application for TpsiApp {
    fn name(&self) -> &'static str {
        "TPSI (threshold private set intersection)"
    }
    fn slug(&self) -> &'static str {
        "tpsi"
    }
    fn build(&self, cfg: &SampleConfig, root: &Path) -> Result<Box<dyn Workload>> {
        let params = DatasetParams {
            num_parties: cfg.num_parties,
            threshold: cfg.threshold,
            num_common_ips: cfg.num_common_ips,
            party_set_size: cfg.party_set_size,
        };
        let fpr = fpr_for(cfg.party_set_size);
        let loaded = load_or_create_party_sets(params, root)?;
        let filters = build_party_bloom_filters(&loaded.sets, cfg.party_set_size, fpr);
        let reference = filters[0].clone();
        let operands: Vec<Vec<bool>> = filters.iter().map(|f| f.bits.clone()).collect();
        let circuit = ThresholdCircuit::new(cfg.num_parties, cfg.threshold);
        let plaintext = circuit.evaluate_plaintext(&operands);
        let pool = loaded
            .sets
            .iter()
            .flatten()
            .copied()
            .collect::<HashSet<_>>()
            .len();
        Ok(Box::new(TpsiWorkload {
            sets: loaded.sets,
            reference,
            operands,
            circuit,
            plaintext,
            threshold: cfg.threshold,
            num_bits: filters[0].num_bits,
            num_hash_funcs: filters[0].num_hash_funcs,
            pool,
            source: loaded.source.as_str(),
            tag: params.tag(),
            fpr,
        }))
    }
}

pub struct TpsiWorkload {
    sets: Vec<Vec<Ipv4Addr>>,
    reference: BloomFilter,
    operands: Vec<Vec<bool>>,
    circuit: ThresholdCircuit,
    plaintext: Vec<bool>,
    threshold: usize,
    num_bits: usize,
    num_hash_funcs: usize,
    pool: usize,
    source: &'static str,
    tag: String,
    fpr: f64,
}

impl Workload for TpsiWorkload {
    fn operands(&self) -> &[Vec<bool>] {
        &self.operands
    }
    fn circuit(&self) -> &ThresholdCircuit {
        &self.circuit
    }
    fn plaintext_result(&self) -> &[bool] {
        &self.plaintext
    }
    fn recovered_count(&self, result_bits: &[bool]) -> usize {
        extract_candidates_from_intersection_bloom(result_bits, &self.sets, &self.reference).len()
    }
    fn accuracy(&self) -> Accuracy {
        Accuracy {
            exact: Some(exact_threshold_intersection(&self.sets, self.threshold).len()),
            candidate_pool: Some(self.pool),
        }
    }
    fn encoding(&self) -> EncodingInfo {
        EncodingInfo {
            num_bits: self.num_bits,
            num_hash_funcs: self.num_hash_funcs,
        }
    }
    fn run_tag(&self) -> String {
        self.tag.clone()
    }
    fn summary(&self) -> String {
        format!(
            "TPSI: {} parties, T={}, Bloom M={} K={} (FPR target {:.3e})",
            self.operands.len(),
            self.threshold,
            self.num_bits,
            self.num_hash_funcs,
            self.fpr,
        )
    }
    fn dataset_source(&self) -> &'static str {
        self.source
    }
}
