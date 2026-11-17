use super::{Accuracy, Application, EncodingInfo, Workload};
use crate::circuit::ThresholdCircuit;
use crate::config::SampleConfig;
use anyhow::Result;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::path::Path;

pub struct VotingApp;

impl Application for VotingApp {
    fn name(&self) -> &'static str {
        "Secure threshold voting"
    }
    fn slug(&self) -> &'static str {
        "voting"
    }
    fn build(&self, cfg: &SampleConfig, _root: &Path) -> Result<Box<dyn Workload>> {
        let voters = cfg.num_parties.max(1);
        let quorum = cfg.threshold.clamp(1, voters);
        let proposals = cfg.party_set_size.max(1);

        let mut rng = StdRng::seed_from_u64(0xB07E_5EED);
        let mut operands = vec![vec![false; proposals]; voters];
        for ballot in operands.iter_mut() {
            for slot in ballot.chunks_mut(64) {
                let r = rng.next_u64();
                for (i, v) in slot.iter_mut().enumerate() {
                    *v = ((r >> i) & 1) == 1;
                }
            }
        }

        let circuit = ThresholdCircuit::new(voters, quorum);
        let plaintext = circuit.evaluate_plaintext(&operands);
        let passed = plaintext.iter().filter(|&&b| b).count();
        Ok(Box::new(VotingWorkload {
            operands,
            circuit,
            plaintext,
            voters,
            quorum,
            proposals,
            passed,
        }))
    }
}

pub struct VotingWorkload {
    operands: Vec<Vec<bool>>,
    circuit: ThresholdCircuit,
    plaintext: Vec<bool>,
    voters: usize,
    quorum: usize,
    proposals: usize,
    passed: usize,
}

impl Workload for VotingWorkload {
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
        result_bits
            .iter()
            .take(self.proposals)
            .filter(|&&b| b)
            .count()
    }
    fn accuracy(&self) -> Accuracy {
        Accuracy {
            exact: Some(self.passed),
            candidate_pool: Some(self.proposals),
        }
    }
    fn encoding(&self) -> EncodingInfo {
        EncodingInfo {
            num_bits: self.proposals,
            num_hash_funcs: 0,
        }
    }
    fn run_tag(&self) -> String {
        format!("vote_n{}_q{}_p{}", self.voters, self.quorum, self.proposals)
    }
    fn summary(&self) -> String {
        format!(
            "Voting: {} voters, quorum {}, {} proposals",
            self.voters, self.quorum, self.proposals
        )
    }
}
