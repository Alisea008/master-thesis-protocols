use itertools::Itertools;

#[derive(Debug, Clone)]
pub struct ThresholdCircuit {
    pub num_parties: usize,
    pub threshold: usize,

    pub terms: Vec<Vec<usize>>,
}

impl ThresholdCircuit {
    pub fn new(num_parties: usize, threshold: usize) -> Self {
        assert!(threshold >= 1 && threshold <= num_parties);
        let terms: Vec<Vec<usize>> = (0..num_parties).combinations(threshold).collect();
        ThresholdCircuit {
            num_parties,
            threshold,
            terms,
        }
    }

    pub fn num_terms(&self) -> usize {
        self.terms.len()
    }

    pub fn and_gates_per_bit(&self) -> usize {
        self.terms.len() * self.threshold.saturating_sub(1)
    }

    pub fn or_gates_per_bit(&self) -> usize {
        self.terms.len().saturating_sub(1)
    }

    pub fn display(&self) -> String {
        let mut parts = Vec::with_capacity(self.terms.len());
        for term in &self.terms {
            let s: String = term.iter().map(|&i| (b'A' + i as u8) as char).collect();
            parts.push(s);
        }
        parts.join(" + ")
    }

    pub fn evaluate_plaintext(&self, filters: &[Vec<bool>]) -> Vec<bool> {
        assert_eq!(filters.len(), self.num_parties);
        let num_bits = filters[0].len();
        for f in filters {
            assert_eq!(f.len(), num_bits);
        }
        let mut result = vec![false; num_bits];
        for bit_idx in 0..num_bits {
            let mut count = 0usize;
            for f in filters {
                if f[bit_idx] {
                    count += 1;
                    if count >= self.threshold {
                        break;
                    }
                }
            }
            result[bit_idx] = count >= self.threshold;
        }
        result
    }
}
