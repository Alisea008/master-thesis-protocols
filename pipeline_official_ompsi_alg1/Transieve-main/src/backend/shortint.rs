use std::time::Instant;
use tfhe::shortint::ServerKey;

use crate::cipher::{EncBitShortint, ShortintKeys};
use crate::circuit::ThresholdCircuit;

#[derive(Debug, Clone, Default)]
pub struct SopTimings {
    pub evaluate_s: f64,
    pub decrypt_s: f64,
    pub total_s: f64,
}

pub fn evaluate_sop_shortint(
    keys: &ShortintKeys,
    encrypted_filters: &[Vec<EncBitShortint>],
    circuit: &ThresholdCircuit,
) -> (Vec<bool>, SopTimings) {
    let num_parties = encrypted_filters.len();
    assert_eq!(
        num_parties, circuit.num_parties,
        "encrypted_filters length must match circuit.num_parties",
    );
    let num_bits = encrypted_filters[0].len();
    for f in encrypted_filters {
        assert_eq!(
            f.len(),
            num_bits,
            "all parties must have the same bit count"
        );
    }

    let sk = &keys.server_key;

    let t0 = Instant::now();
    let mut result_ct: Vec<EncBitShortint> = Vec::with_capacity(num_bits);
    for bit_idx in 0..num_bits {
        let mut or_accum: Option<EncBitShortint> = None;
        for term in &circuit.terms {
            let mut and_accum: Option<EncBitShortint> = None;
            for &party_idx in term {
                let bit = &encrypted_filters[party_idx][bit_idx];
                and_accum = Some(match and_accum {
                    None => bit.clone(),
                    Some(acc) => sk.bitand(&acc, bit),
                });
            }
            let term_val = and_accum.expect("threshold>=1 guarantees a non-empty term");
            or_accum = Some(match or_accum {
                None => term_val,
                Some(acc) => sk.bitor(&acc, &term_val),
            });
        }
        result_ct.push(or_accum.expect("circuit has at least one term"));
    }
    let evaluate_s = t0.elapsed().as_secs_f64();

    let t0 = Instant::now();
    let result_bits: Vec<bool> = result_ct.iter().map(|ct| keys.decrypt_bit(ct)).collect();
    let decrypt_s = t0.elapsed().as_secs_f64();

    (
        result_bits,
        SopTimings {
            evaluate_s,
            decrypt_s,
            total_s: evaluate_s + decrypt_s,
        },
    )
}

#[allow(dead_code)]
pub(crate) fn approx_serialized_size(_sk: &ServerKey) -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    #[test]
    #[ignore]
    fn sop_matches_plaintext_threshold_2_of_3() {
        let keys = ShortintKeys::generate(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let circuit = ThresholdCircuit::new(3, 2);

        let party_a = vec![true, true, false, false];
        let party_b = vec![true, false, true, false];
        let party_c = vec![true, true, true, false];
        let plain =
            circuit.evaluate_plaintext(&[party_a.clone(), party_b.clone(), party_c.clone()]);

        let enc_a: Vec<EncBitShortint> = party_a.iter().map(|&b| keys.encrypt_bit(b)).collect();
        let enc_b: Vec<EncBitShortint> = party_b.iter().map(|&b| keys.encrypt_bit(b)).collect();
        let enc_c: Vec<EncBitShortint> = party_c.iter().map(|&b| keys.encrypt_bit(b)).collect();
        let (got, _) = evaluate_sop_shortint(&keys, &[enc_a, enc_b, enc_c], &circuit);
        assert_eq!(got, plain);
    }
}
