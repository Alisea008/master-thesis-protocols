use std::time::Instant;
use tfhe::boolean::prelude::*;

use crate::circuit::ThresholdCircuit;

pub struct Keys {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
}

impl Keys {
    pub fn generate() -> Self {
        let (client_key, server_key) = gen_keys();
        Keys {
            client_key,
            server_key,
        }
    }
}

pub struct BaselineTimings {
    pub encrypt_s: f64,
    pub evaluate_s: f64,
    pub decrypt_s: f64,
    pub total_s: f64,
}

pub struct SopTimings {
    pub evaluate_s: f64,
    pub decrypt_s: f64,
    pub total_s: f64,
}

pub fn evaluate_sop_boolean(
    keys: &Keys,
    encrypted_filters: &[Vec<Ciphertext>],
    circuit: &ThresholdCircuit,
) -> (Vec<bool>, SopTimings) {
    let num_bits = encrypted_filters[0].len();
    let sk = &keys.server_key;

    let t0 = Instant::now();
    let mut result_ct: Vec<Ciphertext> = Vec::with_capacity(num_bits);
    for bit_idx in 0..num_bits {
        let mut or_accum: Option<Ciphertext> = None;
        for term in &circuit.terms {
            let mut and_accum: Option<Ciphertext> = None;
            for &party_idx in term {
                let bit = &encrypted_filters[party_idx][bit_idx];
                and_accum = Some(match and_accum {
                    None => bit.clone(),
                    Some(acc) => sk.and(&acc, bit),
                });
            }
            let term_val = and_accum.unwrap();
            or_accum = Some(match or_accum {
                None => term_val,
                Some(acc) => sk.or(&acc, &term_val),
            });
        }
        result_ct.push(or_accum.unwrap());
    }
    let evaluate_s = t0.elapsed().as_secs_f64();

    let t0 = Instant::now();
    let result_bits: Vec<bool> = result_ct
        .iter()
        .map(|ct| keys.client_key.decrypt(ct))
        .collect();
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

pub fn run_baseline(
    keys: &Keys,
    filters: &[Vec<bool>],
    circuit: &ThresholdCircuit,
) -> (Vec<bool>, BaselineTimings) {
    let num_parties = filters.len();
    assert_eq!(num_parties, circuit.num_parties);
    let num_bits = filters[0].len();
    for f in filters {
        assert_eq!(f.len(), num_bits);
    }

    let t0 = Instant::now();
    let encrypted: Vec<Vec<Ciphertext>> = filters
        .iter()
        .map(|bits| bits.iter().map(|&b| keys.client_key.encrypt(b)).collect())
        .collect();
    let encrypt_s = t0.elapsed().as_secs_f64();

    let (result_bits, sop) = evaluate_sop_boolean(keys, &encrypted, circuit);

    (
        result_bits,
        BaselineTimings {
            encrypt_s,
            evaluate_s: sop.evaluate_s,
            decrypt_s: sop.decrypt_s,
            total_s: encrypt_s + sop.total_s,
        },
    )
}

pub fn run_baseline_sampled(
    keys: &Keys,
    filters: &[Vec<bool>],
    circuit: &ThresholdCircuit,
    sample_bits: usize,
) -> (Vec<bool>, BaselineTimings) {
    let slice: Vec<Vec<bool>> = filters
        .iter()
        .map(|bf| bf.iter().take(sample_bits).copied().collect())
        .collect();
    run_baseline(keys, &slice, circuit)
}
