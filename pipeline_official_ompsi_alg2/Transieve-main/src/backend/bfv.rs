use anyhow::Result;
use std::time::Instant;

use fhe::bfv::{
    BfvParametersBuilder, Ciphertext, Encoding, Plaintext, RelinearizationKey, SecretKey,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

use crate::circuit::ThresholdCircuit;

const PLAINTEXT_MODULUS: u64 = 65537;

const DEGREE: usize = 8192;

#[derive(Debug, Clone, Default)]
pub struct BfvTimings {
    pub keygen_s: f64,
    pub encrypt_s: f64,
    pub evaluate_s: f64,
    pub decrypt_s: f64,
}

fn anyize<E: std::fmt::Debug>(e: E) -> anyhow::Error {
    anyhow::anyhow!("fhe (bfv): {e:?}")
}

pub(crate) fn secure_degree_128(total_q_bits: usize, min_degree: usize) -> Result<usize> {
    const TABLE: &[(usize, usize)] = &[
        (1024, 27),
        (2048, 54),
        (4096, 109),
        (8192, 218),
        (16384, 438),
        (32768, 881),
    ];
    for &(n, max_q) in TABLE {
        if n >= min_degree && total_q_bits <= max_q {
            return Ok(n);
        }
    }
    anyhow::bail!(
        "no 128-bit-secure SIMD degree for a {total_q_bits}-bit BFV modulus chain \
         (p=65537 caps the SIMD degree at 32768, max ~881 bits); reduce the SOP depth"
    )
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

fn sop_mult_depth(circuit: &ThresholdCircuit) -> usize {
    ceil_log2(circuit.threshold) + ceil_log2(circuit.num_terms())
}

fn and_tree(factors: &[Ciphertext], rk: &RelinearizationKey) -> Result<Ciphertext> {
    let mut level: Vec<Ciphertext> = factors.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut prod = &level[i] * &level[i + 1];
                rk.relinearizes(&mut prod).map_err(anyize)?;
                next.push(prod);
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    Ok(level
        .into_iter()
        .next()
        .expect("threshold >= 1 → non-empty term"))
}

fn or_tree(terms: Vec<Ciphertext>, rk: &RelinearizationKey) -> Result<Ciphertext> {
    let mut level = terms;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let a = &level[i];
                let b = &level[i + 1];
                let mut ab = a * b;
                rk.relinearizes(&mut ab).map_err(anyize)?;
                let sum = a + b;
                next.push(&sum - &ab);
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    Ok(level.into_iter().next().expect("circuit has >= 1 term"))
}

pub fn evaluate_sop_bfv(
    filters: &[Vec<bool>],
    circuit: &ThresholdCircuit,
    sample_bits: usize,
) -> Result<(Vec<bool>, BfvTimings)> {
    let num_parties = filters.len();
    assert_eq!(num_parties, circuit.num_parties);
    let num_bits = filters[0].len();
    let requested = sample_bits.min(num_bits).max(1);

    let mut timings = BfvTimings::default();
    let depth = sop_mult_depth(circuit);

    let moduli_sizes: Vec<usize> = vec![55; depth + 2];

    let total_q_bits: usize = moduli_sizes.iter().sum();
    let degree = secure_degree_128(total_q_bits, DEGREE).map_err(anyize)?;

    println!(
        "[RUN] BFV keygen: degree={}, slots={}, plaintext_mod={}, SOP depth={} ({} moduli, {} bit Q) ...",
        degree, degree, PLAINTEXT_MODULUS, depth, moduli_sizes.len(), total_q_bits,
    );
    let t0 = Instant::now();
    let params = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(PLAINTEXT_MODULUS)
        .set_moduli_sizes(&moduli_sizes)
        .build_arc()
        .map_err(anyize)?;
    let mut rng = rand_bfv::rng();
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng).map_err(anyize)?;
    timings.keygen_s = t0.elapsed().as_secs_f64();

    let slots = degree;

    let chunk_count = requested.div_ceil(slots);
    let sample = (chunk_count * slots).min(num_bits);
    let mut result_bits: Vec<bool> = Vec::with_capacity(sample);

    println!(
        "[RUN] BFV baseline: evaluating {} of {} bits ({}%) in {} chunk(s) of {} slots",
        sample,
        num_bits,
        (sample as f64 / num_bits as f64 * 100.0).round(),
        chunk_count,
        slots,
    );

    for chunk_idx in 0..chunk_count {
        let start = chunk_idx * slots;
        let stop = (start + slots).min(sample);
        let span = stop - start;

        let t0 = Instant::now();
        let mut party_cts: Vec<Ciphertext> = Vec::with_capacity(num_parties);
        for filter in filters.iter() {
            let mut slot_vals = vec![0u64; slots];
            for (i, &b) in filter[start..stop].iter().enumerate() {
                slot_vals[i] = b as u64;
            }
            let pt =
                Plaintext::try_encode(&slot_vals, Encoding::simd(), &params).map_err(anyize)?;
            party_cts.push(sk.try_encrypt(&pt, &mut rng).map_err(anyize)?);
        }
        timings.encrypt_s += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let mut term_cts: Vec<Ciphertext> = Vec::with_capacity(circuit.terms.len());
        for term in &circuit.terms {
            let factors: Vec<Ciphertext> = term.iter().map(|&p| party_cts[p].clone()).collect();
            term_cts.push(and_tree(&factors, &rk)?);
        }
        let result_ct = or_tree(term_cts, &rk)?;
        timings.evaluate_s += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let pt = sk.try_decrypt(&result_ct).map_err(anyize)?;
        let vals = Vec::<u64>::try_decode(&pt, Encoding::simd()).map_err(anyize)?;
        timings.decrypt_s += t0.elapsed().as_secs_f64();

        for &v in vals.iter().take(span) {
            result_bits.push((v & 1) == 1);
        }
    }

    Ok((result_bits, timings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfv_sop_matches_plaintext_threshold_2_of_3() {
        let circuit = ThresholdCircuit::new(3, 2);
        let a = vec![true, true, false, false, true];
        let b = vec![true, false, true, false, true];
        let c = vec![true, true, true, false, false];
        let filters = vec![a, b, c];
        let expected = circuit.evaluate_plaintext(&filters);

        let (got, _t) =
            evaluate_sop_bfv(&filters, &circuit, filters[0].len()).expect("BFV SOP failed");
        assert_eq!(got, expected, "BFV SOP did not match plaintext oracle");
    }
}
