use std::time::Instant;
use tfhe::shortint::parameters::{ClassicPBSParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
use tfhe::shortint::server_key::{BivariateLookupTableOwned, LookupTableOwned};
use tfhe::shortint::ServerKey;

use super::super::boolean::rasta::{generate_round_layers, RoundLayers, NUM_ROUNDS, STATE_BITS};
use super::super::DecryptTimings;
use super::{
    clean_to_bit_assign, xor_const, EncBitShortint, ShortintKeys, TranscipherDecryptShortint,
};

pub struct RastaShortint;

impl TranscipherDecryptShortint for RastaShortint {
    const PARAMETERS: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    const BLOCK_BITS: usize = STATE_BITS;
    const KEY_BITS: usize = STATE_BITS;
    const NAME: &'static str = "Rasta-525-5 (shortint)";

    const PBS_PER_OUTPUT_BIT: f64 = 11.0;
    const MULTIPLICATIVE_DEPTH: usize = NUM_ROUNDS;
    const FIXED_INIT_PBS: usize = 0;

    fn decrypt_block(
        keys: &ShortintKeys,
        enc_key: &[EncBitShortint],
        cipher_block: &[bool],
    ) -> Vec<EncBitShortint> {
        assert_eq!(enc_key.len(), Self::KEY_BITS);
        assert!(cipher_block.len() <= Self::BLOCK_BITS);
        let (out, _) = decrypt_stream_timed(keys, enc_key, cipher_block);
        out
    }
}

pub fn decrypt_stream(
    keys: &ShortintKeys,
    enc_key: &[EncBitShortint],
    cipher: &[bool],
) -> Vec<EncBitShortint> {
    let (out, _) = decrypt_stream_timed(keys, enc_key, cipher);
    out
}

pub fn decrypt_stream_timed(
    keys: &ShortintKeys,
    enc_key: &[EncBitShortint],
    cipher: &[bool],
) -> (Vec<EncBitShortint>, DecryptTimings) {
    assert_eq!(enc_key.len(), STATE_BITS);
    let sk = &keys.server_key;
    let xor_lut = &keys.xor_lut;

    let chi_and_lut = sk.generate_lookup_table_bivariate(|a, b| (1 - (a & 1)) & (b & 1));

    let nonce: [u64; 2] = [0, 0];
    let init_s = 0.0;

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    let num_blocks = (cipher.len() + STATE_BITS - 1) / STATE_BITS;
    for block_idx in 0..num_blocks {
        let layers = generate_round_layers(nonce, block_idx as u64);
        let keystream_block = rasta_forward(sk, xor_lut, &chi_and_lut, enc_key, &layers);

        let bit_offset = block_idx * STATE_BITS;
        let bits_in_block = STATE_BITS.min(cipher.len() - bit_offset);
        for i in 0..bits_in_block {
            let mut bit = xor_const(sk, &keystream_block[i], cipher[bit_offset + i]);
            clean_to_bit_assign(sk, xor_lut, &mut bit);
            out.push(bit);
        }
    }
    let per_bit_total_s = t_per.elapsed().as_secs_f64();

    (
        out,
        DecryptTimings {
            init_s,
            per_bit_total_s,
            bits: cipher.len(),
        },
    )
}

fn rasta_forward(
    sk: &ServerKey,
    xor_lut: &LookupTableOwned,
    chi_and_lut: &BivariateLookupTableOwned,
    enc_key: &[EncBitShortint],
    layers: &RoundLayers,
) -> Vec<EncBitShortint> {
    let mut state: Vec<EncBitShortint> = enc_key.to_vec();

    for r in 0..NUM_ROUNDS {
        state = affine_layer(
            sk,
            xor_lut,
            &state,
            &layers.matrices[r],
            &layers.constants[r],
        );
        state = chi_layer(sk, chi_and_lut, &state);
    }
    state = affine_layer(
        sk,
        xor_lut,
        &state,
        &layers.matrices[NUM_ROUNDS],
        &layers.constants[NUM_ROUNDS],
    );

    for i in 0..STATE_BITS {
        sk.unchecked_add_assign(&mut state[i], &enc_key[i]);
    }
    state
}

fn affine_layer(
    sk: &ServerKey,
    xor_lut: &LookupTableOwned,
    state: &[EncBitShortint],
    matrix: &[Vec<bool>],
    constant: &[bool],
) -> Vec<EncBitShortint> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let row = &matrix[i];
        let mut accum: Option<EncBitShortint> = None;
        for j in 0..n {
            if !row[j] {
                continue;
            }
            match accum.as_mut() {
                None => accum = Some(state[j].clone()),
                Some(acc) => {
                    if sk
                        .is_add_possible(acc.noise_degree(), state[j].noise_degree())
                        .is_err()
                    {
                        sk.apply_lookup_table_assign(acc, xor_lut);
                    }
                    sk.unchecked_add_assign(acc, &state[j]);
                }
            }
        }
        let mut bit = match accum {
            Some(a) => a,
            None => sk.create_trivial(0),
        };

        if constant[i] {
            sk.unchecked_scalar_add_assign(&mut bit, 1);
        }
        sk.apply_lookup_table_assign(&mut bit, xor_lut);
        out.push(bit);
    }
    out
}

fn chi_layer(
    sk: &ServerKey,
    chi_and_lut: &BivariateLookupTableOwned,
    state: &[EncBitShortint],
) -> Vec<EncBitShortint> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let and_term =
            sk.apply_lookup_table_bivariate(&state[(i + 1) % n], &state[(i + 2) % n], chi_and_lut);
        let mut bit = state[i].clone();
        sk.unchecked_add_assign(&mut bit, &and_term);
        out.push(bit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::boolean::rasta::keystream_plain;

    #[test]
    #[ignore]
    fn fhe_matches_plaintext_keystream_shortint() {
        let key_bits: Vec<bool> = (0..STATE_BITS).map(|i| i % 5 == 0).collect();
        let nonce = [0u64; 2];
        let want = keystream_plain(&key_bits, nonce, 16);

        let keys = ShortintKeys::generate(RastaShortint::PARAMETERS);
        let enc_key: Vec<EncBitShortint> = key_bits.iter().map(|&b| keys.encrypt_bit(b)).collect();
        let cipher_block: Vec<bool> = vec![false; 16];
        let (enc_out, _) = decrypt_stream_timed(&keys, &enc_key, &cipher_block);
        let got: Vec<bool> = enc_out.iter().map(|c| keys.decrypt_bit(c)).collect();
        assert_eq!(got, want);
    }
}
