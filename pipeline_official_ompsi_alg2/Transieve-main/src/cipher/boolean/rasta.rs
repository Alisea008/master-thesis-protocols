use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Instant;
use tfhe::boolean::prelude::*;

use super::{DecryptTimings, EncBit, TranscipherDecrypt};

pub const STATE_BITS: usize = 525;
pub const NUM_ROUNDS: usize = 5;

pub struct Rasta;

impl TranscipherDecrypt for Rasta {
    const BLOCK_BITS: usize = STATE_BITS;
    const KEY_BITS: usize = STATE_BITS;
    const NAME: &'static str = "Rasta-525-5";

    const PBS_PER_OUTPUT_BIT: f64 = NUM_ROUNDS as f64;

    const MULTIPLICATIVE_DEPTH: usize = NUM_ROUNDS;

    const FIXED_INIT_PBS: usize = 0;

    fn decrypt_block(sk: &ServerKey, enc_key: &[EncBit], cipher_block: &[bool]) -> Vec<EncBit> {
        assert_eq!(enc_key.len(), Self::KEY_BITS);
        assert!(cipher_block.len() <= Self::BLOCK_BITS);
        let (out, _) = decrypt_stream_timed(sk, enc_key, cipher_block);
        out
    }
}

pub fn decrypt_stream(sk: &ServerKey, enc_key: &[EncBit], cipher: &[bool]) -> Vec<EncBit> {
    let (out, _) = decrypt_stream_timed(sk, enc_key, cipher);
    out
}

pub fn decrypt_stream_timed(
    sk: &ServerKey,
    enc_key: &[EncBit],
    cipher: &[bool],
) -> (Vec<EncBit>, DecryptTimings) {
    assert_eq!(enc_key.len(), STATE_BITS);
    let nonce: [u64; 2] = [0, 0]; // experiment-only fixed nonce

    let init_s = 0.0;

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    let num_blocks = (cipher.len() + STATE_BITS - 1) / STATE_BITS;
    for block_idx in 0..num_blocks {
        let layers = generate_round_layers(nonce, block_idx as u64);
        let keystream_block = rasta_forward(sk, enc_key, &layers);

        let bit_offset = block_idx * STATE_BITS;
        let bits_in_block = STATE_BITS.min(cipher.len() - bit_offset);
        for i in 0..bits_in_block {
            out.push(xor_const(sk, &keystream_block[i], cipher[bit_offset + i]));
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

pub(crate) struct RoundLayers {
    pub(crate) matrices: Vec<Vec<Vec<bool>>>,

    pub(crate) constants: Vec<Vec<bool>>,
}

pub(crate) fn generate_round_layers(nonce: [u64; 2], block_counter: u64) -> RoundLayers {
    let mut prg = make_prg(nonce, block_counter);
    let mut matrices = Vec::with_capacity(NUM_ROUNDS + 1);
    let mut constants = Vec::with_capacity(NUM_ROUNDS + 1);

    for _ in 0..=NUM_ROUNDS {
        matrices.push(random_matrix(&mut prg, STATE_BITS));
        constants.push(random_bits(&mut prg, STATE_BITS));
    }
    RoundLayers {
        matrices,
        constants,
    }
}

fn make_prg(nonce: [u64; 2], block_counter: u64) -> StdRng {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&nonce[0].to_le_bytes());
    seed[8..16].copy_from_slice(&nonce[1].to_le_bytes());
    seed[16..24].copy_from_slice(&block_counter.to_le_bytes());
    StdRng::from_seed(seed)
}

fn random_matrix(prg: &mut StdRng, n: usize) -> Vec<Vec<bool>> {
    (0..n).map(|_| random_bits(prg, n)).collect()
}

fn random_bits(prg: &mut StdRng, n: usize) -> Vec<bool> {
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 8];
    let mut bits_left: usize = 0;
    let mut word: u64 = 0;
    for _ in 0..n {
        if bits_left == 0 {
            prg.fill_bytes(&mut buf);
            word = u64::from_le_bytes(buf);
            bits_left = 64;
        }
        out.push((word & 1) == 1);
        word >>= 1;
        bits_left -= 1;
    }
    out
}

fn rasta_forward(sk: &ServerKey, enc_key: &[EncBit], layers: &RoundLayers) -> Vec<EncBit> {
    let mut state: Vec<EncBit> = enc_key.to_vec();

    for r in 0..NUM_ROUNDS {
        state = affine_layer(sk, &state, &layers.matrices[r], &layers.constants[r]);
        state = chi_layer(sk, &state);
    }

    state = affine_layer(
        sk,
        &state,
        &layers.matrices[NUM_ROUNDS],
        &layers.constants[NUM_ROUNDS],
    );

    for i in 0..STATE_BITS {
        state[i] = sk.xor(&state[i], &enc_key[i]);
    }
    state
}

fn affine_layer(
    sk: &ServerKey,
    state: &[EncBit],
    matrix: &[Vec<bool>],
    constant: &[bool],
) -> Vec<EncBit> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let row = &matrix[i];
        let mut accum: Option<EncBit> = None;
        for j in 0..n {
            if row[j] {
                accum = Some(match accum {
                    None => state[j].clone(),
                    Some(a) => sk.xor(&a, &state[j]),
                });
            }
        }

        let bit = match accum {
            Some(a) => xor_const(sk, &a, constant[i]),
            None => sk.trivial_encrypt(constant[i]),
        };
        out.push(bit);
    }
    out
}

fn chi_layer(sk: &ServerKey, state: &[EncBit]) -> Vec<EncBit> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let not_next = sk.not(&state[(i + 1) % n]);
        let and_term = sk.and(&not_next, &state[(i + 2) % n]);
        out.push(sk.xor(&state[i], &and_term));
    }
    out
}

fn xor_const(sk: &ServerKey, x: &EncBit, c: bool) -> EncBit {
    if c {
        sk.not(x)
    } else {
        x.clone()
    }
}

pub fn keystream_plain(key: &[bool], nonce: [u64; 2], n: usize) -> Vec<bool> {
    assert_eq!(key.len(), STATE_BITS);
    let mut out = Vec::with_capacity(n);
    let num_blocks = (n + STATE_BITS - 1) / STATE_BITS;
    for block_idx in 0..num_blocks {
        let layers = generate_round_layers(nonce, block_idx as u64);
        let block = rasta_forward_plain(key, &layers);
        let bit_offset = block_idx * STATE_BITS;
        let bits_in_block = STATE_BITS.min(n - bit_offset);
        out.extend_from_slice(&block[..bits_in_block]);
    }
    out
}

fn rasta_forward_plain(key: &[bool], layers: &RoundLayers) -> Vec<bool> {
    let mut state: Vec<bool> = key.to_vec();
    for r in 0..NUM_ROUNDS {
        state = plain_affine(&state, &layers.matrices[r], &layers.constants[r]);
        state = plain_chi(&state);
    }
    state = plain_affine(
        &state,
        &layers.matrices[NUM_ROUNDS],
        &layers.constants[NUM_ROUNDS],
    );
    for i in 0..STATE_BITS {
        state[i] ^= key[i];
    }
    state
}

fn plain_affine(state: &[bool], matrix: &[Vec<bool>], constant: &[bool]) -> Vec<bool> {
    let n = state.len();
    (0..n)
        .map(|i| {
            let row = &matrix[i];
            let mut bit = false;
            for j in 0..n {
                if row[j] {
                    bit ^= state[j];
                }
            }
            bit ^ constant[i]
        })
        .collect()
}

fn plain_chi(state: &[bool]) -> Vec<bool> {
    let n = state.len();
    (0..n)
        .map(|i| state[i] ^ ((!state[(i + 1) % n]) & state[(i + 2) % n]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn fhe_matches_plaintext_keystream() {
        let key_bits: Vec<bool> = (0..STATE_BITS).map(|i| i % 5 == 0).collect();
        let nonce = [0u64; 2];
        let want = keystream_plain(&key_bits, nonce, 16);

        let (ck, sk) = gen_keys();
        let enc_key: Vec<EncBit> = key_bits.iter().map(|&b| ck.encrypt(b)).collect();
        let cipher_block: Vec<bool> = vec![false; 16];
        let (enc_out, _) = decrypt_stream_timed(&sk, &enc_key, &cipher_block);
        let got: Vec<bool> = enc_out.iter().map(|c| ck.decrypt(c)).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn plaintext_roundtrip() {
        let key: Vec<bool> = (0..STATE_BITS).map(|i| i % 7 == 3).collect();
        let nonce = [0u64; 2];
        let plaintext: Vec<bool> = (0..1200).map(|i| i % 3 == 0).collect();

        let ks_enc = keystream_plain(&key, nonce, plaintext.len());
        let cipher: Vec<bool> = plaintext
            .iter()
            .zip(&ks_enc)
            .map(|(&p, &z)| p ^ z)
            .collect();

        let ks_dec = keystream_plain(&key, nonce, plaintext.len());
        let recovered: Vec<bool> = cipher.iter().zip(&ks_dec).map(|(&c, &z)| c ^ z).collect();
        assert_eq!(plaintext, recovered);
    }
}
