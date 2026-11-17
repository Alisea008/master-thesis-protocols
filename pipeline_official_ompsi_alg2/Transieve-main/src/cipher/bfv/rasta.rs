use anyhow::Result;
use std::sync::Arc;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, RelinearizationKey,
    SecretKey,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

use crate::cipher::boolean::rasta::{
    generate_round_layers, keystream_plain, RoundLayers, NUM_ROUNDS, STATE_BITS,
};

const PLAINTEXT_MODULUS: u64 = 2;

const DEGREE: usize = 4096;

fn anyize<E: std::fmt::Debug>(e: E) -> anyhow::Error {
    anyhow::anyhow!("fhe (bfv-rasta): {e:?}")
}

pub struct RastaBfvKeys {
    pub params: Arc<BfvParameters>,
    pub sk: SecretKey,
    pub rk: RelinearizationKey,
    one: Plaintext,
}

impl RastaBfvKeys {
    pub fn generate(depth: usize) -> Result<Self> {
        let moduli_sizes: Vec<usize> = vec![55; depth + 2];
        let params = BfvParametersBuilder::new()
            .set_degree(DEGREE)
            .set_plaintext_modulus(PLAINTEXT_MODULUS)
            .set_moduli_sizes(&moduli_sizes)
            .build_arc()
            .map_err(anyize)?;
        let mut rng = rand_bfv::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let rk = RelinearizationKey::new(&sk, &mut rng).map_err(anyize)?;
        let one = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).map_err(anyize)?;
        Ok(Self {
            params,
            sk,
            rk,
            one,
        })
    }

    pub fn encrypt_bit(&self, b: bool) -> Result<Ciphertext> {
        let pt =
            Plaintext::try_encode(&[b as u64], Encoding::poly(), &self.params).map_err(anyize)?;
        let mut rng = rand_bfv::rng();
        self.sk.try_encrypt(&pt, &mut rng).map_err(anyize)
    }

    pub fn decrypt_bit(&self, ct: &Ciphertext) -> Result<bool> {
        let pt = self.sk.try_decrypt(ct).map_err(anyize)?;
        let v = Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(anyize)?;
        Ok((v.first().copied().unwrap_or(0) & 1) == 1)
    }
}

fn hxor(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    a + b
}

fn hand(keys: &RastaBfvKeys, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
    let mut p = a * b;
    keys.rk.relinearizes(&mut p).map_err(anyize)?;
    Ok(p)
}

fn hnot(keys: &RastaBfvKeys, a: &Ciphertext) -> Ciphertext {
    a + &keys.one
}

fn hxor_const(keys: &RastaBfvKeys, a: &Ciphertext, c: bool) -> Ciphertext {
    if c {
        hnot(keys, a)
    } else {
        a.clone()
    }
}

fn affine_layer(
    keys: &RastaBfvKeys,
    state: &[Ciphertext],
    matrix: &[Vec<bool>],
    constant: &[bool],
) -> Result<Vec<Ciphertext>> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let row = &matrix[i];
        let mut acc: Option<Ciphertext> = None;
        for (j, &on) in row.iter().enumerate().take(n) {
            if on {
                acc = Some(match acc {
                    None => state[j].clone(),
                    Some(a) => hxor(&a, &state[j]),
                });
            }
        }
        let bit = match acc {
            Some(a) => hxor_const(keys, &a, constant[i]),

            None => keys.encrypt_bit(constant[i])?,
        };
        out.push(bit);
    }
    Ok(out)
}

fn chi_layer(keys: &RastaBfvKeys, state: &[Ciphertext]) -> Result<Vec<Ciphertext>> {
    let n = state.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let not_next = hnot(keys, &state[(i + 1) % n]);
        let and_term = hand(keys, &not_next, &state[(i + 2) % n])?;
        out.push(hxor(&state[i], &and_term));
    }
    Ok(out)
}

fn rasta_forward(
    keys: &RastaBfvKeys,
    enc_key: &[Ciphertext],
    layers: &RoundLayers,
    n: usize,
    rounds: usize,
) -> Result<Vec<Ciphertext>> {
    let mut state = enc_key.to_vec();
    for r in 0..rounds {
        state = affine_layer(keys, &state, &layers.matrices[r], &layers.constants[r])?;
        state = chi_layer(keys, &state)?;
    }
    state = affine_layer(
        keys,
        &state,
        &layers.matrices[rounds],
        &layers.constants[rounds],
    )?;
    for i in 0..n {
        state[i] = hxor(&state[i], &enc_key[i]);
    }
    Ok(state)
}

pub fn decrypt_stream_bfv(
    keys: &RastaBfvKeys,
    enc_key: &[Ciphertext],
    cipher: &[bool],
) -> Result<Vec<Ciphertext>> {
    assert_eq!(
        enc_key.len(),
        STATE_BITS,
        "Rasta key must be {STATE_BITS} bits"
    );
    let nonce = [0u64; 2];
    let mut out = Vec::with_capacity(cipher.len());
    let num_blocks = cipher.len().div_ceil(STATE_BITS);
    for block_idx in 0..num_blocks {
        let layers = generate_round_layers(nonce, block_idx as u64);
        let ks = rasta_forward(keys, enc_key, &layers, STATE_BITS, NUM_ROUNDS)?;
        let off = block_idx * STATE_BITS;
        let take = STATE_BITS.min(cipher.len() - off);
        for i in 0..take {
            out.push(hxor_const(keys, &ks[i], cipher[off + i]));
        }
    }
    Ok(out)
}

pub fn encrypt_stream_plain(key: &[bool], plaintext: &[bool]) -> Vec<bool> {
    let nonce = [0u64; 2];
    let ks = keystream_plain(key, nonce, plaintext.len());
    plaintext
        .iter()
        .zip(ks.iter())
        .map(|(&p, &z)| p ^ z)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TN: usize = 7;
    const TR: usize = 2;

    fn small_layers() -> (Vec<Vec<Vec<bool>>>, Vec<Vec<bool>>) {
        let mut m = Vec::new();
        let mut c = Vec::new();
        for r in 0..=TR {
            let mat: Vec<Vec<bool>> = (0..TN)
                .map(|i| {
                    (0..TN)
                        .map(|j| ((i * 3 + j * 5 + r * 7) % 2) == 0)
                        .collect()
                })
                .collect();
            let con: Vec<bool> = (0..TN).map(|i| ((i + r) % 3) == 0).collect();
            m.push(mat);
            c.push(con);
        }
        (m, c)
    }

    fn plain_chi(s: &[bool]) -> Vec<bool> {
        let n = s.len();
        (0..n)
            .map(|i| s[i] ^ ((!s[(i + 1) % n]) & s[(i + 2) % n]))
            .collect()
    }
    fn plain_affine(s: &[bool], m: &[Vec<bool>], c: &[bool]) -> Vec<bool> {
        let n = s.len();
        (0..n)
            .map(|i| {
                let mut b = false;
                for j in 0..n {
                    if m[i][j] {
                        b ^= s[j];
                    }
                }
                b ^ c[i]
            })
            .collect()
    }
    fn plain_forward(key: &[bool], m: &[Vec<Vec<bool>>], c: &[Vec<bool>]) -> Vec<bool> {
        let mut s = key.to_vec();
        for r in 0..TR {
            s = plain_affine(&s, &m[r], &c[r]);
            s = plain_chi(&s);
        }
        s = plain_affine(&s, &m[TR], &c[TR]);
        for i in 0..TN {
            s[i] ^= key[i];
        }
        s
    }

    #[test]
    fn bfv_rasta_circuit_matches_plaintext_small() {
        let (m, c) = small_layers();
        let key: Vec<bool> = (0..TN).map(|i| i % 2 == 0).collect();
        let want = plain_forward(&key, &m, &c);

        let keys = RastaBfvKeys::generate(TR).expect("keygen");
        let enc_key: Vec<Ciphertext> = key.iter().map(|&b| keys.encrypt_bit(b).unwrap()).collect();
        let layers = RoundLayers {
            matrices: m,
            constants: c,
        };
        let ks = rasta_forward(&keys, &enc_key, &layers, TN, TR).expect("forward");
        let got: Vec<bool> = ks.iter().map(|ct| keys.decrypt_bit(ct).unwrap()).collect();

        assert_eq!(got, want, "BFV F₂ Rasta circuit must match plaintext");
    }
}
