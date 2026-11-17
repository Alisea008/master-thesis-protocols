use rand::{rngs::StdRng, RngCore, SeedableRng};

pub const P: u64 = 65537;

#[derive(Clone, Copy, Debug)]
pub struct PastaParams {
    pub t: usize,
    pub rounds: usize,
}

pub const PASTA3: PastaParams = PastaParams { t: 128, rounds: 3 };

pub const PASTA4: PastaParams = PastaParams { t: 32, rounds: 4 };

#[inline]
fn addm(a: u64, b: u64) -> u64 {
    (a + b) % P
}
#[inline]
fn subm(a: u64, b: u64) -> u64 {
    (a + P - (b % P)) % P
}
#[inline]
fn mulm(a: u64, b: u64) -> u64 {
    (a * b) % P
}

struct Layer {
    m_l: Vec<Vec<u64>>,
    m_r: Vec<Vec<u64>>,
    c_l: Vec<u64>,
    c_r: Vec<u64>,
}

fn make_prg(nonce: [u64; 2], block_counter: u64) -> StdRng {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&nonce[0].to_le_bytes());
    seed[8..16].copy_from_slice(&nonce[1].to_le_bytes());
    seed[16..24].copy_from_slice(&block_counter.to_le_bytes());
    StdRng::from_seed(seed)
}

fn rand_fe(prg: &mut StdRng) -> u64 {
    prg.next_u64() % P
}

fn rand_fe_nonzero(prg: &mut StdRng) -> u64 {
    loop {
        let v = prg.next_u64() % P;
        if v != 0 {
            return v;
        }
    }
}

fn vec_fe(prg: &mut StdRng, n: usize) -> Vec<u64> {
    (0..n).map(|_| rand_fe(prg)).collect()
}

fn companion(alphas: &[u64]) -> Vec<Vec<u64>> {
    let t = alphas.len();
    let mut m = vec![vec![0u64; t]; t];
    for (i, row) in m.iter_mut().enumerate().take(t - 1) {
        row[i + 1] = 1;
    }
    m[t - 1].copy_from_slice(alphas);
    m
}

fn matmul(a: &[Vec<u64>], b: &[Vec<u64>]) -> Vec<Vec<u64>> {
    let t = a.len();
    let mut c = vec![vec![0u64; t]; t];
    for i in 0..t {
        for k in 0..t {
            let aik = a[i][k];
            if aik == 0 {
                continue;
            }
            for j in 0..t {
                c[i][j] = (c[i][j] + aik * b[k][j]) % P;
            }
        }
    }
    c
}

fn identity(t: usize) -> Vec<Vec<u64>> {
    let mut m = vec![vec![0u64; t]; t];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = 1;
    }
    m
}

fn matpow(mut base: Vec<Vec<u64>>, mut exp: usize) -> Vec<Vec<u64>> {
    let t = base.len();
    let mut acc = identity(t);
    while exp > 0 {
        if exp & 1 == 1 {
            acc = matmul(&acc, &base);
        }
        exp >>= 1;
        if exp > 0 {
            base = matmul(&base, &base);
        }
    }
    acc
}

fn sequential_matrix(prg: &mut StdRng, t: usize) -> Vec<Vec<u64>> {
    let alphas: Vec<u64> = (0..t).map(|_| rand_fe_nonzero(prg)).collect();
    matpow(companion(&alphas), t)
}

fn generate_layers(params: PastaParams, nonce: [u64; 2], block_counter: u64) -> Vec<Layer> {
    let mut prg = make_prg(nonce, block_counter);
    let t = params.t;

    (0..=params.rounds)
        .map(|_| Layer {
            m_l: sequential_matrix(&mut prg, t),
            m_r: sequential_matrix(&mut prg, t),
            c_l: vec_fe(&mut prg, t),
            c_r: vec_fe(&mut prg, t),
        })
        .collect()
}

fn matvec(m: &[Vec<u64>], x: &[u64]) -> Vec<u64> {
    m.iter()
        .map(|row| {
            let mut acc = 0u64;
            for (mij, xj) in row.iter().zip(x) {
                acc = (acc + mij * xj) % P;
            }
            acc
        })
        .collect()
}

fn affine(state: &[u64], layer: &Layer, t: usize) -> Vec<u64> {
    let (x_l, x_r) = state.split_at(t);
    let mut u_l = matvec(&layer.m_l, x_l);
    let mut u_r = matvec(&layer.m_r, x_r);
    for i in 0..t {
        u_l[i] = addm(u_l[i], layer.c_l[i]);
        u_r[i] = addm(u_r[i], layer.c_r[i]);
    }

    let mut out = vec![0u64; 2 * t];
    for i in 0..t {
        out[i] = addm(addm(u_l[i], u_l[i]), u_r[i]);
        out[t + i] = addm(u_l[i], addm(u_r[i], u_r[i]));
    }
    out
}

fn feistel(state: &[u64], t: usize) -> Vec<u64> {
    let mut out = state.to_vec();
    for branch in 0..2 {
        let base = branch * t;

        for l in (1..t).rev() {
            let sq = mulm(state[base + l - 1], state[base + l - 1]);
            out[base + l] = addm(state[base + l], sq);
        }
    }
    out
}

fn cube(state: &[u64]) -> Vec<u64> {
    state
        .iter()
        .map(|&x| {
            let x2 = mulm(x, x);
            mulm(x2, x)
        })
        .collect()
}

fn permutation(key: &[u64], layers: &[Layer], params: PastaParams) -> Vec<u64> {
    let t = params.t;
    let mut state = affine(key, &layers[0], t);
    for k in 1..=params.rounds {
        state = if k < params.rounds {
            feistel(&state, t)
        } else {
            cube(&state)
        };
        state = affine(&state, &layers[k], t);
    }
    state
}

pub fn keystream_block(
    key: &[u64],
    nonce: [u64; 2],
    block_counter: u64,
    params: PastaParams,
) -> Vec<u64> {
    assert_eq!(
        key.len(),
        2 * params.t,
        "Pasta key must be 2t field elements"
    );
    let layers = generate_layers(params, nonce, block_counter);
    let full = permutation(key, &layers, params);
    full[..params.t].to_vec()
}

pub fn keystream(key: &[u64], nonce: [u64; 2], n: usize, params: PastaParams) -> Vec<u64> {
    let mut out = Vec::with_capacity(n);
    let blocks = n.div_ceil(params.t);
    for b in 0..blocks {
        out.extend(keystream_block(key, nonce, b as u64, params));
    }
    out.truncate(n);
    out
}

pub fn encrypt(key: &[u64], msg: &[u64], nonce: [u64; 2], params: PastaParams) -> Vec<u64> {
    let ks = keystream(key, nonce, msg.len(), params);
    msg.iter().zip(&ks).map(|(&m, &z)| addm(m % P, z)).collect()
}

pub fn decrypt(key: &[u64], cipher: &[u64], nonce: [u64; 2], params: PastaParams) -> Vec<u64> {
    let ks = keystream(key, nonce, cipher.len(), params);
    cipher
        .iter()
        .zip(&ks)
        .map(|(&c, &z)| subm(c % P, z))
        .collect()
}

#[cfg(feature = "bfv")]
pub use homomorphic::PastaBfv;

#[cfg(feature = "bfv")]
mod homomorphic {
    use super::{generate_layers, Layer, PastaParams, P};
    use crate::circuit::ThresholdCircuit;
    use anyhow::Result;
    use fhe::bfv::{
        BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey,
        EvaluationKeyBuilder, Plaintext, RelinearizationKey, SecretKey,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn anyize<E: std::fmt::Debug>(e: E) -> anyhow::Error {
        anyhow::anyhow!("fhe (pasta): {e:?}")
    }

    fn secure_degree_128(total_q_bits: usize, min_degree: usize) -> Result<usize> {
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
            "no 128-bit-secure SIMD degree for a {total_q_bits}-bit modulus chain \
             (p=65537 caps the SIMD degree at 32768, max ~881 bits); reduce rounds \
             or SOP depth, or use Pasta-3"
        )
    }

    pub struct PastaBfv {
        params: PastaParams,
        bfv: Arc<BfvParameters>,
        sk: SecretKey,
        rk: RelinearizationKey,
        ek: EvaluationKey,
        degree: usize,
        cols: usize,
        seg: usize,
        lanes: usize,
        t1: usize,
        t2: usize,
        lane_mask: Plaintext,
        fmask: Plaintext,
        native_left: bool,
    }

    impl PastaBfv {
        pub fn new(params: PastaParams, degree: usize) -> Result<Self> {
            Self::new_with_sop(params, degree, 0)
        }

        fn moduli_count(params: PastaParams, sop_levels: usize) -> usize {
            4 + 3 * params.rounds + sop_levels
        }

        pub fn new_secure(params: PastaParams, sop_levels: usize) -> Result<Self> {
            let total_q_bits = 50 * Self::moduli_count(params, sop_levels);
            let min_degree = (4 * params.t).next_power_of_two();
            let degree = secure_degree_128(total_q_bits, min_degree)?;
            Self::new_with_sop(params, degree, sop_levels)
        }

        pub fn new_with_sop(params: PastaParams, degree: usize, sop_levels: usize) -> Result<Self> {
            let t = params.t;
            let cols = degree / 2;
            let seg = 2 * t;
            assert!(seg <= cols, "need degree >= 4t for the [x|x] replication");
            let lanes = cols / seg;

            let t1 = (t as f64).sqrt().ceil() as usize;
            let t2 = t.div_ceil(t1);

            let moduli = vec![50usize; Self::moduli_count(params, sop_levels)];
            let bfv = BfvParametersBuilder::new()
                .set_degree(degree)
                .set_plaintext_modulus(P)
                .set_moduli_sizes(&moduli)
                .build_arc()
                .map_err(anyize)?;
            let mut rng = rand_bfv::rng();
            let sk = SecretKey::random(&bfv, &mut rng);
            let rk = RelinearizationKey::new(&sk, &mut rng).map_err(anyize)?;

            let mut amts: BTreeSet<usize> = BTreeSet::new();
            for j in 1..t1 {
                amts.insert(j);
            }
            for i in 1..t2 {
                amts.insert(i * t1);
            }
            amts.insert(cols - t);
            amts.insert(cols - 1);
            amts.insert(1);
            for a in amts.iter().copied().collect::<Vec<_>>() {
                amts.insert(cols - a);
            }
            let mut ekb = EvaluationKeyBuilder::new(&sk).map_err(anyize)?;
            ekb.enable_row_rotation().map_err(anyize)?;
            for &a in &amts {
                ekb.enable_column_rotation(a).map_err(anyize)?;
            }
            let ek = ekb.build(&mut rng).map_err(anyize)?;

            let mut lane_slots = vec![0u64; degree];
            let mut fmask_slots = vec![0u64; degree];
            for s in 0..lanes {
                let base = s * seg;
                for o in 0..t {
                    lane_slots[base + o] = 1;
                    lane_slots[cols + base + o] = 1;
                }
                for o in 1..t {
                    fmask_slots[base + o] = 1;
                    fmask_slots[cols + base + o] = 1;
                }
            }
            let lane_mask =
                Plaintext::try_encode(&lane_slots, Encoding::simd(), &bfv).map_err(anyize)?;
            let fmask =
                Plaintext::try_encode(&fmask_slots, Encoding::simd(), &bfv).map_err(anyize)?;

            let mut me = Self {
                params,
                bfv,
                sk,
                rk,
                ek,
                degree,
                cols,
                seg,
                lanes,
                t1,
                t2,
                lane_mask,
                fmask,
                native_left: true,
            };
            me.native_left = me.probe_direction()?;
            Ok(me)
        }

        pub fn lanes(&self) -> usize {
            self.lanes
        }

        fn encode_slots(&self, slots: &[u64]) -> Result<Plaintext> {
            Plaintext::try_encode(slots, Encoding::simd(), &self.bfv).map_err(anyize)
        }

        pub fn pack_key(&self, key_l: &[u64], key_r: &[u64]) -> Result<Ciphertext> {
            let mut slots = vec![0u64; self.degree];
            for s in 0..self.lanes {
                let base = s * self.seg;
                slots[base..base + key_l.len()].copy_from_slice(key_l);
                slots[self.cols + base..self.cols + base + key_r.len()].copy_from_slice(key_r);
            }
            let pt = self.encode_slots(&slots)?;
            let mut rng = rand_bfv::rng();
            self.sk.try_encrypt(&pt, &mut rng).map_err(anyize)
        }

        pub fn unpack(&self, ct: &Ciphertext) -> Result<Vec<u64>> {
            let pt = self.sk.try_decrypt(ct).map_err(anyize)?;
            Vec::<u64>::try_decode(&pt, Encoding::simd()).map_err(anyize)
        }

        pub fn keystream_words(&self, ct: &Ciphertext) -> Result<Vec<u64>> {
            Ok(self.unpack(ct)?[..self.params.t].to_vec())
        }

        fn probe_direction(&self) -> Result<bool> {
            let mut slots = vec![0u64; self.degree];
            for (i, s) in slots[..self.cols].iter_mut().enumerate() {
                *s = i as u64;
            }
            let pt = self.encode_slots(&slots)?;
            let mut rng = rand_bfv::rng();
            let ct: Ciphertext = self.sk.try_encrypt(&pt, &mut rng).map_err(anyize)?;
            let rot = self.ek.rotates_columns_by(&ct, 1).map_err(anyize)?;
            let d = self.unpack(&rot)?;
            Ok(d[0] == 1)
        }

        fn rotl(&self, ct: &Ciphertext, k: usize) -> Result<Ciphertext> {
            let k = k % self.cols;
            if k == 0 {
                return Ok(ct.clone());
            }
            let amt = if self.native_left { k } else { self.cols - k };
            self.ek.rotates_columns_by(ct, amt).map_err(anyize)
        }

        fn mul_ct(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
            let mut p = a * b;
            self.rk.relinearizes(&mut p).map_err(anyize)?;
            Ok(p)
        }

        fn replicate(&self, ct: &Ciphertext) -> Result<Ciphertext> {
            let shifted = self.rotl(ct, self.cols - self.params.t)?;
            Ok(ct + &shifted)
        }

        fn diag_plaintext(
            &self,
            segs: &[Vec<Layer>],
            round: usize,
            i: usize,
            k: usize,
        ) -> Result<Plaintext> {
            let t = self.params.t;
            let mut slots = vec![0u64; self.degree];
            for (s, layers) in segs.iter().enumerate() {
                let layer = &layers[round];
                let base = s * self.seg + i * self.t1;
                for idx in 0..t {
                    let col = (idx + k) % t;
                    slots[base + idx] = layer.m_l[idx][col];
                    slots[self.cols + base + idx] = layer.m_r[idx][col];
                }
            }
            self.encode_slots(&slots)
        }

        fn matvec(
            &self,
            rep: &Ciphertext,
            segs: &[Vec<Layer>],
            round: usize,
        ) -> Result<Ciphertext> {
            let t = self.params.t;

            let mut babies = Vec::with_capacity(self.t1);
            for j in 0..self.t1 {
                babies.push(self.rotl(rep, j)?);
            }
            let mut u: Option<Ciphertext> = None;
            for i in 0..self.t2 {
                let mut inner: Option<Ciphertext> = None;
                for (j, baby) in babies.iter().enumerate() {
                    let k = i * self.t1 + j;
                    if k >= t {
                        continue;
                    }
                    let d = self.diag_plaintext(segs, round, i, k)?;
                    let term = baby * &d;
                    inner = Some(match inner {
                        Some(a) => &a + &term,
                        None => term,
                    });
                }
                if let Some(inner) = inner {
                    let giant = self.rotl(&inner, i * self.t1)?;
                    u = Some(match u {
                        Some(a) => &a + &giant,
                        None => giant,
                    });
                }
            }
            u.ok_or_else(|| anyhow::anyhow!("empty matvec"))
        }

        fn affine(
            &self,
            state: &Ciphertext,
            segs: &[Vec<Layer>],
            round: usize,
        ) -> Result<Ciphertext> {
            let rep = self.replicate(state)?;
            let mv = &self.matvec(&rep, segs, round)? * &self.lane_mask;
            let u = &mv + &self.const_plaintext(segs, round)?;
            let swap = self.ek.rotates_rows(&u).map_err(anyize)?;

            Ok(&(&u + &u) + &swap)
        }

        fn const_plaintext(&self, segs: &[Vec<Layer>], round: usize) -> Result<Plaintext> {
            let t = self.params.t;
            let mut slots = vec![0u64; self.degree];
            for (s, layers) in segs.iter().enumerate() {
                let layer = &layers[round];
                let base = s * self.seg;
                slots[base..base + t].copy_from_slice(&layer.c_l);
                slots[self.cols + base..self.cols + base + t].copy_from_slice(&layer.c_r);
            }
            self.encode_slots(&slots)
        }

        fn feistel(&self, ct: &Ciphertext) -> Result<Ciphertext> {
            let shifted = self.rotl(ct, self.cols - 1)?;
            let masked = &shifted * &self.fmask;
            let sq = self.mul_ct(&masked, &masked)?;
            Ok(ct + &sq)
        }

        fn cube(&self, ct: &Ciphertext) -> Result<Ciphertext> {
            let sq = self.mul_ct(ct, ct)?;
            self.mul_ct(&sq, ct)
        }

        pub fn keystream_blocks(
            &self,
            key: &Ciphertext,
            nonce: [u64; 2],
            blocks: &[u64],
        ) -> Result<Ciphertext> {
            assert!(
                !blocks.is_empty() && blocks.len() <= self.lanes,
                "blocks must be 1..={} (lanes)",
                self.lanes
            );
            let segs: Vec<Vec<Layer>> = blocks
                .iter()
                .map(|&b| generate_layers(self.params, nonce, b))
                .collect();
            let mut state = self.affine(key, &segs, 0)?;
            for r in 1..=self.params.rounds {
                state = if r < self.params.rounds {
                    self.feistel(&state)?
                } else {
                    self.cube(&state)?
                };
                state = self.affine(&state, &segs, r)?;
            }
            Ok(state)
        }

        pub fn keystream_block(
            &self,
            key: &Ciphertext,
            nonce: [u64; 2],
            block_counter: u64,
        ) -> Result<Ciphertext> {
            self.keystream_blocks(key, nonce, &[block_counter])
        }

        pub fn transcipher_recover_blocks(
            &self,
            key: &Ciphertext,
            nonce: [u64; 2],
            blocks: &[u64],
            words: &[&[u64]],
        ) -> Result<Ciphertext> {
            assert_eq!(blocks.len(), words.len(), "one word slice per block");
            let ks = self.keystream_blocks(key, nonce, blocks)?;
            let mut slots = vec![0u64; self.degree];
            for (s, cw) in words.iter().enumerate() {
                let base = s * self.seg;
                slots[base..base + cw.len()].copy_from_slice(cw);
            }
            let c = self.encode_slots(&slots)?;
            Ok(-&(&ks - &c))
        }

        pub fn transcipher_recover(
            &self,
            key: &Ciphertext,
            nonce: [u64; 2],
            block_counter: u64,
            cipher_words: &[u64],
        ) -> Result<Ciphertext> {
            self.transcipher_recover_blocks(key, nonce, &[block_counter], &[cipher_words])
        }

        fn and_tree(&self, factors: &[Ciphertext]) -> Result<Ciphertext> {
            let mut level: Vec<Ciphertext> = factors.to_vec();
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                let mut i = 0;
                while i < level.len() {
                    if i + 1 < level.len() {
                        next.push(self.mul_ct(&level[i], &level[i + 1])?);
                    } else {
                        next.push(level[i].clone());
                    }
                    i += 2;
                }
                level = next;
            }
            level
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty AND term"))
        }

        fn or_tree(&self, terms: Vec<Ciphertext>) -> Result<Ciphertext> {
            let mut level = terms;
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                let mut i = 0;
                while i < level.len() {
                    if i + 1 < level.len() {
                        let ab = self.mul_ct(&level[i], &level[i + 1])?;
                        let sum = &level[i] + &level[i + 1];
                        next.push(&sum - &ab);
                    } else {
                        next.push(level[i].clone());
                    }
                    i += 2;
                }
                level = next;
            }
            level
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty SOP"))
        }

        pub fn evaluate_sop(
            &self,
            party_cts: &[Ciphertext],
            circuit: &ThresholdCircuit,
        ) -> Result<Ciphertext> {
            let mut term_cts = Vec::with_capacity(circuit.terms.len());
            for term in &circuit.terms {
                let factors: Vec<Ciphertext> = term.iter().map(|&p| party_cts[p].clone()).collect();
                term_cts.push(self.and_tree(&factors)?);
            }
            self.or_tree(term_cts)
        }

        pub fn decrypt_bits(&self, ct: &Ciphertext, n: usize) -> Result<Vec<bool>> {
            self.decrypt_lane_bits(ct, &[n])
        }

        pub fn decrypt_lane_bits(&self, ct: &Ciphertext, lens: &[usize]) -> Result<Vec<bool>> {
            let all = self.unpack(ct)?;
            let mut out = Vec::with_capacity(lens.iter().sum());
            for (s, &len) in lens.iter().enumerate() {
                let base = s * self.seg;
                out.extend(all[base..base + len].iter().map(|&v| (v & 1) == 1));
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::cipher::bfv::pasta::{keystream_block, PastaParams};

        fn check(t: usize, rounds: usize) {
            let params = PastaParams { t, rounds };
            let key: Vec<u64> = (0..2 * t as u64).map(|i| (i * 7 + 1) % P).collect();
            let nonce = [3u64, 9u64];
            let want = keystream_block(&key, nonce, 0, params);

            let pb = PastaBfv::new(params, 8192).expect("pasta bfv setup");
            let key_ct = pb.pack_key(&key[..t], &key[t..]).unwrap();
            let ks_ct = pb
                .keystream_block(&key_ct, nonce, 0)
                .expect("homomorphic keystream");
            let got = pb.keystream_words(&ks_ct).unwrap();
            assert_eq!(
                got, want,
                "homomorphic Pasta (t={t}, r={rounds}) must match plaintext"
            );
        }

        #[test]
        fn pasta_bfv_keystream_matches_plaintext() {
            check(4, 2);
        }

        #[test]
        fn pasta_bfv_bsgs_padded_split_matches_plaintext() {
            check(5, 2);
        }

        #[test]
        fn pasta_bfv_transcipher_then_sop_matches_plaintext() {
            use crate::cipher::bfv::pasta::encrypt;
            use crate::circuit::ThresholdCircuit;

            let params = PastaParams { t: 4, rounds: 2 };
            let circuit = ThresholdCircuit::new(3, 2);
            let filters = vec![
                vec![true, true, false, false],
                vec![true, false, true, false],
                vec![true, true, true, false],
            ];
            let want = circuit.evaluate_plaintext(&filters);

            let sop_levels = 3;
            let pb = PastaBfv::new_with_sop(params, 8192, sop_levels).unwrap();

            let nonce = [11u64, 22u64];
            let recovered: Vec<_> = filters
                .iter()
                .enumerate()
                .map(|(i, bits)| {
                    let key: Vec<u64> = (0..2 * params.t as u64)
                        .map(|w| (w * 7 + 1 + i as u64) % P)
                        .collect();
                    let msg: Vec<u64> = bits.iter().map(|&b| b as u64).collect();
                    let c = encrypt(&key, &msg, nonce, params);
                    let key_ct = pb.pack_key(&key[..params.t], &key[params.t..]).unwrap();
                    pb.transcipher_recover(&key_ct, nonce, 0, &c).unwrap()
                })
                .collect();

            let result = pb.evaluate_sop(&recovered, &circuit).unwrap();
            let got = pb.decrypt_bits(&result, params.t).unwrap();
            assert_eq!(
                got, want,
                "BFV transcipher→SOP must match plaintext circuit"
            );
        }

        #[test]
        fn pasta_bfv_multilane_keystream_matches_plaintext() {
            let params = PastaParams { t: 4, rounds: 2 };
            let key: Vec<u64> = (0..2 * params.t as u64).map(|i| (i * 7 + 1) % P).collect();
            let nonce = [3u64, 9u64];
            let pb = PastaBfv::new(params, 8192).unwrap();
            assert!(pb.lanes() >= 4, "degree 8192, t=4 should give many lanes");
            let key_ct = pb.pack_key(&key[..params.t], &key[params.t..]).unwrap();

            let blocks = [0u64, 1, 2, 5];
            let ks_ct = pb.keystream_blocks(&key_ct, nonce, &blocks).unwrap();
            let all = pb.unpack(&ks_ct).unwrap();
            let seg = 2 * params.t;
            for (s, &b) in blocks.iter().enumerate() {
                let want = keystream_block(&key, nonce, b, params);
                let got = all[s * seg..s * seg + params.t].to_vec();
                assert_eq!(got, want, "lane {s} (block {b}) keystream mismatch");
            }
        }

        #[test]
        fn pasta_bfv_multilane_transcipher_sop_matches_plaintext() {
            use crate::cipher::bfv::pasta::encrypt;
            use crate::circuit::ThresholdCircuit;

            let params = PastaParams { t: 4, rounds: 2 };
            let t = params.t;
            let circuit = ThresholdCircuit::new(3, 2);
            let filters = vec![
                vec![true, true, false, false, true, false, true, true],
                vec![true, false, true, false, true, true, false, true],
                vec![true, true, true, false, false, true, true, true],
            ];
            let want = circuit.evaluate_plaintext(&filters);

            let pb = PastaBfv::new_with_sop(params, 8192, 3).unwrap();
            let nonce = [11u64, 22u64];
            let blocks = [0u64, 1u64];
            let recovered: Vec<_> = filters
                .iter()
                .enumerate()
                .map(|(i, bits)| {
                    let key: Vec<u64> = (0..2 * t as u64)
                        .map(|w| (w * 7 + 1 + i as u64) % P)
                        .collect();
                    let msg: Vec<u64> = bits.iter().map(|&b| b as u64).collect();
                    let c = encrypt(&key, &msg, nonce, params);
                    let key_ct = pb.pack_key(&key[..t], &key[t..]).unwrap();
                    let words: Vec<&[u64]> = vec![&c[0..t], &c[t..2 * t]];
                    pb.transcipher_recover_blocks(&key_ct, nonce, &blocks, &words)
                        .unwrap()
                })
                .collect();

            let result = pb.evaluate_sop(&recovered, &circuit).unwrap();
            let got = pb.decrypt_lane_bits(&result, &[t, t]).unwrap();
            assert_eq!(
                got, want,
                "multi-lane transcipher→SOP must match plaintext circuit"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_of(params: PastaParams) -> Vec<u64> {
        (0..2 * params.t as u64).map(|i| (i * 7 + 1) % P).collect()
    }

    #[test]
    fn pasta4_encrypt_decrypt_roundtrips() {
        let p = PASTA4;
        let key = key_of(p);
        let nonce = [0u64; 2];
        let msg: Vec<u64> = (0..100u64).map(|i| (i * 13) % P).collect();
        let c = encrypt(&key, &msg, nonce, p);
        assert_ne!(c, msg, "ciphertext should differ from plaintext");
        let m = decrypt(&key, &c, nonce, p);
        assert_eq!(m, msg, "decrypt(encrypt(m)) must equal m");
    }

    #[test]
    fn pasta4_keystream_is_deterministic() {
        let p = PASTA4;
        let key = key_of(p);
        let a = keystream(&key, [1, 2], 64, p);
        let b = keystream(&key, [1, 2], 64, p);
        assert_eq!(a, b);
        let c = keystream(&key, [1, 3], 64, p);
        assert_ne!(a, c, "different nonce → different keystream");
    }

    #[test]
    fn bit_valued_messages_roundtrip() {
        let p = PASTA4;
        let key = key_of(p);
        let bits: Vec<u64> = (0..50u64).map(|i| i % 2).collect();
        let c = encrypt(&key, &bits, [9, 9], p);
        let r = decrypt(&key, &c, [9, 9], p);
        assert_eq!(r, bits);
    }

    #[test]
    #[ignore = "Pasta-3 (t=128) matrix powers are slow in plain; run explicitly"]
    fn pasta3_roundtrips() {
        let p = PASTA3;
        let key = key_of(p);
        let msg: Vec<u64> = (0..256u64).map(|i| (i * 3 + 5) % P).collect();
        let c = encrypt(&key, &msg, [0, 0], p);
        let m = decrypt(&key, &c, [0, 0], p);
        assert_eq!(m, msg);
    }
}
