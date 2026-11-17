use std::time::Instant;
use tfhe::boolean::prelude::*;

use super::{DecryptTimings, EncBit, TranscipherDecrypt};

pub const NFSR_LEN: usize = 128;
pub const LFSR_LEN: usize = 128;
pub const KEY_BITS: usize = 128;
pub const IV_BITS: usize = 96;
pub const INIT_CYCLES: usize = 256;

const LFSR_TAPS: [usize; 6] = [0, 7, 38, 70, 81, 96];

const NFSR_LINEAR_TAPS: [usize; 5] = [0, 26, 56, 91, 96];

const NFSR_QUAD_TAPS: [(usize, usize); 7] = [
    (3, 67),
    (11, 13),
    (17, 18),
    (27, 59),
    (40, 48),
    (61, 65),
    (68, 84),
];

const NFSR_CUBIC_TAPS: [(usize, usize, usize); 2] = [(22, 24, 25), (70, 78, 82)];

const NFSR_QUARTIC_TAP: (usize, usize, usize, usize) = (88, 92, 93, 95);

const Y_NFSR_TAPS: [usize; 7] = [2, 15, 36, 45, 64, 73, 89];

pub struct Grain128a;

impl TranscipherDecrypt for Grain128a {
    const BLOCK_BITS: usize = 128;
    const KEY_BITS: usize = 128;
    const NAME: &'static str = "Grain-128a";

    const PBS_PER_OUTPUT_BIT: f64 = 20.0;

    const MULTIPLICATIVE_DEPTH: usize = 3;

    const FIXED_INIT_PBS: usize = INIT_CYCLES * 20;

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
    assert_eq!(enc_key.len(), KEY_BITS);
    let iv = [false; IV_BITS];

    let t_init = Instant::now();
    let mut state = State::init(sk, enc_key, &iv);
    for _ in 0..INIT_CYCLES {
        state.step(sk, true);
    }
    let init_s = t_init.elapsed().as_secs_f64();

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    for &c_bit in cipher {
        let z = state.step(sk, false);
        out.push(xor_const(sk, &z, c_bit));
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

struct State {
    nfsr: Vec<EncBit>,
    lfsr: Vec<EncBit>,
}

impl State {
    fn init(sk: &ServerKey, enc_key: &[EncBit], iv: &[bool]) -> Self {
        let nfsr: Vec<EncBit> = enc_key.to_vec();

        let mut lfsr: Vec<EncBit> = Vec::with_capacity(LFSR_LEN);
        for i in 0..IV_BITS {
            lfsr.push(sk.trivial_encrypt(iv[i]));
        }
        for _ in 0..31 {
            lfsr.push(sk.trivial_encrypt(true));
        }
        lfsr.push(sk.trivial_encrypt(false));

        debug_assert_eq!(lfsr.len(), LFSR_LEN);
        State { nfsr, lfsr }
    }

    fn step(&mut self, sk: &ServerKey, init_phase: bool) -> EncBit {
        let y = self.pre_output(sk);
        let lfsr_fb = self.lfsr_feedback(sk);
        let nfsr_fb = self.nfsr_feedback(sk);

        let new_lfsr = if init_phase {
            sk.xor(&lfsr_fb, &y)
        } else {
            lfsr_fb
        };
        let new_nfsr = if init_phase {
            sk.xor(&nfsr_fb, &y)
        } else {
            nfsr_fb
        };

        rotate_in(&mut self.lfsr, new_lfsr);
        rotate_in(&mut self.nfsr, new_nfsr);
        y
    }

    fn pre_output(&self, sk: &ServerKey) -> EncBit {
        let x0 = &self.nfsr[12];
        let x1 = &self.lfsr[8];
        let x2 = &self.lfsr[13];
        let x3 = &self.lfsr[20];
        let x4 = &self.nfsr[95];
        let x5 = &self.lfsr[42];
        let x6 = &self.lfsr[60];
        let x7 = &self.lfsr[79];
        let x8 = &self.lfsr[94];

        let t1 = sk.and(x0, x1);
        let t2 = sk.and(x2, x3);
        let t3 = sk.and(x4, x5);
        let t4 = sk.and(x6, x7);
        let x0x4 = sk.and(x0, x4);
        let t5 = sk.and(&x0x4, x8);

        let mut h = sk.xor(&t1, &t2);
        h = sk.xor(&h, &t3);
        h = sk.xor(&h, &t4);
        h = sk.xor(&h, &t5);

        let mut y = sk.xor(&h, &self.lfsr[93]);
        for &j in &Y_NFSR_TAPS {
            y = sk.xor(&y, &self.nfsr[j]);
        }
        y
    }

    fn lfsr_feedback(&self, sk: &ServerKey) -> EncBit {
        let mut acc: Option<EncBit> = None;
        for &t in &LFSR_TAPS {
            acc = Some(match acc {
                None => self.lfsr[t].clone(),
                Some(a) => sk.xor(&a, &self.lfsr[t]),
            });
        }
        acc.expect("LFSR has at least one tap")
    }

    fn nfsr_feedback(&self, sk: &ServerKey) -> EncBit {
        let mut acc = sk.xor(&self.lfsr[0], &self.nfsr[NFSR_LINEAR_TAPS[0]]);
        for &t in &NFSR_LINEAR_TAPS[1..] {
            acc = sk.xor(&acc, &self.nfsr[t]);
        }

        for &(a, b) in &NFSR_QUAD_TAPS {
            let m = sk.and(&self.nfsr[a], &self.nfsr[b]);
            acc = sk.xor(&acc, &m);
        }

        for &(a, b, c) in &NFSR_CUBIC_TAPS {
            let ab = sk.and(&self.nfsr[a], &self.nfsr[b]);
            let m = sk.and(&ab, &self.nfsr[c]);
            acc = sk.xor(&acc, &m);
        }

        {
            let (a, b, c, d) = NFSR_QUARTIC_TAP;
            let ab = sk.and(&self.nfsr[a], &self.nfsr[b]);
            let abc = sk.and(&ab, &self.nfsr[c]);
            let m = sk.and(&abc, &self.nfsr[d]);
            acc = sk.xor(&acc, &m);
        }

        acc
    }
}

fn rotate_in(reg: &mut Vec<EncBit>, new: EncBit) {
    reg.rotate_left(1);
    *reg.last_mut().expect("non-empty register") = new;
}

fn xor_const(sk: &ServerKey, x: &EncBit, c: bool) -> EncBit {
    if c {
        sk.not(x)
    } else {
        x.clone()
    }
}

pub fn keystream_plain(key: &[bool; 128], iv: &[bool; 96], n: usize) -> Vec<bool> {
    let mut nfsr: Vec<bool> = key.to_vec();
    let mut lfsr: Vec<bool> = Vec::with_capacity(LFSR_LEN);
    for i in 0..IV_BITS {
        lfsr.push(iv[i]);
    }
    for _ in 0..31 {
        lfsr.push(true);
    }
    lfsr.push(false);

    for _ in 0..INIT_CYCLES {
        let y = plain_pre_output(&nfsr, &lfsr);
        let lfsr_fb = plain_lfsr_feedback(&lfsr);
        let nfsr_fb = plain_nfsr_feedback(&nfsr, &lfsr);
        let new_lfsr = lfsr_fb ^ y;
        let new_nfsr = nfsr_fb ^ y;
        lfsr.rotate_left(1);
        *lfsr.last_mut().unwrap() = new_lfsr;
        nfsr.rotate_left(1);
        *nfsr.last_mut().unwrap() = new_nfsr;
    }

    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let y = plain_pre_output(&nfsr, &lfsr);
        out.push(y);
        let lfsr_fb = plain_lfsr_feedback(&lfsr);
        let nfsr_fb = plain_nfsr_feedback(&nfsr, &lfsr);
        lfsr.rotate_left(1);
        *lfsr.last_mut().unwrap() = lfsr_fb;
        nfsr.rotate_left(1);
        *nfsr.last_mut().unwrap() = nfsr_fb;
    }
    out
}

fn plain_lfsr_feedback(lfsr: &[bool]) -> bool {
    LFSR_TAPS.iter().fold(false, |a, &t| a ^ lfsr[t])
}

fn plain_nfsr_feedback(nfsr: &[bool], lfsr: &[bool]) -> bool {
    let mut acc = lfsr[0];
    for &t in &NFSR_LINEAR_TAPS {
        acc ^= nfsr[t];
    }
    for &(a, b) in &NFSR_QUAD_TAPS {
        acc ^= nfsr[a] & nfsr[b];
    }
    for &(a, b, c) in &NFSR_CUBIC_TAPS {
        acc ^= nfsr[a] & nfsr[b] & nfsr[c];
    }
    let (a, b, c, d) = NFSR_QUARTIC_TAP;
    acc ^= nfsr[a] & nfsr[b] & nfsr[c] & nfsr[d];
    acc
}

fn plain_pre_output(nfsr: &[bool], lfsr: &[bool]) -> bool {
    let x0 = nfsr[12];
    let x1 = lfsr[8];
    let x2 = lfsr[13];
    let x3 = lfsr[20];
    let x4 = nfsr[95];
    let x5 = lfsr[42];
    let x6 = lfsr[60];
    let x7 = lfsr[79];
    let x8 = lfsr[94];
    let h = (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
    let mut y = h ^ lfsr[93];
    for &j in &Y_NFSR_TAPS {
        y ^= nfsr[j];
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    fn hex_to_bits_msb(hex: &str) -> Vec<bool> {
        let mut bits = Vec::with_capacity(hex.len() * 4);
        for c in hex.chars() {
            let nyb = c.to_digit(16).expect("hex digit");
            for shift in (0..4).rev() {
                bits.push(((nyb >> shift) & 1) == 1);
            }
        }
        bits
    }

    #[test]
    fn keystream_plain_matches_paper_test_vector_1() {
        let key = [false; 128];
        let iv = [false; 96];
        let got = keystream_plain(&key, &iv, 64);
        let want = hex_to_bits_msb("c0207f221660650b");
        assert_eq!(got, want);
    }

    #[test]
    fn keystream_plain_matches_paper_test_vector_2() {
        let key_hex = "0123456789abcdef123456789abcdef0";
        let iv_hex = "0123456789abcdef12345678";
        let key_bits = hex_to_bits_msb(key_hex);
        let iv_bits_vec = hex_to_bits_msb(iv_hex);

        let mut key = [false; 128];
        key.copy_from_slice(&key_bits);
        let mut iv = [false; 96];
        iv.copy_from_slice(&iv_bits_vec);

        assert!(!iv[0], "IV[0] must be 0 for encryption-only mode");

        let got = keystream_plain(&key, &iv, 64);
        let want = hex_to_bits_msb("f88720c13f46e6a4");
        assert_eq!(got, want);
    }

    #[test]
    fn fhe_matches_plaintext_keystream() {
        let key_bits: Vec<bool> = (0..128).map(|i| i % 3 == 0).collect();
        let iv_bits = [false; 96];

        let mut key_arr = [false; 128];
        key_arr.copy_from_slice(&key_bits);
        let want = keystream_plain(&key_arr, &iv_bits, 16);
        let cipher_block: Vec<bool> = vec![false; 16];

        let (ck, sk) = gen_keys();
        let enc_key: Vec<EncBit> = key_bits.iter().map(|&b| ck.encrypt(b)).collect();

        let (enc_out, _) = decrypt_stream_timed(&sk, &enc_key, &cipher_block);
        let got: Vec<bool> = enc_out.iter().map(|c| ck.decrypt(c)).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn plaintext_roundtrip() {
        let key_bits: Vec<bool> = (0..128).map(|i| i % 7 == 3).collect();
        let mut key = [false; 128];
        key.copy_from_slice(&key_bits);
        let iv = [false; 96];
        let plaintext: Vec<bool> = (0..1000).map(|i| i % 3 == 0).collect();

        let ks = keystream_plain(&key, &iv, plaintext.len());
        let cipher: Vec<bool> = plaintext.iter().zip(&ks).map(|(&p, &z)| p ^ z).collect();
        let recovered: Vec<bool> = cipher.iter().zip(&ks).map(|(&c, &z)| c ^ z).collect();
        assert_eq!(plaintext, recovered);
    }
}
