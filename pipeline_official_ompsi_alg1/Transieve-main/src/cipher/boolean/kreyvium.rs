use tfhe::boolean::prelude::*;

use super::{EncBit, TranscipherDecrypt};

const A_LEN: usize = 93;
const B_LEN: usize = 84;
const C_LEN: usize = 111;
const KSTAR_LEN: usize = 128;
const IVSTAR_LEN: usize = 128;
const WARMUP_CYCLES: usize = 4 * 288;

pub struct Kreyvium128;

impl TranscipherDecrypt for Kreyvium128 {
    const BLOCK_BITS: usize = 128;
    const KEY_BITS: usize = 128;
    const NAME: &'static str = "Kreyvium-128";

    const PBS_PER_OUTPUT_BIT: f64 = 3.0;

    const MULTIPLICATIVE_DEPTH: usize = 1;

    const FIXED_INIT_PBS: usize = 1152 * 3;

    fn decrypt_block(sk: &ServerKey, enc_key: &[EncBit], cipher_block: &[bool]) -> Vec<EncBit> {
        assert_eq!(enc_key.len(), Self::KEY_BITS);
        assert_eq!(cipher_block.len(), Self::BLOCK_BITS);

        let iv = [false; 128];

        let mut state = State::init(sk, enc_key, &iv);

        for _ in 0..WARMUP_CYCLES {
            state.step(sk);
        }

        let mut plaintext = Vec::with_capacity(Self::BLOCK_BITS);
        for &c_bit in cipher_block {
            let z = state.step(sk);
            plaintext.push(xor_const(sk, &z, c_bit));
        }
        plaintext
    }
}

fn xor_const(sk: &ServerKey, x: &EncBit, c: bool) -> EncBit {
    if c {
        sk.not(x)
    } else {
        x.clone()
    }
}

struct State {
    a: Vec<EncBit>,
    b: Vec<EncBit>,
    c: Vec<EncBit>,
    k_star: Vec<EncBit>,
    iv_star: Vec<bool>,
}

impl State {
    fn init(sk: &ServerKey, key: &[EncBit], iv: &[bool]) -> Self {
        let mut a = Vec::with_capacity(A_LEN);
        for i in 0..A_LEN {
            a.push(key[i].clone());
        }

        let mut b = Vec::with_capacity(B_LEN);
        for i in 0..B_LEN {
            b.push(trivial(sk, iv[i]));
        }

        let mut c = Vec::with_capacity(C_LEN);

        for i in 84..128 {
            c.push(trivial(sk, iv[i]));
        }
        for _ in 0..66 {
            c.push(trivial(sk, true));
        }
        c.push(trivial(sk, false));
        debug_assert_eq!(c.len(), C_LEN);

        let mut k_star = Vec::with_capacity(KSTAR_LEN);
        for i in 0..KSTAR_LEN {
            k_star.push(key[i].clone());
        }

        let mut iv_star = Vec::with_capacity(IVSTAR_LEN);
        for i in 0..IVSTAR_LEN {
            iv_star.push(iv[i]);
        }

        State {
            a,
            b,
            c,
            k_star,
            iv_star,
        }
    }

    fn step(&mut self, sk: &ServerKey) -> EncBit {
        let a = |i: usize| &self.a[i - 1];
        let b = |i: usize| &self.b[i - 1];
        let c = |i: usize| &self.c[i - 1];

        let and_a = sk.and(a(91), a(92));
        let mut t1 = sk.xor(a(66), a(93));
        t1 = sk.xor(&t1, &and_a);
        t1 = sk.xor(&t1, b(78));

        let iv_out = self.iv_star[IVSTAR_LEN - 1];
        let t1 = xor_const(sk, &t1, iv_out);

        let and_b = sk.and(b(82), b(83));
        let mut t2 = sk.xor(b(69), b(84));
        t2 = sk.xor(&t2, &and_b);
        t2 = sk.xor(&t2, c(87));

        let and_c = sk.and(c(109), c(110));
        let mut t3 = sk.xor(c(66), c(111));
        t3 = sk.xor(&t3, &and_c);
        t3 = sk.xor(&t3, a(69));

        let k_out = self.k_star[KSTAR_LEN - 1].clone();
        let t3 = sk.xor(&t3, &k_out);

        let z = {
            let zz = sk.xor(&t1, &t2);
            sk.xor(&zz, &t3)
        };

        rotate_in(&mut self.a, t3);

        rotate_in(&mut self.b, t1);

        rotate_in(&mut self.c, t2);

        rotate_in(&mut self.k_star, k_out);
        let iv_in = iv_out;
        rotate_in_const(&mut self.iv_star, iv_in);

        z
    }
}

fn trivial(sk: &ServerKey, b: bool) -> EncBit {
    sk.trivial_encrypt(b)
}

pub fn decrypt_stream(sk: &ServerKey, enc_key: &[EncBit], cipher: &[bool]) -> Vec<EncBit> {
    let (out, _) = decrypt_stream_timed(sk, enc_key, cipher);
    out
}

pub fn decrypt_stream_timed(
    sk: &ServerKey,
    enc_key: &[EncBit],
    cipher: &[bool],
) -> (Vec<EncBit>, super::DecryptTimings) {
    use std::time::Instant;
    assert_eq!(enc_key.len(), 128);
    let iv = [false; 128];

    let t_init = Instant::now();
    let mut state = State::init(sk, enc_key, &iv);
    for _ in 0..WARMUP_CYCLES {
        state.step(sk);
    }
    let init_s = t_init.elapsed().as_secs_f64();

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    for &c_bit in cipher {
        let z = state.step(sk);
        out.push(xor_const(sk, &z, c_bit));
    }
    let per_bit_total_s = t_per.elapsed().as_secs_f64();

    (
        out,
        super::DecryptTimings {
            init_s,
            per_bit_total_s,
            bits: cipher.len(),
        },
    )
}

fn rotate_in(reg: &mut Vec<EncBit>, new: EncBit) {
    reg.pop();
    reg.insert(0, new);
}

fn rotate_in_const(reg: &mut Vec<bool>, new: bool) {
    reg.pop();
    reg.insert(0, new);
}

pub fn keystream_plain(key: &[bool; 128], iv: &[bool; 128], n: usize) -> Vec<bool> {
    let mut a: Vec<bool> = (0..A_LEN).map(|i| key[i]).collect();
    let mut b: Vec<bool> = (0..B_LEN).map(|i| iv[i]).collect();
    let mut c: Vec<bool> = Vec::with_capacity(C_LEN);
    for i in 84..128 {
        c.push(iv[i]);
    }
    for _ in 0..66 {
        c.push(true);
    }
    c.push(false);
    let mut k_star: Vec<bool> = key.to_vec();
    let mut iv_star: Vec<bool> = iv.to_vec();

    let total = WARMUP_CYCLES + n;
    let mut out = Vec::with_capacity(n);
    for cycle in 0..total {
        let a91 = a[90];
        let a92 = a[91];
        let a66 = a[65];
        let a93 = a[92];
        let a69 = a[68];
        let b78 = b[77];
        let b69 = b[68];
        let b84 = b[83];
        let b82 = b[81];
        let b83 = b[82];
        let c66 = c[65];
        let c111 = c[110];
        let c109 = c[108];
        let c110 = c[109];
        let c87 = c[86];
        let iv_out = iv_star[IVSTAR_LEN - 1];
        let k_out = k_star[KSTAR_LEN - 1];

        let t1 = a66 ^ a93 ^ (a91 & a92) ^ b78 ^ iv_out;
        let t2 = b69 ^ b84 ^ (b82 & b83) ^ c87;
        let t3 = c66 ^ c111 ^ (c109 & c110) ^ a69 ^ k_out;
        let z = t1 ^ t2 ^ t3;

        if cycle >= WARMUP_CYCLES {
            out.push(z);
        }

        a.pop();
        a.insert(0, t3);
        b.pop();
        b.insert(0, t1);
        c.pop();
        c.insert(0, t2);
        k_star.pop();
        k_star.insert(0, k_out);
        iv_star.pop();
        iv_star.insert(0, iv_out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn fhe_matches_plaintext_keystream() {
        let key_bits: [bool; 128] = std::array::from_fn(|i| i % 3 == 0);
        let iv_bits: [bool; 128] = [false; 128];

        let want = keystream_plain(&key_bits, &iv_bits, 16);
        let cipher_block: Vec<bool> = vec![false; 16];

        let (ck, sk) = gen_keys();
        let enc_key: Vec<EncBit> = key_bits.iter().map(|&b| ck.encrypt(b)).collect();

        let mut cipher = Kreyvium128 {};
        let _ = &mut cipher;

        let mut state = State::init(&sk, &enc_key, &iv_bits);
        for _ in 0..WARMUP_CYCLES {
            state.step(&sk);
        }
        let mut got = Vec::with_capacity(want.len());
        for &c_bit in &cipher_block {
            let z = state.step(&sk);
            got.push(ck.decrypt(&xor_const(&sk, &z, c_bit)));
        }

        assert_eq!(got, want);
    }
}
