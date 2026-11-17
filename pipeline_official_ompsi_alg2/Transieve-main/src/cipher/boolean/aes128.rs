use std::time::Instant;

use tfhe::boolean::prelude::*;

use super::{EncBit, TranscipherDecrypt};

pub(crate) trait BitEngine {
    type Bit: Clone;
    fn xor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn and(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn xnor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn not(&self, a: &Self::Bit) -> Self::Bit;
    fn constant(&self, v: bool) -> Self::Bit;
}

struct PlainEngine;

impl BitEngine for PlainEngine {
    type Bit = bool;
    #[inline]
    fn xor(&self, a: &bool, b: &bool) -> bool {
        a ^ b
    }
    #[inline]
    fn and(&self, a: &bool, b: &bool) -> bool {
        a & b
    }
    #[inline]
    fn xnor(&self, a: &bool, b: &bool) -> bool {
        !(a ^ b)
    }
    #[inline]
    fn not(&self, a: &bool) -> bool {
        !a
    }
    #[inline]
    fn constant(&self, v: bool) -> bool {
        v
    }
}

struct FheEngine<'a> {
    sk: &'a ServerKey,
}

impl BitEngine for FheEngine<'_> {
    type Bit = Ciphertext;
    #[inline]
    fn xor(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        self.sk.xor(a, b)
    }
    #[inline]
    fn and(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        self.sk.and(a, b)
    }
    #[inline]
    fn xnor(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        self.sk.xnor(a, b)
    }
    #[inline]
    fn not(&self, a: &Ciphertext) -> Ciphertext {
        self.sk.not(a)
    }
    #[inline]
    fn constant(&self, v: bool) -> Ciphertext {
        self.sk.trivial_encrypt(v)
    }
}

pub(crate) type Byte<E> = Vec<<E as BitEngine>::Bit>;

pub(crate) fn sbox<E: BitEngine>(e: &E, inp: &[E::Bit]) -> Vec<E::Bit> {
    let x0 = &inp[0];
    let x1 = &inp[1];
    let x2 = &inp[2];
    let x3 = &inp[3];
    let x4 = &inp[4];
    let x5 = &inp[5];
    let x6 = &inp[6];
    let x7 = &inp[7];

    let y14 = e.xor(x3, x5);
    let y13 = e.xor(x0, x6);
    let y9 = e.xor(x0, x3);
    let y8 = e.xor(x0, x5);
    let t0 = e.xor(x1, x2);
    let y1 = e.xor(&t0, x7);
    let y4 = e.xor(&y1, x3);
    let y12 = e.xor(&y13, &y14);
    let y2 = e.xor(&y1, x0);
    let y5 = e.xor(&y1, x6);
    let y3 = e.xor(&y5, &y8);
    let t1 = e.xor(x4, &y12);
    let y15 = e.xor(&t1, x5);
    let y20 = e.xor(&t1, x1);
    let y6 = e.xor(&y15, x7);
    let y10 = e.xor(&y15, &t0);
    let y11 = e.xor(&y20, &y9);
    let y7 = e.xor(x7, &y11);
    let y17 = e.xor(&y10, &y11);
    let y19 = e.xor(&y10, &y8);
    let y16 = e.xor(&t0, &y11);
    let y21 = e.xor(&y13, &y16);
    let y18 = e.xor(x0, &y16);

    let t2 = e.and(&y12, &y15);
    let t3 = e.and(&y3, &y6);
    let t4 = e.xor(&t3, &t2);
    let t5 = e.and(&y4, x7);
    let t6 = e.xor(&t5, &t2);
    let t7 = e.and(&y13, &y16);
    let t8 = e.and(&y5, &y1);
    let t9 = e.xor(&t8, &t7);
    let t10 = e.and(&y2, &y7);
    let t11 = e.xor(&t10, &t7);
    let t12 = e.and(&y9, &y11);
    let t13 = e.and(&y14, &y17);
    let t14 = e.xor(&t13, &t12);
    let t15 = e.and(&y8, &y10);
    let t16 = e.xor(&t15, &t12);
    let t17 = e.xor(&t4, &t14);
    let t18 = e.xor(&t6, &t16);
    let t19 = e.xor(&t9, &t14);
    let t20 = e.xor(&t11, &t16);
    let t21 = e.xor(&t17, &y20);
    let t22 = e.xor(&t18, &y19);
    let t23 = e.xor(&t19, &y21);
    let t24 = e.xor(&t20, &y18);
    let t25 = e.xor(&t21, &t22);
    let t26 = e.and(&t21, &t23);
    let t27 = e.xor(&t24, &t26);
    let t28 = e.and(&t25, &t27);
    let t29 = e.xor(&t28, &t22);
    let t30 = e.xor(&t23, &t24);
    let t31 = e.xor(&t22, &t26);
    let t32 = e.and(&t31, &t30);
    let t33 = e.xor(&t32, &t24);
    let t34 = e.xor(&t23, &t33);
    let t35 = e.xor(&t27, &t33);
    let t36 = e.and(&t24, &t35);
    let t37 = e.xor(&t36, &t34);
    let t38 = e.xor(&t27, &t36);
    let t39 = e.and(&t29, &t38);
    let t40 = e.xor(&t25, &t39);
    let t41 = e.xor(&t40, &t37);
    let t42 = e.xor(&t29, &t33);
    let t43 = e.xor(&t29, &t40);
    let t44 = e.xor(&t33, &t37);
    let t45 = e.xor(&t42, &t41);
    let z0 = e.and(&t44, &y15);
    let z1 = e.and(&t37, &y6);
    let z2 = e.and(&t33, x7);
    let z3 = e.and(&t43, &y16);
    let z4 = e.and(&t40, &y1);
    let z5 = e.and(&t29, &y7);
    let z6 = e.and(&t42, &y11);
    let z7 = e.and(&t45, &y17);
    let z8 = e.and(&t41, &y10);
    let z9 = e.and(&t44, &y12);
    let z10 = e.and(&t37, &y3);
    let z11 = e.and(&t33, &y4);
    let z12 = e.and(&t43, &y13);
    let z13 = e.and(&t40, &y5);
    let z14 = e.and(&t29, &y2);
    let z15 = e.and(&t42, &y9);
    let z16 = e.and(&t45, &y14);
    let z17 = e.and(&t41, &y8);

    let t46 = e.xor(&z15, &z16);
    let t47 = e.xor(&z10, &z11);
    let t48 = e.xor(&z5, &z13);
    let t49 = e.xor(&z9, &z10);
    let t50 = e.xor(&z2, &z12);
    let t51 = e.xor(&z2, &z5);
    let t52 = e.xor(&z7, &z8);
    let t53 = e.xor(&z0, &z3);
    let t54 = e.xor(&z6, &z7);
    let t55 = e.xor(&z16, &z17);
    let t56 = e.xor(&z12, &t48);
    let t57 = e.xor(&t50, &t53);
    let t58 = e.xor(&z4, &t46);
    let t59 = e.xor(&z3, &t54);
    let t60 = e.xor(&t46, &t57);
    let t61 = e.xor(&z14, &t57);
    let t62 = e.xor(&t52, &t58);
    let t63 = e.xor(&t49, &t58);
    let t64 = e.xor(&z4, &t59);
    let t65 = e.xor(&t61, &t62);
    let t66 = e.xor(&z1, &t63);
    let s0 = e.xor(&t59, &t63);
    let s6 = e.xnor(&t56, &t62);
    let s7 = e.xnor(&t48, &t60);
    let t67 = e.xor(&t64, &t65);
    let s3 = e.xor(&t53, &t66);
    let s4 = e.xor(&t51, &t66);
    let s5 = e.xor(&t47, &t65);
    let s1 = e.xnor(&t64, &s3);
    let s2 = e.xnor(&t55, &t67);

    vec![s0, s1, s2, s3, s4, s5, s6, s7]
}

fn byte_xor<E: BitEngine>(e: &E, a: &[E::Bit], b: &[E::Bit]) -> Byte<E> {
    (0..8).map(|i| e.xor(&a[i], &b[i])).collect()
}

fn byte_xor_const<E: BitEngine>(e: &E, a: &[E::Bit], c: u8) -> Byte<E> {
    (0..8)
        .map(|i| {
            if (c >> (7 - i)) & 1 == 1 {
                e.not(&a[i])
            } else {
                a[i].clone()
            }
        })
        .collect()
}

fn xtime<E: BitEngine>(e: &E, a: &[E::Bit]) -> Byte<E> {
    vec![
        a[1].clone(),
        a[2].clone(),
        a[3].clone(),
        e.xor(&a[4], &a[0]),
        e.xor(&a[5], &a[0]),
        a[6].clone(),
        e.xor(&a[7], &a[0]),
        a[0].clone(),
    ]
}

fn sub_bytes<E: BitEngine>(e: &E, state: &mut [Byte<E>]) {
    for byte in state.iter_mut() {
        *byte = sbox(e, byte);
    }
}

fn shift_rows<T: Clone>(state: &mut [T]) {
    let old: Vec<T> = state.to_vec();
    for i in 0..16 {
        let row = i % 4;
        let col = i / 4;
        let src = row + 4 * ((col + row) % 4);
        state[i] = old[src].clone();
    }
}

fn mix_columns<E: BitEngine>(e: &E, state: &mut [Byte<E>]) {
    for c in 0..4 {
        let b = 4 * c;
        let s0 = state[b].clone();
        let s1 = state[b + 1].clone();
        let s2 = state[b + 2].clone();
        let s3 = state[b + 3].clone();
        let two0 = xtime(e, &s0);
        let two1 = xtime(e, &s1);
        let two2 = xtime(e, &s2);
        let two3 = xtime(e, &s3);

        let n0 = xor5(e, &two0, &two1, &s1, &s2, &s3);

        let n1 = xor5(e, &s0, &two1, &two2, &s2, &s3);

        let n2 = xor5(e, &s0, &s1, &two2, &two3, &s3);

        let n3 = xor5(e, &two0, &s0, &s1, &s2, &two3);
        state[b] = n0;
        state[b + 1] = n1;
        state[b + 2] = n2;
        state[b + 3] = n3;
    }
}

fn xor5<E: BitEngine>(
    e: &E,
    a: &[E::Bit],
    b: &[E::Bit],
    c: &[E::Bit],
    d: &[E::Bit],
    f: &[E::Bit],
) -> Byte<E> {
    let r = byte_xor(e, a, b);
    let r = byte_xor(e, &r, c);
    let r = byte_xor(e, &r, d);
    byte_xor(e, &r, f)
}

fn add_round_key<E: BitEngine>(e: &E, state: &mut [Byte<E>], rk: &[Byte<E>]) {
    for i in 0..16 {
        state[i] = byte_xor(e, &state[i], &rk[i]);
    }
}

pub(crate) fn expand_key<E: BitEngine>(e: &E, key: &[E::Bit]) -> Vec<Vec<Byte<E>>> {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    let mut w: Vec<Vec<Byte<E>>> = Vec::with_capacity(44);
    for j in 0..4 {
        let word: Vec<Byte<E>> = (0..4)
            .map(|b| key[8 * (4 * j + b)..8 * (4 * j + b) + 8].to_vec())
            .collect();
        w.push(word);
    }
    for j in 4..44 {
        let mut temp = w[j - 1].clone();
        if j % 4 == 0 {
            let rot = vec![
                temp[1].clone(),
                temp[2].clone(),
                temp[3].clone(),
                temp[0].clone(),
            ];
            let mut sub: Vec<Byte<E>> = rot.iter().map(|byte| sbox(e, byte)).collect();
            sub[0] = byte_xor_const(e, &sub[0], RCON[j / 4 - 1]);
            temp = sub;
        }
        let wj: Vec<Byte<E>> = (0..4)
            .map(|b| byte_xor(e, &w[j - 4][b], &temp[b]))
            .collect();
        w.push(wj);
    }
    let mut rk: Vec<Vec<Byte<E>>> = Vec::with_capacity(11);
    for r in 0..11 {
        let mut bytes: Vec<Byte<E>> = Vec::with_capacity(16);
        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            bytes.push(w[4 * r + col][row].clone());
        }
        rk.push(bytes);
    }
    rk
}

pub(crate) fn aes_encrypt_block<E: BitEngine>(
    e: &E,
    rk: &[Vec<Byte<E>>],
    block: &[E::Bit],
) -> Vec<E::Bit> {
    let mut state: Vec<Byte<E>> = (0..16).map(|i| block[8 * i..8 * i + 8].to_vec()).collect();
    add_round_key(e, &mut state, &rk[0]);
    for r in 1..=9 {
        sub_bytes(e, &mut state);
        shift_rows(&mut state);
        mix_columns(e, &mut state);
        add_round_key(e, &mut state, &rk[r]);
    }
    sub_bytes(e, &mut state);
    shift_rows(&mut state);
    add_round_key(e, &mut state, &rk[10]);
    state.into_iter().flatten().collect()
}

pub(crate) fn counter_block<E: BitEngine>(e: &E, ctr: u64) -> Vec<E::Bit> {
    let mut bits = Vec::with_capacity(128);
    for byte_idx in 0..16usize {
        let byte_val: u8 = if byte_idx < 8 {
            0
        } else {
            let shift = 8 * (15 - byte_idx);
            ((ctr >> shift) & 0xff) as u8
        };
        for k in 0..8 {
            bits.push(e.constant((byte_val >> (7 - k)) & 1 == 1));
        }
    }
    bits
}

pub struct Aes128;

impl TranscipherDecrypt for Aes128 {
    const BLOCK_BITS: usize = 128;
    const KEY_BITS: usize = 128;
    const NAME: &'static str = "AES-128";

    const PBS_PER_OUTPUT_BIT: f64 = 40.0;

    const MULTIPLICATIVE_DEPTH: usize = 4;

    const FIXED_INIT_PBS: usize = 1280;

    fn decrypt_block(sk: &ServerKey, enc_key: &[EncBit], cipher_block: &[bool]) -> Vec<EncBit> {
        let (out, _) = decrypt_stream_timed(sk, enc_key, cipher_block);
        out
    }
}

pub fn keystream_plain(key: &[bool; 128], n: usize) -> Vec<bool> {
    let e = PlainEngine;
    let key_bits = key.to_vec();
    let rk = expand_key(&e, &key_bits);
    let mut out = Vec::with_capacity(n);
    let mut ctr = 0u64;
    while out.len() < n {
        let block = counter_block(&e, ctr);
        out.extend(aes_encrypt_block(&e, &rk, &block));
        ctr += 1;
    }
    out.truncate(n);
    out
}

pub fn decrypt_stream_timed(
    sk: &ServerKey,
    enc_key: &[EncBit],
    cipher: &[bool],
) -> (Vec<EncBit>, super::DecryptTimings) {
    assert_eq!(enc_key.len(), 128, "AES-128 key must be 128 bits");
    let e = FheEngine { sk };

    let t_init = Instant::now();
    let rk = expand_key(&e, enc_key);
    let init_s = t_init.elapsed().as_secs_f64();

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    let mut ctr = 0u64;
    while out.len() < cipher.len() {
        let block = counter_block(&e, ctr);
        let ks = aes_encrypt_block(&e, &rk, &block);
        for kbit in ks {
            if out.len() >= cipher.len() {
                break;
            }

            let c_bit = cipher[out.len()];
            out.push(if c_bit { sk.not(&kbit) } else { kbit });
        }
        ctr += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    #[rustfmt::skip]
    const AES_SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];

    fn byte_to_bits(b: u8) -> Vec<bool> {
        (0..8).map(|i| (b >> (7 - i)) & 1 == 1).collect()
    }

    fn bits_to_byte(bits: &[bool]) -> u8 {
        let mut b = 0u8;
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                b |= 1 << (7 - i);
            }
        }
        b
    }

    #[test]
    fn sbox_matches_table() {
        let e = PlainEngine;
        for x in 0u16..256 {
            let out = sbox(&e, &byte_to_bits(x as u8));
            assert_eq!(
                bits_to_byte(&out),
                AES_SBOX[x as usize],
                "S-box mismatch at input {:#04x}",
                x
            );
        }
    }

    #[test]
    fn aes_kat_fips197() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let e = PlainEngine;
        let key_bits: Vec<bool> = key.iter().flat_map(|&b| byte_to_bits(b)).collect();
        let block_bits: Vec<bool> = plaintext.iter().flat_map(|&b| byte_to_bits(b)).collect();
        let rk = expand_key(&e, &key_bits);
        let out = aes_encrypt_block(&e, &rk, &block_bits);
        let out_bytes: Vec<u8> = out.chunks(8).map(bits_to_byte).collect();
        assert_eq!(out_bytes, expected.to_vec());
    }

    #[test]
    fn fhe_sbox_matches_plain() {
        let (ck, sk) = gen_keys();
        let fe = FheEngine { sk: &sk };
        let pe = PlainEngine;
        for &x in &[0x00u8, 0x53, 0xff, 0xa7] {
            let want = sbox(&pe, &byte_to_bits(x));
            let enc: Vec<Ciphertext> = byte_to_bits(x).iter().map(|&b| ck.encrypt(b)).collect();
            let got_enc = sbox(&fe, &enc);
            let got: Vec<bool> = got_enc.iter().map(|c| ck.decrypt(c)).collect();
            assert_eq!(got, want, "FHE S-box mismatch at {:#04x}", x);
        }
    }

    #[test]
    #[ignore]
    fn fhe_keystream_matches_plain() {
        let key_bits: [bool; 128] = std::array::from_fn(|i| i % 5 == 0);
        let want = keystream_plain(&key_bits, 128);

        let (ck, sk) = gen_keys();
        let enc_key: Vec<EncBit> = key_bits.iter().map(|&b| ck.encrypt(b)).collect();
        let cipher = vec![false; 128];
        let (out, _) = decrypt_stream_timed(&sk, &enc_key, &cipher);
        let got: Vec<bool> = out.iter().map(|c| ck.decrypt(c)).collect();
        assert_eq!(got, want);
    }
}
