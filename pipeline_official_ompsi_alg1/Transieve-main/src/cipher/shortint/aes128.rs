use std::time::Instant;

use tfhe::shortint::parameters::{ClassicPBSParameters, PARAM_MESSAGE_1_CARRY_2_KS_PBS};
use tfhe::shortint::server_key::{BivariateLookupTableOwned, LookupTableOwned};
use tfhe::shortint::ServerKey;

use crate::cipher::boolean::aes128::{aes_encrypt_block, counter_block, expand_key, BitEngine};

use super::super::DecryptTimings;
use super::{EncBitShortint, ShortintKeys, TranscipherDecryptShortint};

pub struct Aes128Shortint;

impl TranscipherDecryptShortint for Aes128Shortint {
    const PARAMETERS: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_2_KS_PBS;
    const BLOCK_BITS: usize = 128;
    const KEY_BITS: usize = 128;
    const NAME: &'static str = "AES-128 (shortint)";

    const PBS_PER_OUTPUT_BIT: f64 = 40.0;

    const MULTIPLICATIVE_DEPTH: usize = 4;

    const FIXED_INIT_PBS: usize = 1280;

    fn decrypt_block(
        keys: &ShortintKeys,
        enc_key: &[EncBitShortint],
        cipher_block: &[bool],
    ) -> Vec<EncBitShortint> {
        let (out, _) = decrypt_stream_timed(keys, enc_key, cipher_block);
        out
    }
}

struct ShortintEngine<'a> {
    sk: &'a ServerKey,

    clean_lut: &'a LookupTableOwned,

    and_lut: BivariateLookupTableOwned,
}

impl<'a> ShortintEngine<'a> {
    fn new(keys: &'a ShortintKeys) -> Self {
        let and_lut = keys
            .server_key
            .generate_lookup_table_bivariate(|a, b| (a & 1) & (b & 1));
        Self {
            sk: &keys.server_key,
            clean_lut: &keys.xor_lut,
            and_lut,
        }
    }

    #[inline]
    fn clean(&self, ct: &EncBitShortint) -> EncBitShortint {
        self.sk.apply_lookup_table(ct, self.clean_lut)
    }
}

impl BitEngine for ShortintEngine<'_> {
    type Bit = EncBitShortint;

    fn xor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit {
        let mut r = a.clone();
        if self
            .sk
            .is_add_possible(r.noise_degree(), b.noise_degree())
            .is_err()
        {
            self.sk.apply_lookup_table_assign(&mut r, self.clean_lut);
            if self
                .sk
                .is_add_possible(r.noise_degree(), b.noise_degree())
                .is_err()
            {
                let bc = self.clean(b);
                self.sk.unchecked_add_assign(&mut r, &bc);
                return r;
            }
        }
        self.sk.unchecked_add_assign(&mut r, b);
        r
    }

    fn and(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit {
        let ca = self.clean(a);
        let cb = self.clean(b);
        self.sk
            .apply_lookup_table_bivariate(&ca, &cb, &self.and_lut)
    }

    fn xnor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit {
        let t = self.xor(a, b);
        self.not(&t)
    }

    fn not(&self, a: &Self::Bit) -> Self::Bit {
        let one = self.constant(true);
        self.xor(a, &one)
    }

    fn constant(&self, v: bool) -> Self::Bit {
        self.sk.create_trivial(v as u64)
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
    assert_eq!(enc_key.len(), 128, "AES-128 key must be 128 bits");
    let engine = ShortintEngine::new(keys);
    let sk = &keys.server_key;
    let clean_lut = &keys.xor_lut;

    let flip_lut = sk.generate_lookup_table(|x| (x + 1) & 1);

    let t_init = Instant::now();
    let rk = expand_key(&engine, enc_key);
    let init_s = t_init.elapsed().as_secs_f64();

    let t_per = Instant::now();
    let mut out = Vec::with_capacity(cipher.len());
    let mut ctr = 0u64;
    while out.len() < cipher.len() {
        let block = counter_block(&engine, ctr);
        let ks = aes_encrypt_block(&engine, &rk, &block);
        for mut kbit in ks {
            if out.len() >= cipher.len() {
                break;
            }

            let lut = if cipher[out.len()] {
                &flip_lut
            } else {
                clean_lut
            };
            sk.apply_lookup_table_assign(&mut kbit, lut);
            out.push(kbit);
        }
        ctr += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::boolean::aes128::{keystream_plain, sbox};

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
    #[ignore]
    fn fhe_sbox_matches_plain_shortint() {
        let keys = ShortintKeys::generate(Aes128Shortint::PARAMETERS);
        let engine = ShortintEngine::new(&keys);

        for &(x, want) in &[(0x00u8, 0x63u8), (0x53, 0xed), (0xff, 0x16), (0xa7, 0x5c)] {
            let enc: Vec<EncBitShortint> = (0..8)
                .map(|i| keys.encrypt_bit((x >> (7 - i)) & 1 == 1))
                .collect();
            let got_enc = sbox(&engine, &enc);
            let got: Vec<bool> = got_enc.iter().map(|c| keys.decrypt_bit(c)).collect();
            assert_eq!(
                bits_to_byte(&got),
                want,
                "shortint S-box mismatch at {:#04x}",
                x
            );
        }
    }

    #[test]
    #[ignore]
    fn fhe_keystream_matches_plain_shortint() {
        let key_bits: [bool; 128] = std::array::from_fn(|i| i % 5 == 0);
        let want = keystream_plain(&key_bits, 8);

        let keys = ShortintKeys::generate(Aes128Shortint::PARAMETERS);
        let enc_key: Vec<EncBitShortint> = key_bits.iter().map(|&b| keys.encrypt_bit(b)).collect();
        let cipher = vec![false; 8];
        let (out, _) = decrypt_stream_timed(&keys, &enc_key, &cipher);
        let got: Vec<bool> = out.iter().map(|c| keys.decrypt_bit(c)).collect();
        assert_eq!(got, want);
    }
}
