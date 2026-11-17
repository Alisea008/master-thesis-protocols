pub mod aes128;
pub mod grain128a;
pub mod kreyvium;
pub mod rasta;

use tfhe::boolean::prelude::*;

pub use super::DecryptTimings;

pub type EncBit = Ciphertext;

pub trait TranscipherDecrypt {
    const BLOCK_BITS: usize;

    const KEY_BITS: usize;

    const NAME: &'static str;

    const PBS_PER_OUTPUT_BIT: f64;

    const MULTIPLICATIVE_DEPTH: usize;

    const FIXED_INIT_PBS: usize;

    fn decrypt_block(sk: &ServerKey, enc_key: &[EncBit], cipher_block: &[bool]) -> Vec<EncBit>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Kreyvium,
    Grain128a,
    Rasta,
    Aes128,
}

impl Cipher {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "kreyvium" | "kreyvium-128" | "kreyvium128" => Cipher::Kreyvium,
            "grain" | "grain-128a" | "grain128a" => Cipher::Grain128a,
            "rasta" | "rasta-boolean" | "boolean-rasta" => Cipher::Rasta,
            "aes" | "aes128" | "aes-128" | "aes-boolean" | "boolean-aes" => Cipher::Aes128,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::NAME,
            Cipher::Grain128a => grain128a::Grain128a::NAME,
            Cipher::Rasta => rasta::Rasta::NAME,
            Cipher::Aes128 => aes128::Aes128::NAME,
        }
    }

    pub fn key_bits(self) -> usize {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::KEY_BITS,
            Cipher::Grain128a => grain128a::Grain128a::KEY_BITS,
            Cipher::Rasta => rasta::Rasta::KEY_BITS,
            Cipher::Aes128 => aes128::Aes128::KEY_BITS,
        }
    }

    pub fn block_bits(self) -> usize {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::BLOCK_BITS,
            Cipher::Grain128a => grain128a::Grain128a::BLOCK_BITS,
            Cipher::Rasta => rasta::Rasta::BLOCK_BITS,
            Cipher::Aes128 => aes128::Aes128::BLOCK_BITS,
        }
    }

    pub fn pbs_per_output_bit(self) -> f64 {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::PBS_PER_OUTPUT_BIT,
            Cipher::Grain128a => grain128a::Grain128a::PBS_PER_OUTPUT_BIT,
            Cipher::Rasta => rasta::Rasta::PBS_PER_OUTPUT_BIT,
            Cipher::Aes128 => aes128::Aes128::PBS_PER_OUTPUT_BIT,
        }
    }

    pub fn multiplicative_depth(self) -> usize {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::MULTIPLICATIVE_DEPTH,
            Cipher::Grain128a => grain128a::Grain128a::MULTIPLICATIVE_DEPTH,
            Cipher::Rasta => rasta::Rasta::MULTIPLICATIVE_DEPTH,
            Cipher::Aes128 => aes128::Aes128::MULTIPLICATIVE_DEPTH,
        }
    }

    pub fn fixed_init_pbs(self) -> usize {
        match self {
            Cipher::Kreyvium => kreyvium::Kreyvium128::FIXED_INIT_PBS,
            Cipher::Grain128a => grain128a::Grain128a::FIXED_INIT_PBS,
            Cipher::Rasta => rasta::Rasta::FIXED_INIT_PBS,
            Cipher::Aes128 => aes128::Aes128::FIXED_INIT_PBS,
        }
    }

    pub fn sym_ciphertext_bits(self, plaintext_bits: usize) -> usize {
        match self {
            Cipher::Kreyvium | Cipher::Grain128a | Cipher::Rasta | Cipher::Aes128 => plaintext_bits,
        }
    }

    pub fn encrypt_stream(self, key: &[bool], plaintext: &[bool]) -> Vec<bool> {
        match self {
            Cipher::Kreyvium => {
                let mut k = [false; 128];
                k.copy_from_slice(&key[..128]);
                let iv = [false; 128];
                let ks = kreyvium::keystream_plain(&k, &iv, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
            Cipher::Grain128a => {
                let mut k = [false; 128];
                k.copy_from_slice(&key[..128]);
                let iv = [false; 96];
                let ks = grain128a::keystream_plain(&k, &iv, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
            Cipher::Rasta => {
                assert_eq!(key.len(), rasta::STATE_BITS, "Rasta key must be 525 bits");
                let nonce = [0u64; 2];
                let ks = rasta::keystream_plain(key, nonce, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
            Cipher::Aes128 => {
                let mut k = [false; 128];
                k.copy_from_slice(&key[..128]);
                let ks = aes128::keystream_plain(&k, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
        }
    }

    pub fn decrypt_homomorphic(
        self,
        sk: &ServerKey,
        enc_key: &[EncBit],
        cipher: &[bool],
    ) -> Vec<EncBit> {
        let (out, _) = self.decrypt_homomorphic_timed(sk, enc_key, cipher);
        out
    }

    pub fn decrypt_homomorphic_timed(
        self,
        sk: &ServerKey,
        enc_key: &[EncBit],
        cipher: &[bool],
    ) -> (Vec<EncBit>, DecryptTimings) {
        match self {
            Cipher::Kreyvium => kreyvium::decrypt_stream_timed(sk, enc_key, cipher),
            Cipher::Grain128a => grain128a::decrypt_stream_timed(sk, enc_key, cipher),
            Cipher::Rasta => rasta::decrypt_stream_timed(sk, enc_key, cipher),
            Cipher::Aes128 => aes128::decrypt_stream_timed(sk, enc_key, cipher),
        }
    }
}
