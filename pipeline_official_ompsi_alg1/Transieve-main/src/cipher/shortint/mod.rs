pub mod aes128;
pub mod rasta;

use tfhe::shortint::parameters::ClassicPBSParameters;
use tfhe::shortint::server_key::LookupTableOwned;
use tfhe::shortint::{Ciphertext, ClientKey, ServerKey};

use super::DecryptTimings;

pub type EncBitShortint = Ciphertext;

pub struct ShortintKeys {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
    pub xor_lut: LookupTableOwned,
    pub parameters: ClassicPBSParameters,
}

impl ShortintKeys {
    pub fn generate(parameters: ClassicPBSParameters) -> Self {
        let (client_key, server_key) = tfhe::shortint::gen_keys(parameters);
        let xor_lut = server_key.generate_lookup_table(|x| x & 1);
        Self {
            client_key,
            server_key,
            xor_lut,
            parameters,
        }
    }

    pub fn encrypt_bit(&self, b: bool) -> EncBitShortint {
        self.client_key.encrypt(b as u64)
    }

    pub fn decrypt_bit(&self, ct: &EncBitShortint) -> bool {
        (self.client_key.decrypt(ct) & 1) == 1
    }
}

#[inline]
pub fn xor_into(sk: &ServerKey, dst: &mut EncBitShortint, src: &EncBitShortint) {
    sk.unchecked_add_assign(dst, src);
}

pub fn safe_xor_assign(
    sk: &ServerKey,
    xor_lut: &LookupTableOwned,
    dst: &mut EncBitShortint,
    src: &EncBitShortint,
) {
    if sk
        .is_add_possible(dst.noise_degree(), src.noise_degree())
        .is_err()
    {
        sk.apply_lookup_table_assign(dst, xor_lut);
    }
    sk.unchecked_add_assign(dst, src);
}

#[inline]
pub fn clean_to_bit(
    sk: &ServerKey,
    xor_lut: &LookupTableOwned,
    x: &EncBitShortint,
) -> EncBitShortint {
    sk.apply_lookup_table(x, xor_lut)
}

#[inline]
pub fn clean_to_bit_assign(sk: &ServerKey, xor_lut: &LookupTableOwned, x: &mut EncBitShortint) {
    sk.apply_lookup_table_assign(x, xor_lut);
}

#[inline]
pub fn and_bits(sk: &ServerKey, a: &EncBitShortint, b: &EncBitShortint) -> EncBitShortint {
    sk.bitand(a, b)
}

#[inline]
pub fn xor_const(sk: &ServerKey, x: &EncBitShortint, b: bool) -> EncBitShortint {
    if b {
        sk.unchecked_scalar_add(x, 1)
    } else {
        x.clone()
    }
}

pub trait TranscipherDecryptShortint {
    const PARAMETERS: ClassicPBSParameters;
    const BLOCK_BITS: usize;
    const KEY_BITS: usize;
    const NAME: &'static str;

    const PBS_PER_OUTPUT_BIT: f64;
    const MULTIPLICATIVE_DEPTH: usize;
    const FIXED_INIT_PBS: usize;

    fn decrypt_block(
        keys: &ShortintKeys,
        enc_key: &[EncBitShortint],
        cipher_block: &[bool],
    ) -> Vec<EncBitShortint>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherShortint {
    Rasta,
    Aes128,
}

impl CipherShortint {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "rasta-shortint" | "shortint-rasta" | "rasta-si" => Self::Rasta,

            "aes-shortint" | "shortint-aes" => Self::Aes128,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rasta => rasta::RastaShortint::NAME,
            Self::Aes128 => aes128::Aes128Shortint::NAME,
        }
    }

    pub fn key_bits(self) -> usize {
        match self {
            Self::Rasta => rasta::RastaShortint::KEY_BITS,
            Self::Aes128 => aes128::Aes128Shortint::KEY_BITS,
        }
    }

    pub fn block_bits(self) -> usize {
        match self {
            Self::Rasta => rasta::RastaShortint::BLOCK_BITS,
            Self::Aes128 => aes128::Aes128Shortint::BLOCK_BITS,
        }
    }

    pub fn pbs_per_output_bit(self) -> f64 {
        match self {
            Self::Rasta => rasta::RastaShortint::PBS_PER_OUTPUT_BIT,
            Self::Aes128 => aes128::Aes128Shortint::PBS_PER_OUTPUT_BIT,
        }
    }

    pub fn multiplicative_depth(self) -> usize {
        match self {
            Self::Rasta => rasta::RastaShortint::MULTIPLICATIVE_DEPTH,
            Self::Aes128 => aes128::Aes128Shortint::MULTIPLICATIVE_DEPTH,
        }
    }

    pub fn fixed_init_pbs(self) -> usize {
        match self {
            Self::Rasta => rasta::RastaShortint::FIXED_INIT_PBS,
            Self::Aes128 => aes128::Aes128Shortint::FIXED_INIT_PBS,
        }
    }

    pub fn parameters(self) -> ClassicPBSParameters {
        match self {
            Self::Rasta => rasta::RastaShortint::PARAMETERS,
            Self::Aes128 => aes128::Aes128Shortint::PARAMETERS,
        }
    }

    pub fn sym_ciphertext_bits(self, plaintext_bits: usize) -> usize {
        match self {
            Self::Rasta => plaintext_bits,

            Self::Aes128 => plaintext_bits,
        }
    }

    pub fn encrypt_stream(self, key: &[bool], plaintext: &[bool]) -> Vec<bool> {
        match self {
            Self::Rasta => {
                assert_eq!(
                    key.len(),
                    super::boolean::rasta::STATE_BITS,
                    "Rasta key must be {} bits",
                    super::boolean::rasta::STATE_BITS,
                );
                let nonce = [0u64; 2];
                let ks = super::boolean::rasta::keystream_plain(key, nonce, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
            Self::Aes128 => {
                let mut k = [false; 128];
                k.copy_from_slice(&key[..128]);
                let ks = super::boolean::aes128::keystream_plain(&k, plaintext.len());
                plaintext
                    .iter()
                    .zip(ks.iter())
                    .map(|(&p, &z)| p ^ z)
                    .collect()
            }
        }
    }

    pub fn decrypt_homomorphic_timed(
        self,
        keys: &ShortintKeys,
        enc_key: &[EncBitShortint],
        cipher: &[bool],
    ) -> (Vec<EncBitShortint>, DecryptTimings) {
        match self {
            Self::Rasta => rasta::decrypt_stream_timed(keys, enc_key, cipher),
            Self::Aes128 => aes128::decrypt_stream_timed(keys, enc_key, cipher),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    #[test]
    fn xor_and_clean_smoke() {
        let keys = ShortintKeys::generate(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let sk = &keys.server_key;

        for &b in &[false, true] {
            let ct = keys.encrypt_bit(b);
            assert_eq!(keys.decrypt_bit(&ct), b);
        }

        let mut accum = keys.encrypt_bit(true);
        xor_into(sk, &mut accum, &keys.encrypt_bit(true));
        xor_into(sk, &mut accum, &keys.encrypt_bit(false));
        xor_into(sk, &mut accum, &keys.encrypt_bit(true));
        clean_to_bit_assign(sk, &keys.xor_lut, &mut accum);
        assert_eq!(keys.decrypt_bit(&accum), true);

        let a = keys.encrypt_bit(true);
        let b = keys.encrypt_bit(false);
        let ab = and_bits(sk, &a, &b);
        assert_eq!(keys.decrypt_bit(&ab), false);

        let c = keys.encrypt_bit(true);
        let ac = and_bits(sk, &a, &c);
        assert_eq!(keys.decrypt_bit(&ac), true);
    }
}
