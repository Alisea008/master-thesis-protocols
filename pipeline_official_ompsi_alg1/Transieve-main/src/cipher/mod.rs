pub mod bfv;
pub mod boolean;
pub mod shortint;

pub use bfv::CipherBfv;
pub use boolean::{Cipher, EncBit, TranscipherDecrypt};
pub use shortint::{CipherShortint, EncBitShortint, ShortintKeys};

#[derive(Debug, Clone, Default)]
pub struct DecryptTimings {
    pub init_s: f64,

    pub per_bit_total_s: f64,

    pub bits: usize,
}

impl DecryptTimings {
    pub fn s_per_bit(&self) -> f64 {
        if self.bits == 0 {
            0.0
        } else {
            self.per_bit_total_s / self.bits as f64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSpec {
    Boolean(Cipher),
    Shortint(CipherShortint),

    Bfv(CipherBfv),
}

impl CipherSpec {
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(c) = Cipher::parse(s) {
            return Some(CipherSpec::Boolean(c));
        }
        if let Some(c) = CipherShortint::parse(s) {
            return Some(CipherSpec::Shortint(c));
        }

        CipherBfv::parse(s).map(CipherSpec::Bfv)
    }

    pub fn shortint_shadow_hint(self, raw: &str) -> Option<&'static str> {
        if raw.to_ascii_lowercase().contains("boolean") {
            return None;
        }
        match self {
            CipherSpec::Boolean(Cipher::Rasta) => Some("rasta-shortint"),
            CipherSpec::Boolean(Cipher::Aes128) => Some("aes-shortint"),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CipherSpec::Boolean(c) => c.name(),
            CipherSpec::Shortint(c) => c.name(),
            CipherSpec::Bfv(c) => c.name(),
        }
    }

    pub fn backend(self) -> &'static str {
        match self {
            CipherSpec::Boolean(_) => "boolean",
            CipherSpec::Shortint(_) => "shortint",
            CipherSpec::Bfv(_) => "bfv",
        }
    }

    pub fn key_bits(self) -> usize {
        match self {
            CipherSpec::Boolean(c) => c.key_bits(),
            CipherSpec::Shortint(c) => c.key_bits(),
            CipherSpec::Bfv(c) => c.key_words(),
        }
    }

    pub fn block_bits(self) -> usize {
        match self {
            CipherSpec::Boolean(c) => c.block_bits(),
            CipherSpec::Shortint(c) => c.block_bits(),
            CipherSpec::Bfv(c) => c.block_words(),
        }
    }

    pub fn pbs_per_output_bit(self) -> f64 {
        match self {
            CipherSpec::Boolean(c) => c.pbs_per_output_bit(),
            CipherSpec::Shortint(c) => c.pbs_per_output_bit(),
            CipherSpec::Bfv(_) => 0.0,
        }
    }

    pub fn multiplicative_depth(self) -> usize {
        match self {
            CipherSpec::Boolean(c) => c.multiplicative_depth(),
            CipherSpec::Shortint(c) => c.multiplicative_depth(),
            CipherSpec::Bfv(c) => c.multiplicative_depth(),
        }
    }

    pub fn fixed_init_pbs(self) -> usize {
        match self {
            CipherSpec::Boolean(c) => c.fixed_init_pbs(),
            CipherSpec::Shortint(c) => c.fixed_init_pbs(),
            CipherSpec::Bfv(_) => 0,
        }
    }

    pub fn sym_ciphertext_bits(self, plaintext_bits: usize) -> usize {
        match self {
            CipherSpec::Boolean(c) => c.sym_ciphertext_bits(plaintext_bits),
            CipherSpec::Shortint(c) => c.sym_ciphertext_bits(plaintext_bits),
            CipherSpec::Bfv(c) => c.sym_ciphertext_bits(plaintext_bits),
        }
    }

    pub fn encrypt_stream(self, key: &[bool], plaintext: &[bool]) -> Vec<bool> {
        match self {
            CipherSpec::Boolean(c) => c.encrypt_stream(key, plaintext),
            CipherSpec::Shortint(c) => c.encrypt_stream(key, plaintext),

            CipherSpec::Bfv(_) => {
                panic!("CipherSpec::Bfv (Pasta) is field-valued; use the BFV transcipher stage")
            }
        }
    }

    pub fn slug(self) -> String {
        match self {
            CipherSpec::Boolean(Cipher::Kreyvium) => "kreyvium".into(),
            CipherSpec::Boolean(Cipher::Grain128a) => "grain128a".into(),
            CipherSpec::Boolean(Cipher::Rasta) => "rasta".into(),
            CipherSpec::Boolean(Cipher::Aes128) => "aes128".into(),
            CipherSpec::Shortint(CipherShortint::Rasta) => "rasta-shortint".into(),
            CipherSpec::Shortint(CipherShortint::Aes128) => "aes128-shortint".into(),
            CipherSpec::Bfv(c) => c.slug(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_precedence_bare_names_are_boolean() {
        assert_eq!(
            CipherSpec::parse("rasta"),
            Some(CipherSpec::Boolean(Cipher::Rasta))
        );
        assert_eq!(
            CipherSpec::parse("aes128"),
            Some(CipherSpec::Boolean(Cipher::Aes128))
        );
        assert_eq!(
            CipherSpec::parse("aes"),
            Some(CipherSpec::Boolean(Cipher::Aes128))
        );

        assert_eq!(
            CipherSpec::parse("rasta-shortint"),
            Some(CipherSpec::Shortint(CipherShortint::Rasta))
        );
        assert_eq!(
            CipherSpec::parse("aes-shortint"),
            Some(CipherSpec::Shortint(CipherShortint::Aes128))
        );
    }

    #[test]
    fn shortint_shadow_hint_fires_only_for_ambiguous_bare_names() {
        assert_eq!(
            CipherSpec::parse("rasta")
                .unwrap()
                .shortint_shadow_hint("rasta"),
            Some("rasta-shortint")
        );
        assert_eq!(
            CipherSpec::parse("aes128")
                .unwrap()
                .shortint_shadow_hint("aes128"),
            Some("aes-shortint")
        );

        assert_eq!(
            CipherSpec::parse("rasta-boolean")
                .unwrap()
                .shortint_shadow_hint("rasta-boolean"),
            None
        );

        assert_eq!(
            CipherSpec::parse("rasta-shortint")
                .unwrap()
                .shortint_shadow_hint("rasta-shortint"),
            None
        );

        assert_eq!(
            CipherSpec::parse("kreyvium")
                .unwrap()
                .shortint_shadow_hint("kreyvium"),
            None
        );
    }
}
