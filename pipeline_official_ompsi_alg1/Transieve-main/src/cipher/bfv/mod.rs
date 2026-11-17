pub mod aes128;
pub mod dasta;

pub mod pasta;

#[cfg(feature = "bfv")]
pub mod rasta;

#[cfg(feature = "bfv")]
pub mod prototype;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherBfv {
    Pasta,

    Rasta,

    Aes128,

    Dasta,
}

impl CipherBfv {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "pasta" | "pasta-bfv" | "bfv-pasta" => CipherBfv::Pasta,

            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            CipherBfv::Pasta => "Pasta (BFV)",
            CipherBfv::Rasta => "Rasta (BFV)",
            CipherBfv::Aes128 => "AES-128 (BFV)",
            CipherBfv::Dasta => "Dasta (BFV)",
        }
    }

    pub fn slug(self) -> String {
        match self {
            CipherBfv::Pasta => "pasta-bfv".into(),
            CipherBfv::Rasta => "rasta-bfv".into(),
            CipherBfv::Aes128 => "aes128-bfv".into(),
            CipherBfv::Dasta => "dasta-bfv".into(),
        }
    }

    pub fn pasta_params(self) -> pasta::PastaParams {
        pasta::PASTA3
    }

    pub fn key_words(self) -> usize {
        2 * self.pasta_params().t
    }

    pub fn block_words(self) -> usize {
        self.pasta_params().t
    }

    pub fn multiplicative_depth(self) -> usize {
        self.pasta_params().rounds
    }

    pub fn bits_per_word(self) -> usize {
        17
    }

    pub fn sym_ciphertext_bits(self, plaintext_bits: usize) -> usize {
        let blocks = plaintext_bits.div_ceil(self.block_words());
        blocks * self.block_words() * self.bits_per_word()
    }
}
