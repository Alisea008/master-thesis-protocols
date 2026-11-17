use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use rand::RngCore;

pub const SIM_NONCE_LEN: usize = 12;

pub trait SymmetricCipher {
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8>;
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>>;
}

pub struct Sim;
impl Sim {
    pub fn fresh_nonce() -> [u8; SIM_NONCE_LEN] {
        let mut n = [0u8; SIM_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut n);
        n
    }
}

impl SymmetricCipher for Sim {
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key len");
        let nonce = Nonce::from_slice(nonce);
        cipher.encrypt(nonce, Payload { msg: pt, aad: b"PSI-PMI/SIM/v1" }).expect("enc")
    }
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, Payload { msg: ct, aad: b"PSI-PMI/SIM/v1" }).ok()
    }
}

pub fn enc_with_nonce(key: &[u8], pt: &[u8]) -> Vec<u8> {
    let nonce = Sim::fresh_nonce();
    let ct = Sim.enc(key, &nonce, pt);
    let mut out = Vec::with_capacity(SIM_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn dec_with_nonce(key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < SIM_NONCE_LEN { return None; }
    let (nb, ct) = input.split_at(SIM_NONCE_LEN);
    let nonce: [u8; SIM_NONCE_LEN] = nb.try_into().ok()?;
    Sim.dec(key, &nonce, ct)
}

// -------------------------------------------------------------------------
// SIM "Pasta-shaped" usata dal transcipher (stream cipher Pasta, mod P).
// -------------------------------------------------------------------------

use transieve::cipher::bfv::pasta::{encrypt as pasta_encrypt, P};

/// Deriva 2t field element mod P da k_sym (stessa derivazione in `pack_key`).
pub fn derive_pasta_key(k_sym: &[u8], t: usize) -> Vec<u64> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/Pasta/key/v1");
    h.update(k_sym);
    let mut r = h.finalize_xof();
    let mut buf = vec![0u8; 8 * 2 * t];
    r.read(&mut buf);
    buf.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) % P)
        .collect()
}

pub mod pasta_sim {
    use super::{derive_pasta_key, pasta_encrypt};
    use transieve::cipher::bfv::pasta::PastaParams;

    /// Cifra `bits` (0/1) in un ciphertext SIM formato "parole Pasta" serializzate LE.
    /// `bits.len()` deve essere <= `params.t`.
    pub fn enc(bits: &[u8], k_sym: &[u8], nonce: [u64; 2], params: PastaParams) -> Vec<u8> {
        assert!(bits.len() <= params.t, "bits must fit in one Pasta lane");
        let key = derive_pasta_key(k_sym, params.t);
        let mut msg: Vec<u64> = bits.iter().map(|&b| (b & 1) as u64).collect();
        msg.resize(params.t, 0);
        let ct = pasta_encrypt(&key, &msg, nonce, params);
        words_to_bytes(&ct)
    }

    /// Cifra `bits` in N blocchi da `params.t`. Nonce per blocco:
    /// `[nonce_base[0], nonce_base[1] + block_idx]`.
    pub fn enc_multi_block(
        bits: &[u8],
        k_sym: &[u8],
        nonce_base: [u64; 2],
        params: PastaParams,
    ) -> Vec<Vec<u8>> {
        let t = params.t;
        let n = (bits.len() + t - 1) / t;
        (0..n)
            .map(|b| {
                let start = b * t;
                let end = (start + t).min(bits.len());
                let nonce = [nonce_base[0], nonce_base[1] + b as u64];
                enc(&bits[start..end], k_sym, nonce, params)
            })
            .collect()
    }

    /// Cifra una lista di indici come bit (bits_per_idx per indice) in multi-block.
    pub fn enc_indices_multi_block(
        indices: &[usize],
        bits_per_idx: usize,
        k_sym: &[u8],
        nonce_base: [u64; 2],
        params: PastaParams,
    ) -> Vec<Vec<u8>> {
        let mut bits = Vec::with_capacity(indices.len() * bits_per_idx);
        for &idx in indices {
            for k in 0..bits_per_idx {
                bits.push(((idx >> k) & 1) as u8);
            }
        }
        enc_multi_block(&bits, k_sym, nonce_base, params)
    }

    pub fn words_to_bytes(words: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 8);
        for w in words { out.extend_from_slice(&w.to_le_bytes()); }
        out
    }

    pub fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()) % super::P)
            .collect()
    }
}
