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
// SIM "Pasta-shaped" usata dal transcipher.
// -------------------------------------------------------------------------

use transieve::cipher::bfv::pasta::P;

/// Deriva 2t field element mod P da k_sym. Stessa derivazione in
/// `pasta_fhe::pack_key` e `pasta_sim::enc_blocks`.
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
    use super::{derive_pasta_key};
    use transieve::cipher::bfv::pasta::PastaParams;

    /// Single-block encryption (n_bits <= t). Wrapper di `enc_blocks` con
    /// assert che fallisce se ci sono più blocchi (per non rompere i test
    /// esistenti che si aspettano un solo Vec<u8>).
    pub fn enc(bits: &[u8], k_sym: &[u8], nonce: [u64; 2], params: PastaParams) -> Vec<u8> {
        let blocks = enc_blocks(bits, k_sym, nonce, params);
        assert_eq!(
            blocks.len(), 1,
            "enc called on multi-block input; use enc_blocks instead"
        );
        blocks.into_iter().next().unwrap()
    }

    /// Multi-block encryption. Splits `bits` into chunks of `params.t` bits,
    /// pads each to `t` field elements, encrypts each chunk with a per-block
    /// nonce `[nonce_base[0], nonce_base[1] + block_id]`.
    ///
    /// Returns one `Vec<u8>` per block, each of size `t * 8` bytes
    /// (128 field elements × 8 bytes = 1024 bytes for PASTA3).
    pub fn enc_blocks(
    bits: &[u8],
    k_sym: &[u8],
    nonce: [u64; 2],
    params: PastaParams,
) -> Vec<Vec<u8>> {
    use rayon::prelude::*;
    use transieve::cipher::bfv::pasta::keystream_block;

    let t = params.t;
    let n_blocks = (bits.len() + t - 1) / t;
    let key = derive_pasta_key(k_sym, t);

    (0..n_blocks)
        .into_par_iter()
        .map(|b| {
            let ks = keystream_block(&key, nonce, b as u64, params);
            let s = b * t;
            let words: Vec<u64> = (0..t)
                .map(|i| {
                    let m = if s + i < bits.len() { (bits[s + i] & 1) as u64 } else { 0 };
                    (m + ks[i]) % super::P
                })
                .collect();
            words_to_bytes(&words)
        })
        .collect()
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
