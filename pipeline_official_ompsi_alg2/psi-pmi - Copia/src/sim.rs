use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use rand::RngCore;

// Length of a nonce for the symmetric cipher (12 bytes for ChaCha20-Poly1305)
pub const SIM_NONCE_LEN: usize = 12;

// Trait abstracting a symmetric authenticated cipher
pub trait SymmetricCipher {
    // Encrypt plaintext `pt` with `key` and `nonce`, returning ciphertext
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8>;
    // Decrypt ciphertext `ct` with `key` and `nonce`, returning plaintext if valid
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>>;
}

// Concrete implementation of SymmetricCipher
pub struct Sim;
impl Sim {
    // Generate a fresh random nonce
    pub fn fresh_nonce() -> [u8; SIM_NONCE_LEN] {
        let mut n = [0u8; SIM_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut n);
        n
    }
}

impl SymmetricCipher for Sim {
    // Encrypt using ChaCha20-Poly1305 with fixed AAD
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key len");
        let nonce = Nonce::from_slice(nonce);
        cipher.encrypt(nonce, Payload { msg: pt, aad: b"PSI-PMI/SIM/v1" }).expect("enc")
    }
    // Decrypt using ChaCha20-Poly1305 with fixed AAD
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, Payload { msg: ct, aad: b"PSI-PMI/SIM/v1" }).ok()
    }
}

// Encrypt with a freshly generated nonce prepended to the ciphertext
pub fn enc_with_nonce(key: &[u8], pt: &[u8]) -> Vec<u8> {
    let nonce = Sim::fresh_nonce();
    let ct = Sim.enc(key, &nonce, pt);
    let mut out = Vec::with_capacity(SIM_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

// Decrypt input where the first SIM_NONCE_LEN bytes are the nonce
pub fn dec_with_nonce(key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < SIM_NONCE_LEN { return None; }
    let (nb, ct) = input.split_at(SIM_NONCE_LEN);
    let nonce: [u8; SIM_NONCE_LEN] = nb.try_into().ok()?;
    Sim.dec(key, &nonce, ct)
}

// -------------------------------------------------------------------------
// "Pasta-shaped" SIM used by the transcipher (Pasta stream cipher, mod P).
// -------------------------------------------------------------------------

use transieve::cipher::bfv::pasta::{encrypt as pasta_encrypt, P};

/// Derive 2t field elements mod P from k_sym (same derivation as in `pack_key`).
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

    /// Encrypt `bits` (0/1) into a single SIM ciphertext formatted as
    /// serialized LE "Pasta words". `bits.len()` must be <= `params.t`.
    pub fn enc(bits: &[u8], k_sym: &[u8], nonce: [u64; 2], params: PastaParams) -> Vec<u8> {
        assert!(bits.len() <= params.t, "bits must fit in one Pasta lane");
        let key = derive_pasta_key(k_sym, params.t);
        let mut msg: Vec<u64> = bits.iter().map(|&b| (b & 1) as u64).collect();
        msg.resize(params.t, 0);
        let ct = pasta_encrypt(&key, &msg, nonce, params);
        words_to_bytes(&ct)
    }

    /// Encrypt `bits` into N blocks of size `params.t`. Nonce per block:
    /// `[nonce_base[0], nonce_base[1] + block_idx]`.
    /// Multi-block: fixed nonce, global block counter (0,1,2,...),
    /// consistent with `block_ids` on the FHE side. Parallel per block.
pub fn enc_blocks(
    bits: &[u8],
    k_sym: &[u8],
    nonce: [u64; 2],
    params: PastaParams,
) -> Vec<Vec<u8>> {
    use rayon::prelude::*;
    use transieve::cipher::bfv::pasta::keystream_block;

    let t = params.t;
    // Number of blocks needed to cover all bits
    let n_blocks = (bits.len() + t - 1) / t;
    let key = derive_pasta_key(k_sym, t);

    (0..n_blocks)
        .into_par_iter()
        .map(|b| {
            // Compute the Pasta keystream for block index `b`
            let ks = keystream_block(&key, nonce, b as u64, params);
            let s = b * t;
            // Add each message bit (padded with zeros) to the keystream mod P
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

// Alias for `enc_blocks`, kept for API compatibility
pub fn enc_multi_block(
    bits: &[u8],
    k_sym: &[u8],
    nonce_base: [u64; 2],
    params: PastaParams,
) -> Vec<Vec<u8>> {
    enc_blocks(bits, k_sym, nonce_base, params)
}

    /// Encrypt a list of indices as bits (bits_per_idx per index) in multi-block mode.
    pub fn enc_indices_multi_block(
        indices: &[usize],
        bits_per_idx: usize,
        k_sym: &[u8],
        nonce_base: [u64; 2],
        params: PastaParams,
    ) -> Vec<Vec<u8>> {
        // Flatten each index into `bits_per_idx` little-endian bits
        let mut bits = Vec::with_capacity(indices.len() * bits_per_idx);
        for &idx in indices {
            for k in 0..bits_per_idx {
                bits.push(((idx >> k) & 1) as u8);
            }
        }
        enc_multi_block(&bits, k_sym, nonce_base, params)
    }

    // Serialize a slice of u64 words into little-endian bytes
    pub fn words_to_bytes(words: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 8);
        for w in words { out.extend_from_slice(&w.to_le_bytes()); }
        out
    }

    // Deserialize little-endian bytes into u64 words, reducing each mod P
    pub fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()) % super::P)
            .collect()
    }
}
