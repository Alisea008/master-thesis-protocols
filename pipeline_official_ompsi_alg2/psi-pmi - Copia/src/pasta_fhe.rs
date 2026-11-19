//! Adapter for Transieve's BFV+Pasta-3 backend.

use anyhow::Result;
use fhe::bfv::Ciphertext;

use transieve::cipher::bfv::pasta::{PastaBfv, PastaParams, PASTA3};
use transieve::circuit::ThresholdCircuit;

use crate::sim::derive_pasta_key;

// Trait abstracting the Pasta FHE backend operations
pub trait PastaFhe {
    type Ct: Clone;
    type KeyCt: Clone;
    type Ctx;

    // Initialize the FHE context with the given number of SOP levels
    fn setup(&self, sop_levels: usize) -> Result<Self::Ctx>;
    // Pack the symmetric key into an FHE-encrypted key ciphertext
    fn pack_key(&self, ctx: &Self::Ctx, k_sym: &[u8]) -> Result<Self::KeyCt>;
    // Transcipher the Pasta-encrypted words into a single FHE ciphertext
    fn transcipher(
        &self,
        ctx: &Self::Ctx,
        key_ct: &Self::KeyCt,
        nonce: [u64; 2],
        blocks: &[u64],
        cipher_words: &[Vec<u64>],
    ) -> Result<Self::Ct>;
    // Evaluate the threshold "AND all" circuit over the given ciphertexts
    fn eval_and_all(&self, ctx: &Self::Ctx, cts: &[Self::Ct], n_parties: usize) -> Result<Self::Ct>;
    // Decrypt the ciphertext into `num_bits` boolean bits
    fn decrypt_bits(&self, ctx: &Self::Ctx, ct: &Self::Ct, num_bits: usize) -> Result<Vec<bool>>;
}

// Concrete implementation of PastaFhe using Transieve's Pasta-3 parameters
#[derive(Clone)]
pub struct TransievePasta {
    pub params: PastaParams,
    pub force_degree: Option<usize>,
}

impl Default for TransievePasta {
    fn default() -> Self {
        Self {
            params: PASTA3,
            // Force a polynomial degree of 8192 for deterministic setup
            force_degree: Some(8192),
        }
    }
}

impl PastaFhe for TransievePasta {
    type Ct = Ciphertext;
    type KeyCt = Ciphertext;
    type Ctx = PastaBfv;

    fn setup(&self, sop_levels: usize) -> Result<Self::Ctx> {
        // Use the forced degree if set, otherwise fall back to a secure default
        match self.force_degree {
            Some(d) => PastaBfv::new_with_sop(self.params, d, sop_levels),
            None => PastaBfv::new_secure(self.params, sop_levels),
        }
    }

    fn pack_key(&self, ctx: &Self::Ctx, k_sym: &[u8]) -> Result<Self::KeyCt> {
        let t = self.params.t;
        // Derive 2t field elements: first t for the key, last t for the mask
        let fe = derive_pasta_key(k_sym, t);
        ctx.pack_key(&fe[..t], &fe[t..])
    }

    fn transcipher(
        &self,
        ctx: &Self::Ctx,
        key_ct: &Self::KeyCt,
        nonce: [u64; 2],
        blocks: &[u64],
        cipher_words: &[Vec<u64>],
    ) -> Result<Self::Ct> {
        assert_eq!(blocks.len(), cipher_words.len());
        // Convert Vec<Vec<u64>> into Vec<&[u64]> for the backend API
        let refs: Vec<&[u64]> = cipher_words.iter().map(|v| v.as_slice()).collect();
        ctx.transcipher_recover_blocks(key_ct, nonce, blocks, &refs)
    }

    fn eval_and_all(&self, ctx: &Self::Ctx, cts: &[Self::Ct], n_parties: usize) -> Result<Self::Ct> {
        // Build an n-of-n threshold circuit and evaluate it over the ciphertexts
        let circuit = ThresholdCircuit::new(n_parties, n_parties);
        ctx.evaluate_sop(cts, &circuit)
    }

    fn decrypt_bits(&self, ctx: &Self::Ctx, ct: &Self::Ct, num_bits: usize) -> Result<Vec<bool>> {
    let t = self.params.t;
    // Compute the per-lane bit lengths: full blocks of t, plus a remainder
    let mut lens = vec![t; num_bits / t];
    if num_bits % t != 0 { lens.push(num_bits % t); }
    // Ensure the number of blocks fits within the available lanes
    anyhow::ensure!(
        lens.len() <= ctx.lanes(),
        "{} blocchi > {} lanes: servono più ciphertext", lens.len(), ctx.lanes()
    );
    ctx.decrypt_lane_bits(ct, &lens)
    }
}

// -------------------------------------------------------------------------
// Canonical fingerprint of a ciphertext (to sign E_B without serializing)
// -------------------------------------------------------------------------

/// Returns SHAKE256("PSI-PMI/Eval/ct-fingerprint/v1" || len || bytes(ct)).
/// Used to sign `Eval` deterministically, without serializing the
/// Ciphertext via serde.
pub fn ct_fingerprint(ct: &Ciphertext) -> Vec<u8> {
    use fhe_traits::Serialize as FheSerialize;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    // Serialize the ciphertext to bytes for hashing
    let bytes = ct.to_bytes();
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/Eval/ct-fingerprint/v1");
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; 32];
    r.read(&mut out);
    out
}
