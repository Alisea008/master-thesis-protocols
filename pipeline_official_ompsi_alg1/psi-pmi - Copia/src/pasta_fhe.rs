//! Adapter per il backend BFV+Pasta-3 di Transieve.

use anyhow::Result;
use fhe::bfv::Ciphertext;

use transieve::cipher::bfv::pasta::{PastaBfv, PastaParams, PASTA3};
use transieve::circuit::ThresholdCircuit;

use crate::sim::derive_pasta_key;

pub trait PastaFhe {
    type Ct: Clone;
    type KeyCt: Clone;
    type Ctx;

    fn setup(&self, sop_levels: usize) -> Result<Self::Ctx>;
    fn pack_key(&self, ctx: &Self::Ctx, k_sym: &[u8]) -> Result<Self::KeyCt>;
    fn transcipher(
        &self,
        ctx: &Self::Ctx,
        key_ct: &Self::KeyCt,
        nonce: [u64; 2],
        blocks: &[u64],
        cipher_words: &[Vec<u64>],
    ) -> Result<Self::Ct>;
    fn eval_and_all(&self, ctx: &Self::Ctx, cts: &[Self::Ct], n_parties: usize) -> Result<Self::Ct>;
    fn decrypt_bits(&self, ctx: &Self::Ctx, ct: &Self::Ct, num_bits: usize) -> Result<Vec<bool>>;
}

#[derive(Clone)]
pub struct TransievePasta {
    pub params: PastaParams,
    pub force_degree: Option<usize>,
}

impl Default for TransievePasta {
    fn default() -> Self {
        Self {
            params: PASTA3,
            force_degree: Some(8192),
        }
    }
}

impl PastaFhe for TransievePasta {
    type Ct = Ciphertext;
    type KeyCt = Ciphertext;
    type Ctx = PastaBfv;

    fn setup(&self, sop_levels: usize) -> Result<Self::Ctx> {
        match self.force_degree {
            Some(d) => PastaBfv::new_with_sop(self.params, d, sop_levels),
            None => PastaBfv::new_secure(self.params, sop_levels),
        }
    }

    fn pack_key(&self, ctx: &Self::Ctx, k_sym: &[u8]) -> Result<Self::KeyCt> {
        let t = self.params.t;
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
        let refs: Vec<&[u64]> = cipher_words.iter().map(|v| v.as_slice()).collect();
        ctx.transcipher_recover_blocks(key_ct, nonce, blocks, &refs)
    }

    fn eval_and_all(&self, ctx: &Self::Ctx, cts: &[Self::Ct], n_parties: usize) -> Result<Self::Ct> {
        let circuit = ThresholdCircuit::new(n_parties, n_parties);
        ctx.evaluate_sop(cts, &circuit)
    }

    fn decrypt_bits(&self, ctx: &Self::Ctx, ct: &Self::Ct, num_bits: usize) -> Result<Vec<bool>> {
    let t = self.params.t;
    let mut lens = vec![t; num_bits / t];
    if num_bits % t != 0 { lens.push(num_bits % t); }
    anyhow::ensure!(
        lens.len() <= ctx.lanes(),
        "{} blocchi > {} lanes: servono più ciphertext", lens.len(), ctx.lanes()
    );
    ctx.decrypt_lane_bits(ct, &lens)
}
}

// -------------------------------------------------------------------------
// Fingerprint canonico di un ciphertext (per firmare E_B senza serializzare)
// -------------------------------------------------------------------------

/// Restituisce SHAKE256("PSI-PMI/Eval/ct-fingerprint/v1" || len || bytes(ct)).
/// Usato per firmare `Eval` in modo deterministico, senza serializzare il
/// Ciphertext con serde.
pub fn ct_fingerprint(ct: &Ciphertext) -> Vec<u8> {
    use fhe_traits::Serialize as FheSerialize;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
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

/// Fingerprint di una sequenza ordinata di ciphertext (uno per gruppo di lane).
pub fn ct_fingerprint_multi(cts: &[Ciphertext]) -> Vec<u8> {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/Eval/ct-fingerprint-multi/v1");
    h.update(&(cts.len() as u64).to_le_bytes());
    for ct in cts {
        h.update(&ct_fingerprint(ct));
    }
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; 32];
    r.read(&mut out);
    out
}
