//! Orchestrazione end-to-end (Algorithm 2) — multi-block.

use std::collections::HashSet;
use std::time::Instant;

use zeroize::Zeroize;

use crate::bloom::HashFamilies;
use crate::ot::{ot_phase1, ot_phase2, ot_phase2_with_sigma, ot_phase3, ot_phase4};
use crate::pasta_fhe::{ct_fingerprint_multi, PastaFhe, TransievePasta};
use crate::sig::{Ed25519Signer, Ed25519Verifier, Signer, Verifier};
use crate::sim::{enc_with_nonce, pasta_sim};
use crate::tee::{Tee1Pasta, TeeHostInputPasta};
use crate::ttp::{eval_msg, sigma_msg, t_msg, Ttp};
use crate::types::{fresh_sid, Sid};
use crate::{Error, Result};

use transieve::cipher::bfv::pasta::PastaParams;
use fhe::bfv::Ciphertext;

pub struct DataOwnerInput {
    pub elements: Vec<Vec<u8>>,
    pub k_sym: Vec<u8>,
}

impl Drop for DataOwnerInput {
    fn drop(&mut self) {
        self.k_sym.zeroize();
        for e in &mut self.elements { e.zeroize(); }
    }
}

pub struct E2eConfig {
    pub u: usize,
    pub n_bits: usize,
    pub hash_k: usize,
    pub seeds: Vec<[u8; 32]>,
}

#[derive(Default, Clone)]
pub struct E2eTimings {
    pub fhe_setup_s: f64,
    pub pack_key_s: f64,
    pub sim_enc_s: f64,
    pub ot_s: f64,
    pub transcipher_s: f64,
    pub eval_and_s: f64,
    pub tee_s: f64,
    pub total_s: f64,
}

#[derive(Default, Clone)]
pub struct E2eCommCost {
    pub num_blocks: usize,
    pub block_size_bytes: usize,
    pub ct_size_bytes: usize,
    pub m_sigma_len: usize,
    pub do_to_ttp_bytes_per_party: usize,
    pub ttp_to_do_bytes_per_party: usize,
    pub ttp_to_s_bytes_per_party: usize,
    pub do_to_s_bytes_per_party: usize,
    pub s_to_s1_bytes_per_party: usize,
    pub s1_to_tee_bytes: usize,
    pub total_bytes: usize,
}

pub struct E2eResult {
    pub sid: Sid,
    pub sigma: usize,
    pub do1_out: Vec<(Vec<u8>, [u8; 32])>,
    pub expected_intersection: Vec<Vec<u8>>,
    pub found_intersection: Vec<Vec<u8>>,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub timings: E2eTimings,
    pub comm: E2eCommCost,
}

pub fn run_e2e_pasta(
    params: PastaParams,
    force_degree: Option<usize>,
    cfg: &E2eConfig,
    do_inputs: Vec<DataOwnerInput>,
) -> Result<E2eResult> {
    let n = do_inputs.len();
    assert!(n >= 2, "at least 2 data owners (n>=2)");

    // NEW: multi-block. n_bits può superare params.t.
    let num_blocks = (cfg.n_bits + params.t - 1) / params.t;
    let block_size = params.t * 8; // 1024 B per PASTA3

    let t_run = Instant::now();
    eprintln!(
        "[psi] === E2E start === n={} U={} n_bits={} ({} block{}) hash_k={} Pasta_t={} force_degree={:?}",
        n, cfg.u, cfg.n_bits, num_blocks,
        if num_blocks == 1 { "" } else { "s" },
        cfg.hash_k, params.t, force_degree
    );

    let hashes = HashFamilies::new(cfg.seeds.clone(), cfg.hash_k);
    let sid = fresh_sid();

    let t_sig = Instant::now();
    let ttp = Ttp::new();
    let ttp_vk = ttp.signer.verifying_key_bytes();
    let ttp_verifier = Box::new(
        Ed25519Verifier::from_bytes(&ttp_vk)
            .ok_or_else(|| Error::Crypto("bad TTP verifying key".into()))?,
    );
    let ttp_verifier_sa = Ed25519Verifier::from_bytes(&ttp_vk)
        .ok_or_else(|| Error::Crypto("bad TTP verifying key (S_a)".into()))?;

    let s1 = Ed25519Signer::generate();
    let s1_vk = s1.verifying_key_bytes();
    let s1_verifier = Box::new(
        Ed25519Verifier::from_bytes(&s1_vk)
            .ok_or_else(|| Error::Crypto("bad S1 verifying key".into()))?,
    );
    eprintln!(
        "[psi] [sign]        Ed25519 keygen (TTP + S1): {:.3} ms",
        t_sig.elapsed().as_secs_f64() * 1e3
    );

    let sop_levels = (n as f64).log2().ceil() as usize;
    let fhe = TransievePasta { params, force_degree };

    let t0 = Instant::now();
    let ctx = fhe.setup(sop_levels)?;
    let t_fhe_setup = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [fhe setup]   PastaBfv::new (sop_levels={}): {:.3} s",
        sop_levels, t_fhe_setup
    );

    let t0 = Instant::now();
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let t_pack_key = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [pack_key]    encrypt_key for n={} DOs: {:.3} ms",
        n, t_pack_key * 1e3
    );

    // NEW: SIM encryption multi-block. Ogni (DO, hash_family) produce
    // `num_blocks` ciphertext SIM, concatenati in un unico Vec<u8> per
    // essere trasportati dall'OT (che è size-agnostic).
    let t0 = Instant::now();
    let u = hashes.len();
    let mut per_do_messages: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
    let mut m_sigma_len = 0usize;
    for do_in in &do_inputs {
        let mut msgs = Vec::with_capacity(u);
        for hu in 0..u {
            let mut bits = vec![0u8; cfg.n_bits];
            for x in &do_in.elements {
                for p in hashes.get(hu).positions(x, cfg.n_bits) {
                    bits[p] = 1;
                }
            }
            let nonce = [hu as u64, 0u64];
            let blocks = pasta_sim::enc_blocks(&bits, &do_in.k_sym, nonce, params);
            debug_assert_eq!(blocks.len(), num_blocks);
            let mut ct_concat = Vec::with_capacity(num_blocks * block_size);
            for b in blocks { ct_concat.extend_from_slice(&b); }
            m_sigma_len = m_sigma_len.max(ct_concat.len());
            msgs.push(ct_concat);
        }
        per_do_messages.push(msgs);
    }
    let t_sim_enc = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [SIM enc]     {} filters x {} DOs x {} blocks: {:.3} ms ({:.1} MB/DO)",
        u, n, num_blocks, t_sim_enc * 1e3,
        (m_sigma_len as f64) / (1024.0 * 1024.0)
    );

    let d1_prime: Vec<Vec<u8>> = do_inputs[0]
        .elements
        .iter()
        .map(|x| enc_with_nonce(&do_inputs[0].k_sym, x))
        .collect();

    let mut tee = Tee1Pasta::new(ctx, fhe, ttp_verifier, s1_verifier);
    tee.submit_host_input(TeeHostInputPasta {
        d1_prime,
        hashes: hashes.clone(),
        k_sym: do_inputs[0].k_sym.clone(),
    })?;

    let t0 = Instant::now();
    let mut rng = rand::thread_rng();

    let mut states = Vec::with_capacity(n);
    let mut p1msgs = Vec::with_capacity(n);
    for _ in 0..n {
        let (st, p1) = ot_phase1(u, &mut rng);
        states.push(st);
        p1msgs.push(p1);
    }
    let ttp1 = ot_phase2(u, &p1msgs[0], &mut rng)?;
    let sigma = ttp1.sigma;
    let mut ttp_outs = vec![ttp1];
    for a in 1..n {
        ttp_outs.push(ot_phase2_with_sigma(u, &p1msgs[a], sigma, &mut rng)?);
    }

    let mut m_sigmas: Vec<Vec<u8>> = Vec::with_capacity(n);
    for a in 0..n {
        let t_signed = t_msg(&sid, &ttp_outs[a].t);
        let sig_t = ttp.signer.sign(&t_signed);
        if !ttp_verifier_sa.verify(&t_signed, &sig_t) {
            return Err(Error::Crypto(format!(
                "bad TTP signature on T for DO_{}", a + 1
            )));
        }
        let cts = ot_phase3(&states[a], &ttp_outs[a].pk0_bytes, &per_do_messages[a])?;
        let (_j, m_sigma) = ot_phase4(&ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }
    let t_ot = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [OT]          n={} U={} sigma={} m_sigma={} B: {:.3} ms",
        n, u, sigma, m_sigmas[0].len(), t_ot * 1e3
    );

    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    tee.register_sigma(sigma, &sigma_msg(&sid, sigma), &sig_sigma)?;

    // Transcipher + AND per gruppi di `lanes` blocchi. block_ids globali.
let lanes = tee.ctx().lanes();
let num_groups = (num_blocks + lanes - 1) / lanes;
eprintln!("[psi] [groups]      {} blocks, {} lanes -> {} group(s)", num_blocks, lanes, num_groups);

let nonce = [sigma as u64, 0u64];
let mut e_b_groups: Vec<Ciphertext> = Vec::with_capacity(num_groups);
let mut t_transcipher = 0.0f64;
let mut t_eval_and = 0.0f64;

for g in 0..num_groups {
    let b0 = g * lanes;
    let b1 = ((g + 1) * lanes).min(num_blocks);
    let block_ids: Vec<u64> = (b0..b1).map(|b| b as u64).collect();

    let mut e_a_vec = Vec::with_capacity(n);
    for a in 0..n {
        let m = &m_sigmas[a];
        let words: Vec<Vec<u64>> = (b0..b1)
            .map(|b| {
                let s = b * block_size;
                let e = (s + block_size).min(m.len());
                pasta_sim::bytes_to_words(&m[s..e])
            })
            .collect();
        let t_do = Instant::now();
        let ct = tee.fhe().transcipher(tee.ctx(), &per_do_keys[a], nonce, &block_ids, &words)?;
        let dt = t_do.elapsed().as_secs_f64();
        t_transcipher += dt;
        eprintln!(
            "[psi] [transcipher] group {}/{} DO_{} ({} blocks): {:.3} s",
            g + 1, num_groups, a + 1, b1 - b0, dt
        );
        e_a_vec.push(ct);
    }

    let t_and = Instant::now();
    let e_b_g = tee.fhe().eval_and_all(tee.ctx(), &e_a_vec, n)?;
    t_eval_and += t_and.elapsed().as_secs_f64();
    e_b_groups.push(e_b_g);
}
eprintln!(
    "[psi] [eval_and]    {} group(s): AND {:.3} s (transcipher totale {:.3} s)",
    num_groups, t_eval_and, t_transcipher
);

let ct_size_bytes: usize = {
    use fhe_traits::Serialize as FheSerialize;
    e_b_groups.iter().map(|c| c.to_bytes().len()).sum()
};

    let t0 = Instant::now();
    let fp = ct_fingerprint_multi(&e_b_groups);
    let signed_msg = eval_msg(&sid, &fp);
    let sig_eval = s1.sign(&signed_msg);
    let out = tee.process_eval(&sid, &e_b_groups, &sig_eval, cfg.n_bits)?;
    let t_tee = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [TEE]         |D1'|={} tokens in {:.3} ms",
        out.len(), t_tee * 1e3
    );

    let all_sets: Vec<HashSet<_>> = do_inputs
        .iter()
        .map(|d| d.elements.iter().cloned().collect())
        .collect();
    let expected: Vec<Vec<u8>> = do_inputs[0]
        .elements
        .iter()
        .filter(|x| all_sets.iter().all(|s| s.contains(*x)))
        .cloned()
        .collect();

    let found: Vec<Vec<u8>> = out
        .iter()
        .filter(|(_, tok)| *tok != [0u8; 32])
        .map(|(x, _)| x.clone())
        .collect();

    let expected_set: HashSet<_> = expected.iter().cloned().collect();
    let found_set: HashSet<_> = found.iter().cloned().collect();
    let false_positives = found_set.difference(&expected_set).count();
    let false_negatives = expected_set.difference(&found_set).count();

    // Comm cost multi-block
    let do_to_ttp = (u - 1) * 32 + 32;
    let ttp_to_do = 32;
    let ttp_to_s = 32;
    let do_to_s = u * (m_sigma_len + 6);
    let s_to_s1 = ct_size_bytes;
    let s1_to_tee = ct_size_bytes;
    let total_bytes = n * do_to_ttp
        + n * ttp_to_do
        + n * ttp_to_s
        + n * do_to_s
        + n * s_to_s1
        + s1_to_tee;
    let comm = E2eCommCost {
        num_blocks,
        block_size_bytes: block_size,
        ct_size_bytes,
        m_sigma_len,
        do_to_ttp_bytes_per_party: do_to_ttp,
        ttp_to_do_bytes_per_party: ttp_to_do,
        ttp_to_s_bytes_per_party: ttp_to_s,
        do_to_s_bytes_per_party: do_to_s,
        s_to_s1_bytes_per_party: s_to_s1,
        s1_to_tee_bytes: s1_to_tee,
        total_bytes,
    };

    let total_s = t_run.elapsed().as_secs_f64();
    let timings = E2eTimings {
        fhe_setup_s: t_fhe_setup,
        pack_key_s: t_pack_key,
        sim_enc_s: t_sim_enc,
        ot_s: t_ot,
        transcipher_s: t_transcipher,
        eval_and_s: t_eval_and,
        tee_s: t_tee,
        total_s,
    };

    eprintln!(
        "[psi] === E2E done in {:.3} s | n_bits={} ({} block{}) | sigma={} | |exp|={} | |found|={} | FP={} | FN={} ===",
        total_s, cfg.n_bits, num_blocks,
        if num_blocks == 1 { "" } else { "s" },
        sigma,
        expected.len(), found.len(), false_positives, false_negatives
    );

    Ok(E2eResult {
        sid, sigma, do1_out: out,
        expected_intersection: expected,
        found_intersection: found,
        false_positives, false_negatives,
        timings, comm,
    })
}
