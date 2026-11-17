//! Orchestrazione end-to-end Algorithm 2 (senza TEE, CMUX simulato, multi-block).

use std::collections::HashSet;
use std::time::Instant;

use fhe::bfv::Ciphertext;
use zeroize::Zeroize;

use crate::bloom::HashFamilies;
use crate::ot::{ot_phase1, ot_phase2, ot_phase2_with_sigma, ot_phase3, ot_phase4};
use crate::pasta_fhe::{PastaFhe, TransievePasta};
use crate::sig::{Ed25519Verifier, Signer, Verifier};
use crate::sim::pasta_sim;
use crate::ttp::{sigma_msg, Ttp};
use crate::types::{fresh_sid, fresh_token, Sid};
use crate::{Error, Result};

use transieve::cipher::bfv::pasta::PastaParams;

pub struct DataOwnerInput {
    pub elements: Vec<Vec<u8>>,
    pub k_sym: Vec<u8>,
}

impl Drop for DataOwnerInput {
    fn drop(&mut self) {
        self.k_sym.zeroize();
        for e in &mut self.elements {
            e.zeroize();
        }
    }
}

pub struct E2eConfig {
    pub u: usize,
    pub n_bits: usize,
    pub hash_k: usize,
    pub seeds: Vec<[u8; 32]>,
}

pub struct E2eResultAlt {
    pub sid: Sid,
    pub sigma: usize,
    pub do1_out: Vec<(Vec<u8>, [u8; 32])>,
    pub expected_intersection: Vec<Vec<u8>>,
    pub found_intersection: Vec<Vec<u8>>,
    pub false_positives: usize,
    pub false_negatives: usize,
    // Multi-block info
    pub n_b_blocks: usize,
    pub n_a_blocks: usize,
    // Timings (s)
    pub total_s: f64,
    pub fhe_setup_s: f64,
    pub pack_key_s: f64,
    pub sim_enc_s: f64,
    pub ot_s: f64,
    pub transcipher_s: f64,
    pub eval_and_s: f64,
    pub cmux_sim_s: f64,
}

/// Esegue Algorithm "Alternative" in modalità multi-block: nessun TEE, S_1
/// fa il membership test via CMUX (simulato, vedi NOTES.md).
pub fn run_e2e_pasta_alt(
    params: PastaParams,
    force_degree: Option<usize>,
    cfg: &E2eConfig,
    do_inputs: Vec<DataOwnerInput>,
) -> Result<E2eResultAlt> {
    let n = do_inputs.len();
    assert!(n >= 2, "at least 2 data owners (n>=2)");

    let t_run = Instant::now();
    let t = params.t;
    let block_bytes = t * 8;
    let hashes = HashFamilies::new(cfg.seeds.clone(), cfg.hash_k);
    let sid = fresh_sid();
    let u = hashes.len();
    let h = cfg.hash_k;
    let m1 = do_inputs[0].elements.len();
    let bits_per_idx = ((cfg.n_bits as f64).log2().ceil() as usize).max(1);
    let n_b = (cfg.n_bits + t - 1) / t;
    let idx_bits_total = m1 * h * bits_per_idx;
    let n_a = (idx_bits_total + t - 1) / t;

    eprintln!(
        "[psi-alt] === E2E start (no TEE, multi-block) === n={} U={} n_bits={} hash_k={} set_size={}",
        n, u, cfg.n_bits, h, m1
    );
    eprintln!(
        "[psi-alt] multi-block: t={} n_bits={} -> n_b={} blocks; idx_bits={} -> n_a={} blocks",
        t, cfg.n_bits, n_b, idx_bits_total, n_a
    );

    // --- FHE setup ---
    let sop_levels = (n as f64).log2().ceil() as usize;
    let fhe = TransievePasta { params, force_degree };
    let t_setup = Instant::now();
    let ctx = fhe.setup(sop_levels)?;
    let t_fhe_setup = t_setup.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [fhe setup] {:.3} s", t_fhe_setup);

    // --- TTP + verifier ---
    let ttp = Ttp::new();
    let ttp_vk = ttp.signer.verifying_key_bytes();
    let ttp_verifier = Ed25519Verifier::from_bytes(&ttp_vk)
        .ok_or_else(|| Error::Crypto("bad TTP verifying key".into()))?;

    // --- pack_key ---
    let t0 = Instant::now();
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let t_pack_key = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [pack_key] {:.3} ms", t_pack_key * 1e3);

    // --- SIM: filtri multi-block + matrice indici multi-block ---
    let t0 = Instant::now();
    // per_do_messages[a][hu] = Vec<blocks>  (concatenati in un unico messaggio OT)
    let mut per_do_messages: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
    for do_in in &do_inputs {
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(u);
        for hu in 0..u {
            let mut bits = vec![0u8; cfg.n_bits];
            for x in &do_in.elements {
                for p in hashes.get(hu).positions(x, cfg.n_bits) {
                    bits[p] = 1;
                }
            }
            let blocks = pasta_sim::enc_multi_block(&bits, &do_in.k_sym, [hu as u64, 0], params);
            let concat: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
            msgs.push(concat);
        }
        per_do_messages.push(msgs);
    }

    // Matrice indici (solo DO_1): namespace separato (u + hu) per il nonce
    let mut do1_index_messages: Vec<Vec<u8>> = Vec::with_capacity(u);
    for hu in 0..u {
        let mut all_indices: Vec<usize> = Vec::with_capacity(m1 * h);
        for x in &do_inputs[0].elements {
            for p in hashes.get(hu).positions(x, cfg.n_bits) {
                all_indices.push(p);
            }
        }
        let blocks = pasta_sim::enc_indices_multi_block(
            &all_indices,
            bits_per_idx,
            &do_inputs[0].k_sym,
            [(u + hu) as u64, 0],
            params,
        );
        let concat: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
        do1_index_messages.push(concat);
    }
    let t_sim_enc = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi-alt] [SIM enc] {} filtri + {} matrici indici (multi-block): {:.3} ms",
        u, u, t_sim_enc * 1e3
    );

    // --- OT filtri (n istanze) + OT indici (1 istanza), stesso σ ---
    let t0 = Instant::now();
    let mut rng = rand::thread_rng();
    let mut filter_states = Vec::with_capacity(n);
    let mut filter_p1s = Vec::with_capacity(n);
    for _ in 0..n {
        let (st, p1) = ot_phase1(u, &mut rng);
        filter_states.push(st);
        filter_p1s.push(p1);
    }
    let ttp1 = ot_phase2(u, &filter_p1s[0], &mut rng)?;
    let sigma = ttp1.sigma;
    let mut filter_ttp_outs = vec![ttp1];
    for a in 1..n {
        filter_ttp_outs.push(ot_phase2_with_sigma(u, &filter_p1s[a], sigma, &mut rng)?);
    }
    let (idx_state, idx_p1) = ot_phase1(u, &mut rng);
    let idx_ttp_out = ot_phase2_with_sigma(u, &idx_p1, sigma, &mut rng)?;

    let mut m_sigmas: Vec<Vec<u8>> = Vec::with_capacity(n);
    for a in 0..n {
        let cts = ot_phase3(&filter_states[a], &filter_ttp_outs[a].pk0_bytes, &per_do_messages[a])?;
        let (_j, m_sigma) = ot_phase4(&filter_ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }
    let idx_cts = ot_phase3(&idx_state, &idx_ttp_out.pk0_bytes, &do1_index_messages)?;
    let (_j, m_a_sigma) = ot_phase4(&idx_ttp_out.t, &idx_cts)?;
    let t_ot = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [OT] σ={} n_b={} n_a={}: {:.3} ms", sigma, n_b, n_a, t_ot * 1e3);

    // --- TTP firma σ (autenticazione tra server) ---
    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    if !ttp_verifier.verify(&sigma_msg(&sid, sigma), &sig_sigma) {
        return Err(Error::Crypto("bad TTP signature on sigma".into()));
    }

    // --- Transcipher filtri + matrice indici (per blocco) ---
    let t0 = Instant::now();
    // e_a_vec[b][a] = ciphertext del blocco b per il DO a
    let mut e_a_vec: Vec<Vec<Ciphertext>> = Vec::with_capacity(n_b);
    for b in 0..n_b {
        let mut block_cts = Vec::with_capacity(n);
        for a in 0..n {
            let bytes = &m_sigmas[a][b * block_bytes..(b + 1) * block_bytes];
            let words = pasta_sim::bytes_to_words(bytes);
            let nonce = [sigma as u64, b as u64];
            let ct = fhe.transcipher(&ctx, &per_do_keys[a], nonce, &[0], &[words])?;
            block_cts.push(ct);
        }
        e_a_vec.push(block_cts);
    }

    // E_A: n_a ciphertext (uno per blocco degli indici)
    let mut e_a_ct_vec: Vec<Ciphertext> = Vec::with_capacity(n_a);
    for b in 0..n_a {
        let bytes = &m_a_sigma[b * block_bytes..(b + 1) * block_bytes];
        let words = pasta_sim::bytes_to_words(bytes);
        let nonce = [(u + sigma) as u64, b as u64];
        let ct = fhe.transcipher(&ctx, &per_do_keys[0], nonce, &[0], &[words])?;
        e_a_ct_vec.push(ct);
    }
    let t_transcipher = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi-alt] [transcipher] {} ct filtri + {} ct indici: {:.3} s",
        n_b * n, n_a, t_transcipher
    );

    // --- AND slot-wise per blocco ---
    let t0 = Instant::now();
    let mut e_b_vec: Vec<Ciphertext> = Vec::with_capacity(n_b);
    for b in 0..n_b {
        e_b_vec.push(fhe.eval_and_all(&ctx, &e_a_vec[b], n)?);
    }
    let t_eval_and = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [eval_and] {} blocchi AND: {:.3} s", n_b, t_eval_and);

    // =====================================================================
    // CMUX (SIMULATO multi-block) — vedi NOTES.md
    //
    // In FHE reale: R[j,l] = B_blocks[idx/t][idx%t] richiede un two-level
    // CMUX (TFHE PBS). Qui S_1 ha sk e fa il lookup in chiaro, quindi il
    // costo FHE del CMUX NON è misurato.
    // =====================================================================
    let t0 = Instant::now();
    let mut b_bits_all: Vec<bool> = Vec::with_capacity(n_b * t);
    for b in 0..n_b {
        let bits = fhe.decrypt_bits(&ctx, &e_b_vec[b], t)?;
        b_bits_all.extend_from_slice(&bits);
    }
    b_bits_all.truncate(cfg.n_bits);

    let mut a_bits_all: Vec<bool> = Vec::with_capacity(n_a * t);
    for b in 0..n_a {
        let bits = fhe.decrypt_bits(&ctx, &e_a_ct_vec[b], t)?;
        a_bits_all.extend_from_slice(&bits);
    }
    a_bits_all.truncate(idx_bits_total);

    let mut indices: Vec<usize> = Vec::with_capacity(m1 * h);
    for i in 0..m1 * h {
        let mut idx = 0usize;
        for k in 0..bits_per_idx {
            idx |= (a_bits_all[i * bits_per_idx + k] as usize) << k;
        }
        indices.push(idx);
    }

    let mut r_bits: Vec<bool> = Vec::with_capacity(m1 * h);
    for &idx in &indices {
        r_bits.push(b_bits_all.get(idx).copied().unwrap_or(false));
    }
    let t_cmux_sim = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [CMUX-sim] {} lookup: {:.3} ms", m1 * h, t_cmux_sim * 1e3);
    // =====================================================================

    // --- DO_1 decide membership ---
    let mut do1_out: Vec<(Vec<u8>, [u8; 32])> = Vec::with_capacity(m1);
    for j in 0..m1 {
        let all_one = (0..h).all(|l| r_bits[j * h + l]);
        let token = if all_one { fresh_token() } else { [0u8; 32] };
        do1_out.push((do_inputs[0].elements[j].clone(), token));
    }

    // --- ground truth + FP/FN ---
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
    let found: Vec<Vec<u8>> = do1_out
        .iter()
        .filter(|(_, tk)| *tk != [0u8; 32])
        .map(|(x, _)| x.clone())
        .collect();

    let expected_set: HashSet<_> = expected.iter().cloned().collect();
    let found_set: HashSet<_> = found.iter().cloned().collect();
    let false_positives = found_set.difference(&expected_set).count();
    let false_negatives = expected_set.difference(&found_set).count();

    let total_s = t_run.elapsed().as_secs_f64();
    eprintln!(
        "[psi-alt] === E2E done in {:.3}s | σ={} | n_b={} n_a={} | |exp|={} | |found|={} | FP={} | FN={} ===",
        total_s, sigma, n_b, n_a, expected.len(), found.len(), false_positives, false_negatives
    );

    Ok(E2eResultAlt {
        sid,
        sigma,
        do1_out,
        expected_intersection: expected,
        found_intersection: found,
        false_positives,
        false_negatives,
        n_b_blocks: n_b,
        n_a_blocks: n_a,
        total_s,
        fhe_setup_s: t_fhe_setup,
        pack_key_s: t_pack_key,
        sim_enc_s: t_sim_enc,
        ot_s: t_ot,
        transcipher_s: t_transcipher,
        eval_and_s: t_eval_and,
        cmux_sim_s: t_cmux_sim,
    })
}
