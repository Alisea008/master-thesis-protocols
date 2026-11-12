//! Orchestrazione end-to-end (Algorithm 2, senza TEE).

use std::collections::HashSet;
use std::time::Instant;

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
        // A3: wipe the symmetric key (and inputs) on drop.
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

// =========================================================================
// Protocollo alternativo (Algorithm "Alternative", senza TEE, con CMUX)
// =========================================================================

/// Risultato del protocollo alternativo (senza TEE).
pub struct E2eResultAlt {
    pub sid: Sid,
    pub sigma: usize,
    pub do1_out: Vec<(Vec<u8>, [u8; 32])>,
    pub expected_intersection: Vec<Vec<u8>>,
    pub found_intersection: Vec<Vec<u8>>,
    pub false_positives: usize,
    pub false_negatives: usize,
}

/// Esegue Algorithm "Alternative": nessun TEE, S_1 fa membership test
/// omomorfico tramite CMUX (simulato, vedi NOTES.md).
///
/// Differenze rispetto a `run_e2e_pasta`:
///  - DO_1 calcola anche M^A_u = E_k(A_u) (matrice di indici) per ogni u.
///  - Due OT paralleli con lo stesso σ: uno per i filtri, uno per A_u.
///  - S_1 transciphers anche M^A_σ → E_A, e usa E_A come select lines
///    del CMUX su E_B (simulato: S_1 decifra, multiplexa, ritorna R).
///  - DO_1 riceve R (bit per (elemento, hash)) e decide la membership
///    facendo AND sugli h bit di ogni elemento.
pub fn run_e2e_pasta_alt(
    params: PastaParams,
    force_degree: Option<usize>,
    cfg: &E2eConfig,
    do_inputs: Vec<DataOwnerInput>,
) -> Result<E2eResultAlt> {
    let n = do_inputs.len();
    assert!(n >= 2, "at least 2 data owners (n>=2)");
    assert!(cfg.n_bits <= params.t, "filter must fit in one Pasta lane");

    let t_run = Instant::now();
    eprintln!(
        "[psi-alt] === E2E start (no TEE) === n={} U={} n_bits={} hash_k={}",
        n, cfg.u, cfg.n_bits, cfg.hash_k
    );

    let hashes = HashFamilies::new(cfg.seeds.clone(), cfg.hash_k);
    let sid = fresh_sid();
    let u = hashes.len();
    let h = cfg.hash_k;
    let m1 = do_inputs[0].elements.len();
    let bits_per_idx = (cfg.n_bits as f64).log2().ceil() as usize;

    // Padiglione di sicurezza: la matrice di indici deve stare in un lane.
    assert!(
        m1 * h * bits_per_idx <= params.t,
        "index matrix too large: {} bits > params.t ({})",
        m1 * h * bits_per_idx,
        params.t
    );

    // --- FHE setup (unico ctx, sk usata da S_1 per la simulazione del CMUX) ---
    let sop_levels = (n as f64).log2().ceil() as usize;
    let fhe = TransievePasta { params, force_degree };
    let ctx = fhe.setup(sop_levels)?;

    // TTP firma σ (usato per autenticare σ tra i server, non più verso TEE)
    let ttp = Ttp::new();
    let ttp_vk = ttp.signer.verifying_key_bytes();
    let ttp_verifier = Ed25519Verifier::from_bytes(&ttp_vk)
        .ok_or_else(|| Error::Crypto("bad TTP verifying key".into()))?;

    // --- pack_key per DO ---
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // --- SIM ciphertexts: U filtri per DO ---
    let mut per_do_messages: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
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
            msgs.push(pasta_sim::enc(&bits, &do_in.k_sym, nonce, params));
        }
        per_do_messages.push(msgs);
    }

    // --- SIM ciphertexts: matrice di indici (solo DO_1) ---
    let mut do1_index_messages: Vec<Vec<u8>> = Vec::with_capacity(u);
    for hu in 0..u {
        let mut all_indices: Vec<usize> = Vec::with_capacity(m1 * h);
        for x in &do_inputs[0].elements {
            for p in hashes.get(hu).positions(x, cfg.n_bits) {
                all_indices.push(p);
            }
        }
        let nonce = [hu as u64, 1u64]; // dominio separato dai filtri
        do1_index_messages.push(pasta_sim::enc_indices(
            &all_indices,
            bits_per_idx,
            &do_inputs[0].k_sym,
            nonce,
            params,
        ));
    }

    // --- OT per i filtri (tutti i DO) ---
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

    // --- OT per la matrice di indici (DO_1 → S_1, stesso σ) ---
    let (idx_state, idx_p1) = ot_phase1(u, &mut rng);
    let idx_ttp_out = ot_phase2_with_sigma(u, &idx_p1, sigma, &mut rng)?;

    // --- DO eseguono OT phase3/4 ---
    let mut m_sigmas: Vec<Vec<u8>> = Vec::with_capacity(n);
    for a in 0..n {
        let cts = ot_phase3(
            &filter_states[a],
            &filter_ttp_outs[a].pk0_bytes,
            &per_do_messages[a],
        )?;
        let (_j, m_sigma) = ot_phase4(&filter_ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }

    // DO_1 invia M^A_σ a S_1
    let idx_cts = ot_phase3(&idx_state, &idx_ttp_out.pk0_bytes, &do1_index_messages)?;
    let (_j, m_a_sigma) = ot_phase4(&idx_ttp_out.t, &idx_cts)?;

    // Sanity: TTP firma σ, i server la verificano (canale autenticato STTP→S_a)
    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    if !ttp_verifier.verify(&sigma_msg(&sid, sigma), &sig_sigma) {
        return Err(Error::Crypto("bad TTP signature on sigma".into()));
    }

    // --- S_a transciphers M^a_σ → E^(a) ---
    let mut e_a_vec = Vec::with_capacity(n);
    for a in 0..n {
        let words = pasta_sim::bytes_to_words(&m_sigmas[a]);
        let nonce = [sigma as u64, 0u64];
        let ct = fhe.transcipher(&ctx, &per_do_keys[a], nonce, &[0], &[words])?;
        e_a_vec.push(ct);
    }

    // --- S_1 transciphers M^A_σ → E_A ---
    let idx_words = pasta_sim::bytes_to_words(&m_a_sigma);
    let e_a_ct = fhe.transcipher(
        &ctx,
        &per_do_keys[0],
        [sigma as u64, 1u64],
        &[0],
        &[idx_words],
    )?;

    // --- S_1 calcola AND slot-wise ---
    let e_b = fhe.eval_and_all(&ctx, &e_a_vec, n)?;

    // =====================================================================
    // CMUX (SIMULATO — vedi NOTES.md)
    //
    // Transieve non espone PBS/CMUX. Simuliamo:
    //  1. S_1 decifra E_B ed E_A (richiede sk: gap di sicurezza)
    //  2. esegue il multiplexer in chiaro: R[j,l] = B[A_σ[j,l]]
    //  3. (opzionale) re-incapsula R con pasta_sim + transcipher
    //
    // In produzione: usare TFHE PBS su E_A senza decifrare, e cifrare R
    // sotto pk prima di inviarla a DO_1.
    // =====================================================================
    let b_bits = fhe.decrypt_bits(&ctx, &e_b, cfg.n_bits)?;
    let a_bits = fhe.decrypt_bits(&ctx, &e_a_ct, m1 * h * bits_per_idx)?;

    let mut indices: Vec<usize> = Vec::with_capacity(m1 * h);
    for i in 0..m1 * h {
        let mut idx = 0usize;
        for k in 0..bits_per_idx {
            idx |= (a_bits[i * bits_per_idx + k] as usize) << k;
        }
        indices.push(idx);
    }

    let mut r_bits: Vec<bool> = Vec::with_capacity(m1 * h);
    for &idx in &indices {
        r_bits.push(b_bits.get(idx).copied().unwrap_or(false));
    }
    // =====================================================================

    // --- DO_1 (in chiaro, simulando la decifratura di E_R) ---
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
        .filter(|(_, t)| *t != [0u8; 32])
        .map(|(x, _)| x.clone())
        .collect();

    let expected_set: HashSet<_> = expected.iter().cloned().collect();
    let found_set: HashSet<_> = found.iter().cloned().collect();
    let false_positives = found_set.difference(&expected_set).count();
    let false_negatives = expected_set.difference(&found_set).count();

    eprintln!(
        "[psi-alt] === E2E done in {:.3}s | σ={} | |exp|={} | |found|={} | FP={} | FN={} ===",
        t_run.elapsed().as_secs_f64(),
        sigma,
        expected.len(),
        found.len(),
        false_positives,
        false_negatives
    );

    Ok(E2eResultAlt {
        sid,
        sigma,
        do1_out,
        expected_intersection: expected,
        found_intersection: found,
        false_positives,
        false_negatives,
    })
}