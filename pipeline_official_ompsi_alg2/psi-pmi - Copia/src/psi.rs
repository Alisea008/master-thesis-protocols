//! End-to-end orchestration of Algorithm 2 (no TEE, simulated CMUX, multi-block).

use std::collections::HashSet;
use std::time::Instant;

use fhe::bfv::Ciphertext;
use fhe_traits::Serialize as FheSerialize;
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

// Input provided by a single data owner: elements and symmetric key
pub struct DataOwnerInput {
    pub elements: Vec<Vec<u8>>,
    pub k_sym: Vec<u8>,
}

// Securely zeroize sensitive material when the input is dropped
impl Drop for DataOwnerInput {
    fn drop(&mut self) {
        self.k_sym.zeroize();
        for e in &mut self.elements {
            e.zeroize();
        }
    }
}

// End-to-end run configuration
pub struct E2eConfig {
    pub u: usize,
    pub n_bits: usize,
    pub hash_k: usize,
    pub seeds: Vec<[u8; 32]>,
}

// Result of the end-to-end run, including timing metrics
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
    // Communication (bytes), computed from the sizes of the messages exchanged
    pub ct_size_bytes: usize,
    pub comm_total_bytes: usize,
}

/// Runs the "Alternative" algorithm in multi-block mode: no TEE, S_1
/// performs the membership test via CMUX (simulated, see NOTES.md).
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
    // Byte size of a single Pasta block (t words of 8 bytes each)
    let block_bytes = t * 8;
    let hashes = HashFamilies::new(cfg.seeds.clone(), cfg.hash_k);
    let sid = fresh_sid();
    let u = hashes.len();
    let h = cfg.hash_k;
    let m1 = do_inputs[0].elements.len();
    // Number of bits needed to encode an index into the filter
    let bits_per_idx = ((cfg.n_bits as f64).log2().ceil() as usize).max(1);
    // Number of Pasta blocks needed to hold the whole filter
    let n_b = (cfg.n_bits + t - 1) / t;
    let idx_bits_total = m1 * h * bits_per_idx;
    // Number of Pasta blocks needed to hold all index bits
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
    // SOP depth: ceil(log2(n)) levels are needed for the n-way AND
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
    // Each DO's symmetric key is packed into an FHE-encrypted key ciphertext
    let t0 = Instant::now();
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let t_pack_key = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [pack_key] {:.3} ms", t_pack_key * 1e3);

    // --- SIM: multi-block filters + multi-block index matrix ---
    let t0 = Instant::now();
    // per_do_messages[a][hu] = Vec<blocks> (concatenated into a single OT message)
    let mut per_do_messages: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
    for do_in in &do_inputs {
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(u);
        for hu in 0..u {
            // Build the Bloom filter bit vector for hash family `hu`
            let mut bits = vec![0u8; cfg.n_bits];
            for x in &do_in.elements {
                for p in hashes.get(hu).positions(x, cfg.n_bits) {
                    bits[p] = 1;
                }
            }
            // Encrypt the filter in multi-block Pasta SIM mode
            let blocks = pasta_sim::enc_multi_block(&bits, &do_in.k_sym, [hu as u64, 0], params);
            let concat: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
            msgs.push(concat);
        }
        per_do_messages.push(msgs);
    }

    // Index matrix (only DO_1): separate namespace (u + hu) for the nonce
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

    // --- Filter OT (n instances) + Index OT (1 instance), same σ ---
    let t0 = Instant::now();
    let mut rng = rand::thread_rng();
    let mut filter_states = Vec::with_capacity(n);
    let mut filter_p1s = Vec::with_capacity(n);
    // Phase 1 for every DO's filter OT instance
    for _ in 0..n {
        let (st, p1) = ot_phase1(u, &mut rng);
        filter_states.push(st);
        filter_p1s.push(p1);
    }
    // Phase 2 for the first DO establishes the shared σ
    let ttp1 = ot_phase2(u, &filter_p1s[0], &mut rng)?;
    let sigma = ttp1.sigma;
    let mut filter_ttp_outs = vec![ttp1];
    // Subsequent DOs reuse the same σ
    for a in 1..n {
        filter_ttp_outs.push(ot_phase2_with_sigma(u, &filter_p1s[a], sigma, &mut rng)?);
    }
    // Index OT instance, also bound to the same σ
    let (idx_state, idx_p1) = ot_phase1(u, &mut rng);
    let idx_ttp_out = ot_phase2_with_sigma(u, &idx_p1, sigma, &mut rng)?;

    // Phase 3 + 4 for each DO's filter OT
    let mut m_sigmas: Vec<Vec<u8>> = Vec::with_capacity(n);
    for a in 0..n {
        let cts = ot_phase3(&filter_states[a], &filter_ttp_outs[a].pk0_bytes, &per_do_messages[a])?;
        let (_j, m_sigma) = ot_phase4(&filter_ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }
    // Phase 3 + 4 for the index OT
    let idx_cts = ot_phase3(&idx_state, &idx_ttp_out.pk0_bytes, &do1_index_messages)?;
    let (_j, m_a_sigma) = ot_phase4(&idx_ttp_out.t, &idx_cts)?;
    let t_ot = t0.elapsed().as_secs_f64();
    eprintln!("[psi-alt] [OT] σ={} n_b={} n_a={}: {:.3} ms", sigma, n_b, n_a, t_ot * 1e3);

    // --- TTP signs σ (server-to-server authentication) ---
    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    if !ttp_verifier.verify(&sigma_msg(&sid, sigma), &sig_sigma) {
        return Err(Error::Crypto("bad TTP signature on sigma".into()));
    }

    // --- Transcipher + AND + decrypt, in groups of `lanes` blocks ---
    // Global block_ids: the keystream() counter does not restart per group.
    let lanes = ctx.lanes();
    let n_groups_b = (n_b + lanes - 1) / lanes;
    let n_groups_a = (n_a + lanes - 1) / lanes;
    eprintln!(
        "[psi-alt] [groups] lanes={} -> {} gruppi filtro, {} gruppi indici",
        lanes, n_groups_b, n_groups_a
    );

    let mut t_transcipher = 0.0f64;
    let mut t_eval_and = 0.0f64;
    let mut t_cmux_sim = 0.0f64;
    // Serialised size of the aggregated filter ciphertexts (sum over groups)
    let mut ct_size_bytes = 0usize;

    // ---- filters: slot-wise AND across DOs, then plaintext bits (simulated CMUX) ----
    let nonce_b = [sigma as u64, 0u64];
    let mut b_bits_all: Vec<bool> = Vec::with_capacity(n_b * t);
    for g in 0..n_groups_b {
        let b0 = g * lanes;
        let b1 = ((g + 1) * lanes).min(n_b);
        // Global block IDs for this group
        let ids: Vec<u64> = (b0..b1).map(|b| b as u64).collect();

        let t0 = Instant::now();
        // Transcipher every DO's filter blocks for this group
        let mut cts: Vec<Ciphertext> = Vec::with_capacity(n);
        for a in 0..n {
            let words: Vec<Vec<u64>> = (b0..b1)
                .map(|b| pasta_sim::bytes_to_words(&m_sigmas[a][b * block_bytes..(b + 1) * block_bytes]))
                .collect();
            cts.push(fhe.transcipher(&ctx, &per_do_keys[a], nonce_b, &ids, &words)?);
        }
        t_transcipher += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        // FHE AND across all DOs
        let e_b = fhe.eval_and_all(&ctx, &cts, n)?;
        t_eval_and += t0.elapsed().as_secs_f64();
        drop(cts);
        ct_size_bytes += e_b.to_bytes().len();

        let t0 = Instant::now();
        // Decrypt the resulting bits for this group
        b_bits_all.extend(fhe.decrypt_bits(&ctx, &e_b, (b1 - b0) * t)?);
        t_cmux_sim += t0.elapsed().as_secs_f64();

        eprintln!("[psi-alt] [filtri] gruppo {}/{} ({} blocchi) fatto", g + 1, n_groups_b, b1 - b0);
    }
    b_bits_all.truncate(cfg.n_bits);

    // ---- index matrix (only DO_1): transcipher + decrypt per group ----
    let nonce_a = [(u + sigma) as u64, 0u64];
    let mut a_bits_all: Vec<bool> = Vec::with_capacity(n_a * t);
    for g in 0..n_groups_a {
        let b0 = g * lanes;
        let b1 = ((g + 1) * lanes).min(n_a);
        // Global block IDs for this group
        let ids: Vec<u64> = (b0..b1).map(|b| b as u64).collect();
        let words: Vec<Vec<u64>> = (b0..b1)
            .map(|b| pasta_sim::bytes_to_words(&m_a_sigma[b * block_bytes..(b + 1) * block_bytes]))
            .collect();

        let t0 = Instant::now();
        let ct = fhe.transcipher(&ctx, &per_do_keys[0], nonce_a, &ids, &words)?;
        t_transcipher += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        a_bits_all.extend(fhe.decrypt_bits(&ctx, &ct, (b1 - b0) * t)?);
        t_cmux_sim += t0.elapsed().as_secs_f64();

        eprintln!("[psi-alt] [indici] gruppo {}/{} ({} blocchi) fatto", g + 1, n_groups_a, b1 - b0);
    }
    a_bits_all.truncate(idx_bits_total);

    // ---- Simulated CMUX: plaintext lookup ----
    let t0 = Instant::now();
    // Reconstruct each index from its little-endian bit encoding
    let mut indices: Vec<usize> = Vec::with_capacity(m1 * h);
    for i in 0..m1 * h {
        let mut idx = 0usize;
        for k in 0..bits_per_idx {
            idx |= (a_bits_all[i * bits_per_idx + k] as usize) << k;
        }
        indices.push(idx);
    }
    // Look up each index in the decrypted filter bits
    let mut r_bits: Vec<bool> = Vec::with_capacity(m1 * h);
    for &idx in &indices {
        r_bits.push(b_bits_all.get(idx).copied().unwrap_or(false));
    }
    t_cmux_sim += t0.elapsed().as_secs_f64();

    eprintln!(
        "[psi-alt] [transcipher] totale {:.3} s | [eval_and] {:.3} s | [CMUX-sim] decrypt+{} lookup {:.3} s",
        t_transcipher, t_eval_and, m1 * h, t_cmux_sim
    );
    
    // --- DO_1 decides membership ---
    // An element is in the intersection only if all h lookups return true
    let mut do1_out: Vec<(Vec<u8>, [u8; 32])> = Vec::with_capacity(m1);
    for j in 0..m1 {
        let all_one = (0..h).all(|l| r_bits[j * h + l]);
        let token = if all_one { fresh_token() } else { [0u8; 32] };
        do1_out.push((do_inputs[0].elements[j].clone(), token));
    }

    // --- ground truth + FP/FN ---
    // Build the true set intersection across all data owners
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
    // Elements for which DO_1 issued a non-zero token
    let found: Vec<Vec<u8>> = do1_out
        .iter()
        .filter(|(_, tk)| *tk != [0u8; 32])
        .map(|(x, _)| x.clone())
        .collect();

    let expected_set: HashSet<_> = expected.iter().cloned().collect();
    let found_set: HashSet<_> = found.iter().cloned().collect();
    let false_positives = found_set.difference(&expected_set).count();
    let false_negatives = expected_set.difference(&found_set).count();

    // --- Communication cost (same accounting as Algorithm 1, no TEE) ---
    // One OT instance per DO for the filters, plus one for the index matrix of DO_1.
    // The table R sent by S_1 to DO_1 is NOT counted: the CMUX is simulated.
    let ot_ctrl = (u - 1) * 32 + 32 + 32 + 32; // DO->TTP + TTP->DO + TTP->S
    let m_b_len = m_sigmas[0].len(); // filter OT message (bytes)
    let m_a_len = m_a_sigma.len();   // index OT message (bytes)
    let comm_total_bytes = n * ot_ctrl
        + n * u * (m_b_len + 6)
        + ot_ctrl
        + u * (m_a_len + 6)
        + n * ct_size_bytes; // S_a -> S_1 (index ciphertexts are transciphered at S_1)

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
        ct_size_bytes,
        comm_total_bytes,
    })
}
