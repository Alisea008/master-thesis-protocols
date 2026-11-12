//! Orchestrazione end-to-end (Algorithm 2).

use std::collections::HashSet;
use std::time::Instant;

use zeroize::Zeroize;

use crate::bloom::HashFamilies;
use crate::ot::{ot_phase1, ot_phase2, ot_phase2_with_sigma, ot_phase3, ot_phase4};
use crate::pasta_fhe::{ct_fingerprint, PastaFhe, TransievePasta};
use crate::sig::{Ed25519Signer, Ed25519Verifier, Signer, Verifier};
use crate::sim::{enc_with_nonce, pasta_sim};
use crate::tee::{Tee1Pasta, TeeHostInputPasta};
use crate::ttp::{eval_msg, sigma_msg, t_msg, Ttp};
use crate::types::{fresh_sid, Sid};
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

pub fn run_e2e_pasta(
    params: PastaParams,
    force_degree: Option<usize>,
    cfg: &E2eConfig,
    do_inputs: Vec<DataOwnerInput>,
) -> Result<E2eResult> {
    let n = do_inputs.len();
    assert!(n >= 2, "at least 2 data owners (n>=2)");
    assert!(cfg.n_bits <= params.t, "filter must fit in one lane");

    let t_run = Instant::now();
    eprintln!(
        "[psi] === E2E start === n={} U={} n_bits={} hash_k={} Pasta_t={} Pasta_rounds={} force_degree={:?}",
        n, cfg.u, cfg.n_bits, cfg.hash_k, params.t, params.rounds, force_degree
    );

    let hashes = HashFamilies::new(cfg.seeds.clone(), cfg.hash_k);
    let sid = fresh_sid();

    // --- signing keys ---
    let t_sig = Instant::now();
    let ttp = Ttp::new();
    let ttp_vk = ttp.signer.verifying_key_bytes();
    let ttp_verifier = Box::new(
        Ed25519Verifier::from_bytes(&ttp_vk)
            .ok_or_else(|| Error::Crypto("bad TTP verifying key".into()))?,
    );
    // A4: a second, independent verifier for S_a to check Σ_TTP(sid, T_a).
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

    // --- FHE setup ---
    let sop_levels = (n as f64).log2().ceil() as usize;
    let fhe = TransievePasta {
        params,
        force_degree,
    };

    let t0 = Instant::now();
    let ctx = fhe.setup(sop_levels)?;
    let t_fhe_setup = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [fhe setup]   PastaBfv::new (keygen + eval keys, sop_levels={}): {:.3} s",
        sop_levels, t_fhe_setup
    );

    // --- pack_key per DO ---
    let t0 = Instant::now();
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let t_pack_key = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [pack_key]    encrypt_key for n={} DOs: {:.3} ms",
        n,
        t_pack_key * 1e3
    );

    // --- SIM ciphertexts: U filtri per DO ---
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
            let ct = pasta_sim::enc(&bits, &do_in.k_sym, nonce, params);
            m_sigma_len = m_sigma_len.max(ct.len());
            msgs.push(ct);
        }
        per_do_messages.push(msgs);
    }
    let t_sim_enc = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [SIM enc]     {} filters x {} DOs: {:.3} ms",
        u,
        n,
        t_sim_enc * 1e3
    );

    // --- TEE: host input da DO_1 ---
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

    // --- OT (Algorithm 1) con σ comune + verifica di T (A4) ---
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
        // A4: TTP signs T_a; S_a verifies the signature before using T_a.
        let t_signed = t_msg(&sid, &ttp_outs[a].t);
        let sig_t = ttp.signer.sign(&t_signed);
        if !ttp_verifier_sa.verify(&t_signed, &sig_t) {
            return Err(Error::Crypto(format!(
                "bad TTP signature on T for DO_{}",
                a + 1
            )));
        }
        let cts = ot_phase3(&states[a], &ttp_outs[a].pk0_bytes, &per_do_messages[a])?;
        let (_j, m_sigma) = ot_phase4(&ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }
    let t_ot = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [OT]          n={} U={} sigma={}: {:.3} ms",
        n,
        u,
        sigma,
        t_ot * 1e3
    );

    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    tee.register_sigma(sigma, &sigma_msg(&sid, sigma), &sig_sigma)?;

    // --- S_a: transcipher ---
    let nonce = [sigma as u64, 0u64];
    let mut e_a_vec = Vec::with_capacity(n);
    let t0 = Instant::now();
    for a in 0..n {
        let words = pasta_sim::bytes_to_words(&m_sigmas[a]);
        let len = words.len();
        let ct = tee
            .fhe()
            .transcipher(tee.ctx(), &per_do_keys[a], nonce, &[0], &[words])?;
        eprintln!(
            "[psi] [transcipher] DO_{} ({} cipher words): {:.3} s",
            a + 1,
            len,
            t0.elapsed().as_secs_f64()
        );
        e_a_vec.push(ct);
    }
    let t_transcipher = t0.elapsed().as_secs_f64();

    // --- S1: AND slot-wise ---
    let t0 = Instant::now();
    let e_b = tee.fhe().eval_and_all(tee.ctx(), &e_a_vec, n)?;
    let t_eval_and = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [eval_and]    slot-wise AND across n={} DOs: {:.3} s",
        n, t_eval_and
    );

    // A6: measure ciphertext size from the wire type (used for comm cost).
    let ct_size_bytes = {
        use fhe_traits::Serialize as FheSerialize;
        e_b.to_bytes().len()
    };

    // --- S1 firma Eval (fingerprint), TEE verifica+decifra+finish ---
    let t0 = Instant::now();
    let fp = ct_fingerprint(&e_b);
    let signed_msg = eval_msg(&sid, &fp);
    let sig_eval = s1.sign(&signed_msg);
    let out = tee.process_eval(&sid, &e_b, &sig_eval, cfg.n_bits)?;
    let t_tee = t0.elapsed().as_secs_f64();
    eprintln!(
        "[psi] [TEE]         |D1'|={} tokens in {:.3} ms (used sid count: {})",
        out.len(),
        t_tee * 1e3,
        tee.used_sid_count()
    );

    // --- A2: ground truth at n>2 (intersection across ALL DOs) ---
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

    // --- A5: observed intersection + FP/FN ---
    let found: Vec<Vec<u8>> = out
        .iter()
        .filter(|(_, tok)| *tok != [0u8; 32])
        .map(|(x, _)| x.clone())
        .collect();

    let expected_set: HashSet<_> = expected.iter().cloned().collect();
    let found_set: HashSet<_> = found.iter().cloned().collect();
    let false_positives = found_set.difference(&expected_set).count();
    let false_negatives = expected_set.difference(&found_set).count();

    // --- A6: analytical communication cost ---
    let do_to_ttp = (u - 1) * 32 + 32;    // U-1 Ristretto points + g^r
    let ttp_to_do = 32;                    // pk0
    let ttp_to_s = 32;                     // T
    let do_to_s = u * (m_sigma_len + 6);   // U SIM ciphertexts + 48-bit tag
    let s_to_s1 = ct_size_bytes;           // one transciphered ct per S_a
    let s1_to_tee = ct_size_bytes;         // E_B
    let total_bytes = n * do_to_ttp
        + n * ttp_to_do
        + n * ttp_to_s
        + n * do_to_s
        + n * s_to_s1
        + s1_to_tee;
    let comm = E2eCommCost {
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
        "[psi] === E2E done in {:.3} s | sigma={} | |expected|={} | |found|={} | FP={} | FN={} ===",
        total_s,
        sigma,
        expected.len(),
        found.len(),
        false_positives,
        false_negatives
    );

    Ok(E2eResult {
        sid,
        sigma,
        do1_out: out,
        expected_intersection: expected,
        found_intersection: found,
        false_positives,
        false_negatives,
        timings,
        comm,
    })
}