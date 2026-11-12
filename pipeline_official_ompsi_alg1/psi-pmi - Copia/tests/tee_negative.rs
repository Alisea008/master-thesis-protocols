//! Test negativi del TEE: replay, host input duplicato, firma corrotta, ecc.

use psi_pmi::bloom::HashFamilies;
use psi_pmi::pasta_fhe::{ct_fingerprint, PastaFhe, TransievePasta};
use psi_pmi::sig::{Ed25519Signer, Ed25519Verifier, Signer};
use psi_pmi::tee::{Tee1Pasta, TeeHostInputPasta};
use psi_pmi::ttp::{eval_msg, sigma_msg, Ttp};
use psi_pmi::types::fresh_sid;

use transieve::cipher::bfv::pasta::PASTA3;

fn mk_tee() -> (Tee1Pasta, TransievePasta, Ttp, Ed25519Signer) {
    let fhe = TransievePasta {
        params: PASTA3,
        force_degree: Some(8192),
    };
    let ctx = fhe.setup(1).expect("setup");

    let ttp = Ttp::new();
    let ttp_vk = ttp.signer.verifying_key_bytes();
    let ttp_verifier = Box::new(Ed25519Verifier::from_bytes(&ttp_vk).unwrap());

    let s1 = Ed25519Signer::generate();
    let s1_vk = s1.verifying_key_bytes();
    let s1_verifier = Box::new(Ed25519Verifier::from_bytes(&s1_vk).unwrap());

    let tee = Tee1Pasta::new(ctx, fhe.clone(), ttp_verifier, s1_verifier);
    (tee, fhe, ttp, s1)
}

fn mk_host_input() -> TeeHostInputPasta {
    TeeHostInputPasta {
        // d1_prime vuoto: eval_replay_rejected arriva fino in fondo a
        // process_eval senza dover decifrare alcun ciphertext SIM.
        d1_prime: vec![],
        hashes: HashFamilies::new(vec![[0u8; 32]], 1),
        k_sym: vec![0u8; 32],
    }
}

#[test]
fn host_input_double_rejected() {
    let (mut tee, _fhe, _ttp, _s1) = mk_tee();
    tee.submit_host_input(mk_host_input()).unwrap();
    let err = tee.submit_host_input(mk_host_input()).unwrap_err();
    assert!(format!("{err}").contains("already submitted"));
}

#[test]
fn sigma_bad_signature_rejected() {
    let (mut tee, _fhe, _ttp, _s1) = mk_tee();
    let sid = fresh_sid();
    let msg = sigma_msg(&sid, 2);
    let bad_sig = vec![0u8; 64];
    let err = tee.register_sigma(2, &msg, &bad_sig).unwrap_err();
    assert!(format!("{err}").contains("bad TTP signature"));
}

#[test]
fn sigma_double_rejected() {
    let (mut tee, _fhe, ttp, _s1) = mk_tee();
    let sid = fresh_sid();
    let msg = sigma_msg(&sid, 2);
    let sig = ttp.signer.sign(&msg);
    tee.register_sigma(2, &msg, &sig).unwrap();
    let err = tee.register_sigma(2, &msg, &sig).unwrap_err();
    assert!(format!("{err}").contains("already registered"));
}

#[test]
fn eval_before_sigma_rejected() {
    let (mut tee, fhe, _ttp, s1) = mk_tee();
    tee.submit_host_input(mk_host_input()).unwrap();
    let sid = fresh_sid();

    let dummy_ct = fhe.pack_key(tee.ctx(), &[0u8; 32]).unwrap();
    let fp = ct_fingerprint(&dummy_ct);
    let msg = eval_msg(&sid, &fp);
    let sig = s1.sign(&msg);

    let err = tee
        .process_eval(&sid, &dummy_ct, &sig, 128)
        .unwrap_err();
    assert!(format!("{err}").contains("sigma not registered"));
}

#[test]
fn eval_bad_signature_rejected() {
    let (mut tee, fhe, ttp, _s1) = mk_tee();
    let sid = fresh_sid();
    tee.submit_host_input(mk_host_input()).unwrap();
    let msg_sigma = sigma_msg(&sid, 0);
    let sig_sigma = ttp.signer.sign(&msg_sigma);
    tee.register_sigma(0, &msg_sigma, &sig_sigma).unwrap();

    let dummy_ct = fhe.pack_key(tee.ctx(), &[0u8; 32]).unwrap();
    let bad_sig = vec![0u8; 64];

    let err = tee
        .process_eval(&sid, &dummy_ct, &bad_sig, 128)
        .unwrap_err();
    assert!(format!("{err}").contains("bad S1 signature"));
}

#[test]
fn eval_replay_rejected() {
    // Non possiamo completare la decifratura (dummy_ct non è E_B valido), ma
    // possiamo forzare il replay di uno stesso sid una volta che è stato
    // marcato come usato. Usiamo due chiamate con firme valide: la prima
    // fallirà per "host input missing" ma NON marcherà il sid. Vogliamo
    // invece testare il caso in cui sid è marcato.
    //
    // Strategia: prendiamo un ciphertext reale dal pack_key come "E_B finto",
    // registriamo σ, host input, e facciamo process_eval due volte. La prima
    // decifrerà qualcosa (32 byte di sk cifrata, non bit validi, ma il metodo
    // non sa distinguere) → successo, sid marcato. La seconda deve fallire.
    let (mut tee, fhe, ttp, s1) = mk_tee();
    let sid = fresh_sid();
    tee.submit_host_input(mk_host_input()).unwrap();
    let msg_sigma = sigma_msg(&sid, 0);
    let sig_sigma = ttp.signer.sign(&msg_sigma);
    tee.register_sigma(0, &msg_sigma, &sig_sigma).unwrap();

    // E_B finto: qualsiasi ciphertext va bene, qui usiamo pack_key.
    let fake_e_b = fhe.pack_key(tee.ctx(), &[3u8; 32]).unwrap();
    let fp = ct_fingerprint(&fake_e_b);
    let msg = eval_msg(&sid, &fp);
    let sig = s1.sign(&msg);

    // Prima chiamata: OK
    let _ = tee.process_eval(&sid, &fake_e_b, &sig, 128).unwrap();
    // Seconda chiamata con lo stesso sid: replay
    let err = tee.process_eval(&sid, &fake_e_b, &sig, 128).unwrap_err();
    assert!(format!("{err}").contains("sid already used"));
}

#[test]
fn host_input_after_sigma_rejected() {
    let (mut tee, _fhe, ttp, _s1) = mk_tee();
    let sid = fresh_sid();
    let msg = sigma_msg(&sid, 0);
    let sig = ttp.signer.sign(&msg);
    tee.register_sigma(0, &msg, &sig).unwrap();
    let err = tee.submit_host_input(mk_host_input()).unwrap_err();
    assert!(format!("{err}").contains("sigma already registered"));
}