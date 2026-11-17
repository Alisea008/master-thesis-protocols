use anyhow::Result;
use std::path::Path;
use std::time::Instant;

use crate::app::{Application, Workload};
use crate::cipher::{Cipher, CipherShortint, CipherSpec, EncBitShortint, ShortintKeys};
use crate::circuit::ThresholdCircuit;
use crate::config::SampleConfig;
use crate::fhe::{evaluate_sop_boolean, run_baseline_sampled, Keys};
use crate::fhe_shortint::evaluate_sop_shortint;
use crate::timing::{peak_rss_bytes, reset_peak_rss, RunTimings};
use tfhe::shortint::parameters::{ClassicPBSParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS};

const SHORTINT_BASELINE_PARAMS: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

const BFV_SLOTS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BaselineBackend {
    #[default]
    Boolean,
    Shortint,

    Bfv,
}

impl BaselineBackend {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "boolean" | "bool" => BaselineBackend::Boolean,
            "shortint" | "short" | "si" => BaselineBackend::Shortint,
            "bfv" | "bgv" => BaselineBackend::Bfv,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BaselineBackend::Boolean => "boolean",
            BaselineBackend::Shortint => "shortint",
            BaselineBackend::Bfv => "bfv",
        }
    }
}

pub struct RunOptions<'a> {
    pub app: &'a dyn Application,
    pub party_sets_root: &'a Path,
    pub sample_bits_cap: usize,
    pub skip_fhe: bool,

    pub baseline_backend: BaselineBackend,

    pub transcipher: Option<CipherSpec>,

    pub boolean_microbench: bool,
}

pub fn run_sample(cfg: &SampleConfig, opts: RunOptions<'_>) -> Result<RunTimings> {
    reset_peak_rss();

    let t0 = Instant::now();
    let wl = opts.app.build(cfg, opts.party_sets_root)?;
    let build_s = t0.elapsed().as_secs_f64();
    let enc = wl.encoding();

    let mut t = RunTimings {
        run_tag: wl.run_tag(),
        num_parties: cfg.num_parties,
        threshold: cfg.threshold,
        num_common_ips: cfg.num_common_ips,
        party_set_size: cfg.party_set_size,
        num_bloom_bits: enc.num_bits,
        num_hash_funcs: enc.num_hash_funcs,
        dataset_source: wl.dataset_source().to_string(),
        load_dataset_s: Some(build_s),
        ..Default::default()
    };

    let operands = wl.operands();
    let circuit = wl.circuit();
    let plaintext_result = wl.plaintext_result().to_vec();

    t.circuit_num_terms = Some(circuit.num_terms());
    t.circuit_and_per_bit = Some(circuit.and_gates_per_bit());
    t.circuit_or_per_bit = Some(circuit.or_gates_per_bit());

    println!(
        "[RUN] {} | app={} | {}",
        t.run_tag,
        opts.app.name(),
        wl.summary()
    );
    println!(
        "[RUN] Circuit: {} terms, {} AND/bit, {} OR/bit -> {}",
        circuit.num_terms(),
        circuit.and_gates_per_bit(),
        circuit.or_gates_per_bit(),
        if circuit.num_parties <= 6 {
            circuit.display()
        } else {
            format!("({} terms)", circuit.num_terms())
        },
    );

    let acc = wl.accuracy();
    let recovered_plain = wl.recovered_count(&plaintext_result);
    let exact = acc.exact.unwrap_or(recovered_plain);
    let false_pos = recovered_plain.saturating_sub(exact);
    t.num_exact = Some(exact);
    t.plaintext_recovered = Some(recovered_plain);
    t.false_positives = Some(false_pos);
    if let Some(pool) = acc.candidate_pool {
        t.candidate_pool_size = Some(pool);
        let non_answer = pool.saturating_sub(exact);
        t.fpr_observed = Some(if non_answer > 0 {
            false_pos as f64 / non_answer as f64
        } else {
            0.0
        });
    }
    println!("[RUN] Plaintext recovered {recovered_plain}; exact answer {exact}");

    let mut fhe_keys_for_reuse: Option<Keys> = None;

    let effective_baseline = match opts.transcipher {
        Some(CipherSpec::Boolean(_)) => BaselineBackend::Boolean,
        Some(CipherSpec::Shortint(_)) => BaselineBackend::Shortint,
        Some(CipherSpec::Bfv(_)) => BaselineBackend::Bfv,
        None => opts.baseline_backend,
    };
    let baseline_will_run = !opts.skip_fhe;

    if baseline_will_run {
        t.fhe_backend = Some(effective_baseline.as_str().to_string());
        match effective_baseline {
            BaselineBackend::Boolean => {
                println!("[RUN] Generating TFHE Boolean keys ...");
                let t0 = Instant::now();
                let keys = Keys::generate();
                t.fhe_keygen_s = Some(t0.elapsed().as_secs_f64());

                let sample = opts.sample_bits_cap.min(t.num_bloom_bits).max(1);
                println!(
                    "[RUN] FHE baseline (boolean): evaluating {} of {} bits ({}%)",
                    sample,
                    t.num_bloom_bits,
                    (sample as f64 / t.num_bloom_bits as f64 * 100.0).round(),
                );
                let (fhe_bits, tm) = run_baseline_sampled(&keys, operands, circuit, sample);
                t.fhe_encrypt_s = Some(tm.encrypt_s);
                t.fhe_evaluate_s = Some(tm.evaluate_s);
                t.fhe_decrypt_s = Some(tm.decrypt_s);
                t.fhe_total_s = Some(tm.total_s);
                t.fhe_bits_evaluated = Some(sample);

                if sample > 0 {
                    let ratio = t.num_bloom_bits as f64 / sample as f64;
                    t.fhe_eval_full_est_s = Some(tm.evaluate_s * ratio);
                }

                let plaintext_prefix: Vec<bool> =
                    plaintext_result.iter().take(sample).copied().collect();
                let matches = plaintext_prefix == fhe_bits;
                t.encrypted_matches_plaintext = Some(matches);
                println!(
                    "[RUN] FHE sample matches plaintext prefix: {}",
                    if matches { "PASS" } else { "FAIL" }
                );

                let t0 = Instant::now();
                let mut decrypted_full = plaintext_result.clone();
                decrypted_full[..sample].copy_from_slice(&fhe_bits);
                t.num_recovered = Some(wl.recovered_count(&decrypted_full));
                t.fhe_extract_s = Some(t0.elapsed().as_secs_f64());
                fhe_keys_for_reuse = Some(keys);
            }
            BaselineBackend::Shortint => {
                run_baseline_stage_shortint(
                    operands,
                    &plaintext_result,
                    &*wl,
                    circuit,
                    opts.sample_bits_cap,
                    &mut t,
                );
            }
            BaselineBackend::Bfv => {
                #[cfg(feature = "bfv")]
                run_baseline_stage_bfv(
                    operands,
                    &plaintext_result,
                    &*wl,
                    circuit,
                    opts.sample_bits_cap,
                    &mut t,
                );
                #[cfg(not(feature = "bfv"))]
                anyhow::bail!(
                    "BFV backend selected (--baseline bfv) but the crate was built \
                     without it; rebuild with `--features bfv`"
                );
            }
        }
    }

    if let Some(cipher) = opts.transcipher {
        match cipher {
            CipherSpec::Boolean(c) => {
                if opts.boolean_microbench {
                    run_transcipher_stage_boolean(
                        c,
                        &operands[0],
                        opts.sample_bits_cap,
                        fhe_keys_for_reuse.take(),
                        &mut t,
                    )
                } else {
                    run_transcipher_stage_boolean_tpsi(
                        c,
                        operands,
                        &plaintext_result,
                        &*wl,
                        circuit,
                        opts.sample_bits_cap,
                        fhe_keys_for_reuse.take(),
                        &mut t,
                    )
                }
            }
            CipherSpec::Shortint(c) => run_transcipher_stage_shortint_tpsi(
                c,
                operands,
                &plaintext_result,
                &*wl,
                circuit,
                opts.sample_bits_cap,
                &mut t,
            ),
            CipherSpec::Bfv(c) => {
                #[cfg(feature = "bfv")]
                run_transcipher_stage_bfv_tpsi(
                    c,
                    operands,
                    &plaintext_result,
                    &*wl,
                    circuit,
                    opts.sample_bits_cap,
                    &mut t,
                );
                #[cfg(not(feature = "bfv"))]
                {
                    let _ = c;
                    anyhow::bail!(
                        "BFV transcipher (pasta) selected but the crate was built without it; \
                         rebuild with `--features bfv`"
                    );
                }
            }
        }
    }

    populate_size_metrics(&mut t, opts.baseline_backend, opts.transcipher);

    t.peak_rss_bytes = peak_rss_bytes();

    Ok(t)
}

fn run_baseline_stage_shortint(
    bits_per_party: &[Vec<bool>],
    plaintext_result: &[bool],
    wl: &dyn Workload,
    circuit: &ThresholdCircuit,
    sample_bits_cap: usize,
    t: &mut RunTimings,
) {
    let num_bits = bits_per_party[0].len();
    let sample = sample_bits_cap.min(num_bits).max(1);

    println!("[RUN] Generating TFHE shortint keys ...");
    let t0 = Instant::now();
    let keys = ShortintKeys::generate(SHORTINT_BASELINE_PARAMS);
    t.fhe_keygen_s = Some(t0.elapsed().as_secs_f64());

    println!(
        "[RUN] FHE baseline (shortint): evaluating {} of {} bits ({}%)",
        sample,
        num_bits,
        (sample as f64 / num_bits as f64 * 100.0).round(),
    );

    let t0 = Instant::now();
    let encrypted_filters: Vec<Vec<EncBitShortint>> = bits_per_party
        .iter()
        .map(|bf| {
            bf.iter()
                .take(sample)
                .map(|&b| keys.encrypt_bit(b))
                .collect()
        })
        .collect();
    t.fhe_encrypt_s = Some(t0.elapsed().as_secs_f64());

    let (sop_bits, sop_t) = evaluate_sop_shortint(&keys, &encrypted_filters, circuit);
    t.fhe_evaluate_s = Some(sop_t.evaluate_s);
    t.fhe_decrypt_s = Some(sop_t.decrypt_s);
    t.fhe_total_s = Some(t.fhe_encrypt_s.unwrap_or(0.0) + sop_t.total_s);
    t.fhe_bits_evaluated = Some(sample);

    if sample > 0 {
        let ratio = num_bits as f64 / sample as f64;
        t.fhe_eval_full_est_s = Some(sop_t.evaluate_s * ratio);
    }

    let plaintext_prefix: Vec<bool> = plaintext_result.iter().take(sample).copied().collect();
    let matches = plaintext_prefix == sop_bits;
    t.encrypted_matches_plaintext = Some(matches);
    println!(
        "[RUN] FHE sample matches plaintext prefix: {}",
        if matches { "PASS" } else { "FAIL" }
    );

    let t0 = Instant::now();
    let mut decrypted_full = plaintext_result.to_vec();
    decrypted_full[..sample].copy_from_slice(&sop_bits);
    let recovered = wl.recovered_count(&decrypted_full);
    t.fhe_extract_s = Some(t0.elapsed().as_secs_f64());
    t.num_recovered = Some(recovered);
}

#[cfg(feature = "bfv")]
fn run_baseline_stage_bfv(
    bits_per_party: &[Vec<bool>],
    plaintext_result: &[bool],
    wl: &dyn Workload,
    circuit: &ThresholdCircuit,
    sample_bits_cap: usize,
    t: &mut RunTimings,
) {
    let num_bits = bits_per_party[0].len();

    let (bits, bt) =
        match crate::fhe_bfv::evaluate_sop_bfv(bits_per_party, circuit, sample_bits_cap) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[RUN] BFV baseline failed: {e:#}");
                t.encrypted_matches_plaintext = Some(false);
                return;
            }
        };

    let sample = bits.len();
    t.fhe_keygen_s = Some(bt.keygen_s);
    t.fhe_encrypt_s = Some(bt.encrypt_s);
    t.fhe_evaluate_s = Some(bt.evaluate_s);
    t.fhe_decrypt_s = Some(bt.decrypt_s);
    t.fhe_total_s = Some(bt.encrypt_s + bt.evaluate_s + bt.decrypt_s);
    t.fhe_bits_evaluated = Some(sample);
    if sample > 0 {
        t.fhe_eval_full_est_s = Some(bt.evaluate_s * (num_bits as f64 / sample as f64));
    }

    let plaintext_prefix: Vec<bool> = plaintext_result.iter().take(sample).copied().collect();
    let matches = plaintext_prefix == bits;
    t.encrypted_matches_plaintext = Some(matches);
    println!(
        "[RUN] FHE sample matches plaintext prefix: {}",
        if matches { "PASS" } else { "FAIL" }
    );

    let t0 = Instant::now();
    let mut decrypted_full = plaintext_result.to_vec();
    decrypted_full[..sample].copy_from_slice(&bits);
    let recovered = wl.recovered_count(&decrypted_full);
    t.fhe_extract_s = Some(t0.elapsed().as_secs_f64());
    t.num_recovered = Some(recovered);
}

fn measure_boolean_ciphertext_bytes() -> Option<usize> {
    let (ck, _sk) = tfhe::boolean::gen_keys();
    let ct = ck.encrypt(false);
    bincode::serialize(&ct).ok().map(|v| v.len())
}

fn measure_shortint_ciphertext_bytes(
    parameters: tfhe::shortint::parameters::ClassicPBSParameters,
) -> Option<usize> {
    let (ck, _sk) = tfhe::shortint::gen_keys(parameters);
    let ct = ck.encrypt(0);
    bincode::serialize(&ct).ok().map(|v| v.len())
}

#[cfg(feature = "bfv")]
fn bfv_secure_ct_bytes() -> Option<(usize, usize)> {
    use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
    use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
    let moduli_sizes = vec![55usize; 5];
    let total_q: usize = moduli_sizes.iter().sum();
    let degree = crate::fhe_bfv::secure_degree_128(total_q, BFV_SLOTS).ok()?;
    let params = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(65537)
        .set_moduli_sizes(&moduli_sizes)
        .build_arc()
        .ok()?;
    let mut rng = rand_bfv::rng();
    let sk = SecretKey::random(&params, &mut rng);
    let pt = Plaintext::try_encode(&vec![0u64; degree], Encoding::simd(), &params).ok()?;
    let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng).ok()?;
    Some((degree, ct.to_bytes().len()))
}

#[cfg(not(feature = "bfv"))]
fn bfv_secure_ct_bytes() -> Option<(usize, usize)> {
    None
}

fn populate_size_metrics(
    t: &mut RunTimings,
    baseline: BaselineBackend,
    cipher: Option<CipherSpec>,
) {
    let bloom_bits = t.num_bloom_bits;
    if bloom_bits == 0 {
        return;
    }

    let plain_bytes = (bloom_bits + 7) / 8;
    t.payload_plain_bytes = Some(plain_bytes);

    let bool_ct_bytes = measure_boolean_ciphertext_bytes().unwrap_or(0);

    let direct_backend = match cipher {
        Some(CipherSpec::Boolean(_)) => BaselineBackend::Boolean,
        Some(CipherSpec::Shortint(_)) => BaselineBackend::Shortint,
        Some(CipherSpec::Bfv(_)) => BaselineBackend::Bfv,
        None => baseline,
    };

    let bfv_ct = if matches!(direct_backend, BaselineBackend::Bfv)
        || matches!(cipher, Some(CipherSpec::Bfv(_)))
    {
        bfv_secure_ct_bytes()
    } else {
        None
    };
    let direct_ct_bytes = match direct_backend {
        BaselineBackend::Boolean => bool_ct_bytes,
        BaselineBackend::Shortint => {
            let params = match cipher {
                Some(CipherSpec::Shortint(c)) => c.parameters(),
                _ => SHORTINT_BASELINE_PARAMS,
            };
            measure_shortint_ciphertext_bytes(params).unwrap_or(0)
        }
        BaselineBackend::Bfv => bfv_ct.map(|(_, b)| b).unwrap_or(0),
    };
    if direct_ct_bytes > 0 {
        let direct = match direct_backend {
            BaselineBackend::Bfv => {
                let slots = bfv_ct.map(|(s, _)| s).unwrap_or(BFV_SLOTS);
                direct_ct_bytes.saturating_mul(bloom_bits.div_ceil(slots))
            }
            _ => direct_ct_bytes.saturating_mul(bloom_bits),
        };
        t.payload_fhe_direct_bytes = Some(direct);
        t.expansion_fhe_direct = Some(direct as f64 / plain_bytes as f64);
    }

    if let Some(cipher) = cipher {
        let sym_bits = cipher.sym_ciphertext_bits(bloom_bits);
        let sym_bytes = (sym_bits + 7) / 8;

        let key_payload_bytes = match cipher {
            CipherSpec::Boolean(_) => Some(bool_ct_bytes.saturating_mul(cipher.key_bits())),
            CipherSpec::Shortint(c) => measure_shortint_ciphertext_bytes(c.parameters())
                .map(|kb| kb.saturating_mul(cipher.key_bits())),
            CipherSpec::Bfv(_) => bfv_ct.map(|(_, b)| b),
        };
        if let Some(key_bytes) = key_payload_bytes.filter(|&v| v > 0) {
            let tc_bytes = sym_bytes + key_bytes;
            t.payload_transcipher_bytes = Some(tc_bytes);
            t.expansion_transcipher = Some(tc_bytes as f64 / plain_bytes as f64);
            if let Some(direct) = t.payload_fhe_direct_bytes {
                t.bandwidth_savings_ratio = Some(direct as f64 / tc_bytes as f64);
            }
        }

        if let (Some(per_bit_total), Some(bits)) =
            (t.transcipher_per_bit_total_s, t.transcipher_bits_evaluated)
        {
            if bits > 0 {
                let ms_per_bit = per_bit_total * 1000.0 / bits as f64;
                t.transcipher_ms_per_bit = Some(ms_per_bit);
                let init = t.transcipher_init_s.unwrap_or(0.0);
                t.transcipher_full_payload_est_s =
                    Some(init + ms_per_bit / 1000.0 * bloom_bits as f64);
                if per_bit_total > 0.0 {
                    t.transcipher_throughput_bps = Some(bits as f64 / per_bit_total);
                }
            }
        }
    }
}

fn random_sym_key(bits: usize) -> Vec<bool> {
    random_sym_key_seeded(bits, 0xCAFE_BABE)
}

fn random_sym_key_seeded(bits: usize, seed: u64) -> Vec<bool> {
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    let mut rng = StdRng::seed_from_u64(seed);
    let mut sym_key = vec![false; bits];
    for chunk in sym_key.chunks_mut(64) {
        let r = rng.next_u64();
        for (i, slot) in chunk.iter_mut().enumerate() {
            *slot = ((r >> i) & 1) == 1;
        }
    }
    sym_key
}

fn record_cipher_metadata(cipher: CipherSpec, bits: usize, t: &mut RunTimings) {
    t.transcipher_name = Some(cipher.name().to_string());
    t.transcipher_backend = Some(cipher.backend().to_string());
    t.transcipher_bits_evaluated = Some(bits);
    t.transcipher_pbs_per_output_bit = Some(cipher.pbs_per_output_bit());
    t.transcipher_multiplicative_depth = Some(cipher.multiplicative_depth());
    t.transcipher_fixed_init_pbs = Some(cipher.fixed_init_pbs());
}

fn run_transcipher_stage_boolean(
    cipher: Cipher,
    bloom_bits: &[bool],
    sample_bits_cap: usize,
    reused_keys: Option<Keys>,
    t: &mut RunTimings,
) {
    let spec = CipherSpec::Boolean(cipher);
    let bits = sample_bits_cap.min(bloom_bits.len()).max(1);
    let plaintext: Vec<bool> = bloom_bits.iter().take(bits).copied().collect();

    println!(
        "\n[TRANSCIPHER boolean] {} on {} bit(s) of party 0's filter",
        cipher.name(),
        bits,
    );
    record_cipher_metadata(spec, bits, t);

    let t0 = Instant::now();
    let sym_key = random_sym_key(cipher.key_bits());
    t.transcipher_sym_keygen_s = Some(t0.elapsed().as_secs_f64());

    let t0 = Instant::now();
    let sym_ciphertext = cipher.encrypt_stream(&sym_key, &plaintext);
    t.transcipher_sym_encrypt_s = Some(t0.elapsed().as_secs_f64());
    t.transcipher_sym_ciphertext_bits = Some(sym_ciphertext.len());
    println!(
        "[TRANSCIPHER] symmetric encrypt: {:.3}s ({} bits)",
        t.transcipher_sym_encrypt_s.unwrap(),
        sym_ciphertext.len(),
    );

    let keys = match reused_keys {
        Some(k) => k,
        None => {
            println!("[TRANSCIPHER] generating fresh TFHE keys (baseline skipped) ...");
            let t0 = Instant::now();
            let k = Keys::generate();
            t.transcipher_fhe_keygen_s = Some(t0.elapsed().as_secs_f64());
            k
        }
    };
    let t0 = Instant::now();
    let enc_key: Vec<crate::cipher::EncBit> = sym_key
        .iter()
        .map(|&b| keys.client_key.encrypt(b))
        .collect();
    t.transcipher_key_encrypt_s = Some(t0.elapsed().as_secs_f64());

    println!("[TRANSCIPHER] running homomorphic decryption circuit ...");
    let (recovered, dt) =
        cipher.decrypt_homomorphic_timed(&keys.server_key, &enc_key, &sym_ciphertext);
    t.transcipher_init_s = Some(dt.init_s);
    t.transcipher_per_bit_total_s = Some(dt.per_bit_total_s);
    t.transcipher_homomorphic_decrypt_s = Some(dt.init_s + dt.per_bit_total_s);
    println!(
        "[TRANSCIPHER] homomorphic decrypt: init={:.3}s, per-bit total={:.3}s ({:.1} ms/bit), {} bits",
        dt.init_s,
        dt.per_bit_total_s,
        dt.s_per_bit() * 1000.0,
        dt.bits,
    );

    let total = t.transcipher_sym_keygen_s.unwrap()
        + t.transcipher_sym_encrypt_s.unwrap()
        + t.transcipher_fhe_keygen_s.unwrap_or(0.0)
        + t.transcipher_key_encrypt_s.unwrap()
        + t.transcipher_homomorphic_decrypt_s.unwrap();
    t.transcipher_total_s = Some(total);

    let recovered_plain: Vec<bool> = recovered
        .iter()
        .map(|ct| keys.client_key.decrypt(ct))
        .collect();
    let matches = recovered_plain == plaintext;
    t.transcipher_matches_plaintext = Some(matches);
    println!(
        "[TRANSCIPHER] roundtrip matches plaintext: {}",
        if matches { "PASS" } else { "FAIL" },
    );
}

#[allow(clippy::too_many_arguments)]
fn run_transcipher_stage_boolean_tpsi(
    cipher: Cipher,
    bits_per_party: &[Vec<bool>],
    plaintext_sop_result: &[bool],
    wl: &dyn Workload,
    circuit: &ThresholdCircuit,
    sample_bits_cap: usize,
    reused_keys: Option<Keys>,
    t: &mut RunTimings,
) {
    let spec = CipherSpec::Boolean(cipher);
    let num_parties = bits_per_party.len();
    assert!(num_parties > 0);
    let num_bits = bits_per_party[0].len();
    let bits = sample_bits_cap.min(num_bits).max(1);
    let plaintext_prefixes: Vec<Vec<bool>> = bits_per_party
        .iter()
        .map(|bf| bf.iter().take(bits).copied().collect())
        .collect();

    println!(
        "\n[TRANSCIPHER boolean TPSI] {} on {} party filter(s), {} bit(s) each",
        cipher.name(),
        num_parties,
        bits,
    );
    record_cipher_metadata(spec, bits, t);
    t.transcipher_parties_transciphered = Some(num_parties);

    let keys = match reused_keys {
        Some(k) => k,
        None => {
            println!("[TRANSCIPHER] generating fresh TFHE Boolean keys (baseline skipped) ...");
            let t0 = Instant::now();
            let k = Keys::generate();
            t.transcipher_fhe_keygen_s = Some(t0.elapsed().as_secs_f64());
            k
        }
    };

    let mut total_sym_keygen_s = 0.0;
    let mut total_sym_encrypt_s = 0.0;
    let mut total_key_encrypt_s = 0.0;
    let mut total_init_s = 0.0;
    let mut total_per_bit_s = 0.0;
    let mut total_sym_ciphertext_bits = 0usize;
    let mut all_party_roundtrip_ok = true;
    let mut encrypted_filters: Vec<Vec<crate::cipher::EncBit>> = Vec::with_capacity(num_parties);

    for (party_idx, prefix) in plaintext_prefixes.iter().enumerate() {
        let t0 = Instant::now();
        let sym_key = random_sym_key_seeded(cipher.key_bits(), 0xCAFE_BABE ^ party_idx as u64);
        total_sym_keygen_s += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let sym_ciphertext = spec.encrypt_stream(&sym_key, prefix);
        total_sym_encrypt_s += t0.elapsed().as_secs_f64();
        total_sym_ciphertext_bits += sym_ciphertext.len();

        let t0 = Instant::now();
        let enc_key: Vec<crate::cipher::EncBit> = sym_key
            .iter()
            .map(|&b| keys.client_key.encrypt(b))
            .collect();
        total_key_encrypt_s += t0.elapsed().as_secs_f64();

        println!(
            "[TRANSCIPHER] party {}/{}: homomorphic decrypt ({} bits) ...",
            party_idx + 1,
            num_parties,
            sym_ciphertext.len(),
        );
        let (recovered, dt) =
            cipher.decrypt_homomorphic_timed(&keys.server_key, &enc_key, &sym_ciphertext);
        total_init_s += dt.init_s;
        total_per_bit_s += dt.per_bit_total_s;
        println!(
            "  party {}: init={:.3}s, per-bit total={:.3}s ({:.1} ms/bit)",
            party_idx,
            dt.init_s,
            dt.per_bit_total_s,
            dt.s_per_bit() * 1000.0,
        );

        let roundtrip: Vec<bool> = recovered
            .iter()
            .map(|ct| keys.client_key.decrypt(ct))
            .collect();
        if &roundtrip != prefix {
            all_party_roundtrip_ok = false;
            println!("  party {}: WARN — roundtrip mismatch", party_idx);
        }
        encrypted_filters.push(recovered);
    }

    let avg_init_s = total_init_s / num_parties as f64;
    let avg_per_bit_s = total_per_bit_s / num_parties as f64;
    t.transcipher_sym_keygen_s = Some(total_sym_keygen_s);
    t.transcipher_sym_encrypt_s = Some(total_sym_encrypt_s);
    t.transcipher_key_encrypt_s = Some(total_key_encrypt_s);
    t.transcipher_init_s = Some(avg_init_s);
    t.transcipher_per_bit_total_s = Some(avg_per_bit_s);
    t.transcipher_homomorphic_decrypt_s = Some(avg_init_s + avg_per_bit_s);
    t.transcipher_sym_ciphertext_bits = Some(total_sym_ciphertext_bits / num_parties);
    t.transcipher_matches_plaintext = Some(all_party_roundtrip_ok);
    println!(
        "[TRANSCIPHER] all-parties roundtrip: {}",
        if all_party_roundtrip_ok {
            "PASS"
        } else {
            "FAIL"
        },
    );

    println!(
        "[TRANSCIPHER] evaluating Boolean SOP ({} terms, {} bits) ...",
        circuit.num_terms(),
        bits,
    );
    let (sop_bits, sop_timings) = evaluate_sop_boolean(&keys, &encrypted_filters, circuit);
    t.transcipher_sop_evaluate_s = Some(sop_timings.evaluate_s);
    t.transcipher_sop_decrypt_s = Some(sop_timings.decrypt_s);
    t.transcipher_sop_total_s = Some(sop_timings.total_s);
    println!(
        "[TRANSCIPHER] SOP eval={:.3}s, decrypt={:.3}s",
        sop_timings.evaluate_s, sop_timings.decrypt_s,
    );

    let plaintext_prefix: Vec<bool> = plaintext_sop_result.iter().take(bits).copied().collect();
    let sop_match = sop_bits == plaintext_prefix;
    t.transcipher_sop_matches_plaintext = Some(sop_match);
    println!(
        "[TRANSCIPHER] SOP match vs plaintext: {}",
        if sop_match { "PASS" } else { "FAIL" },
    );

    let mut intersection_full: Vec<bool> = plaintext_sop_result.to_vec();
    intersection_full[..bits].copy_from_slice(&sop_bits);
    let recovered = wl.recovered_count(&intersection_full);
    t.transcipher_num_recovered = Some(recovered);
    println!(
        "[TRANSCIPHER] recovered {} candidate(s) from Boolean TPSI",
        recovered
    );

    let total = t.transcipher_fhe_keygen_s.unwrap_or(0.0)
        + total_sym_keygen_s
        + total_sym_encrypt_s
        + total_key_encrypt_s
        + total_init_s
        + total_per_bit_s
        + sop_timings.total_s;
    t.transcipher_total_s = Some(total);
}

#[allow(clippy::too_many_arguments)]
fn run_transcipher_stage_shortint_tpsi(
    cipher: CipherShortint,
    bits_per_party: &[Vec<bool>],
    plaintext_sop_result: &[bool],
    wl: &dyn Workload,
    circuit: &ThresholdCircuit,
    sample_bits_cap: usize,
    t: &mut RunTimings,
) {
    let spec = CipherSpec::Shortint(cipher);
    let num_parties = bits_per_party.len();
    assert!(num_parties > 0);
    let num_bits = bits_per_party[0].len();
    let bits = sample_bits_cap.min(num_bits).max(1);
    let plaintext_prefixes: Vec<Vec<bool>> = bits_per_party
        .iter()
        .map(|bf| bf.iter().take(bits).copied().collect())
        .collect();

    println!(
        "\n[TRANSCIPHER shortint TPSI] {} on {} party filter(s), {} bit(s) each",
        cipher.name(),
        num_parties,
        bits,
    );
    record_cipher_metadata(spec, bits, t);
    t.transcipher_parties_transciphered = Some(num_parties);

    println!(
        "[TRANSCIPHER] generating shortint TFHE keys for {} ...",
        cipher.name(),
    );
    let t0 = Instant::now();
    let keys = ShortintKeys::generate(cipher.parameters());
    t.transcipher_fhe_keygen_s = Some(t0.elapsed().as_secs_f64());

    let mut total_sym_keygen_s = 0.0;
    let mut total_sym_encrypt_s = 0.0;
    let mut total_key_encrypt_s = 0.0;
    let mut total_init_s = 0.0;
    let mut total_per_bit_s = 0.0;
    let mut total_sym_ciphertext_bits = 0usize;
    let mut all_party_roundtrip_ok = true;
    let mut encrypted_filters: Vec<Vec<EncBitShortint>> = Vec::with_capacity(num_parties);

    for (party_idx, prefix) in plaintext_prefixes.iter().enumerate() {
        let t0 = Instant::now();
        let sym_key = random_sym_key_seeded(cipher.key_bits(), 0xCAFE_BABE ^ party_idx as u64);
        total_sym_keygen_s += t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let sym_ciphertext = spec.encrypt_stream(&sym_key, prefix);
        total_sym_encrypt_s += t0.elapsed().as_secs_f64();
        total_sym_ciphertext_bits += sym_ciphertext.len();

        let t0 = Instant::now();
        let enc_key: Vec<EncBitShortint> = sym_key.iter().map(|&b| keys.encrypt_bit(b)).collect();
        total_key_encrypt_s += t0.elapsed().as_secs_f64();

        println!(
            "[TRANSCIPHER] party {}/{}: homomorphic decrypt ({} bits) ...",
            party_idx + 1,
            num_parties,
            sym_ciphertext.len(),
        );
        let (recovered, dt) = cipher.decrypt_homomorphic_timed(&keys, &enc_key, &sym_ciphertext);
        total_init_s += dt.init_s;
        total_per_bit_s += dt.per_bit_total_s;
        println!(
            "  party {}: init={:.3}s, per-bit total={:.3}s ({:.1} ms/bit)",
            party_idx,
            dt.init_s,
            dt.per_bit_total_s,
            dt.s_per_bit() * 1000.0,
        );

        let roundtrip: Vec<bool> = recovered.iter().map(|ct| keys.decrypt_bit(ct)).collect();
        if &roundtrip != prefix {
            all_party_roundtrip_ok = false;
            println!("  party {}: WARN — roundtrip mismatch", party_idx);
        }

        encrypted_filters.push(recovered);
    }

    let avg_init_s = total_init_s / num_parties as f64;
    let avg_per_bit_s = total_per_bit_s / num_parties as f64;
    t.transcipher_sym_keygen_s = Some(total_sym_keygen_s);
    t.transcipher_sym_encrypt_s = Some(total_sym_encrypt_s);
    t.transcipher_key_encrypt_s = Some(total_key_encrypt_s);
    t.transcipher_init_s = Some(avg_init_s);
    t.transcipher_per_bit_total_s = Some(avg_per_bit_s);
    t.transcipher_homomorphic_decrypt_s = Some(avg_init_s + avg_per_bit_s);
    t.transcipher_sym_ciphertext_bits = Some(total_sym_ciphertext_bits / num_parties);
    t.transcipher_matches_plaintext = Some(all_party_roundtrip_ok);
    println!(
        "[TRANSCIPHER] all-parties roundtrip: {}",
        if all_party_roundtrip_ok {
            "PASS"
        } else {
            "FAIL"
        },
    );

    println!(
        "[TRANSCIPHER] evaluating shortint SOP ({} terms, {} bits) ...",
        circuit.num_terms(),
        bits,
    );
    let (sop_bits, sop_timings) = evaluate_sop_shortint(&keys, &encrypted_filters, circuit);
    t.transcipher_sop_evaluate_s = Some(sop_timings.evaluate_s);
    t.transcipher_sop_decrypt_s = Some(sop_timings.decrypt_s);
    t.transcipher_sop_total_s = Some(sop_timings.total_s);
    println!(
        "[TRANSCIPHER] SOP eval={:.3}s, decrypt={:.3}s",
        sop_timings.evaluate_s, sop_timings.decrypt_s,
    );

    let plaintext_prefix: Vec<bool> = plaintext_sop_result.iter().take(bits).copied().collect();
    let sop_match = sop_bits == plaintext_prefix;
    t.transcipher_sop_matches_plaintext = Some(sop_match);
    println!(
        "[TRANSCIPHER] SOP match vs plaintext: {}",
        if sop_match { "PASS" } else { "FAIL" },
    );

    let mut intersection_full: Vec<bool> = plaintext_sop_result.to_vec();
    intersection_full[..bits].copy_from_slice(&sop_bits);
    let recovered = wl.recovered_count(&intersection_full);
    t.transcipher_num_recovered = Some(recovered);
    println!(
        "[TRANSCIPHER] recovered {} candidate IP(s) from shortint TPSI",
        recovered,
    );

    let total = t.transcipher_fhe_keygen_s.unwrap_or(0.0)
        + total_sym_keygen_s
        + total_sym_encrypt_s
        + total_key_encrypt_s
        + total_init_s
        + total_per_bit_s
        + sop_timings.total_s;
    t.transcipher_total_s = Some(total);
}

#[cfg(feature = "bfv")]
fn random_pasta_key(words: usize, seed: u64) -> Vec<u64> {
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    let mut rng = StdRng::seed_from_u64(seed);
    (0..words).map(|_| rng.next_u64() % 65537).collect()
}

#[cfg(feature = "bfv")]
#[allow(clippy::too_many_arguments)]
fn run_transcipher_stage_bfv_tpsi(
    cipher: crate::cipher::CipherBfv,
    bits_per_party: &[Vec<bool>],
    plaintext_sop_result: &[bool],
    wl: &dyn Workload,
    circuit: &ThresholdCircuit,
    sample_bits_cap: usize,
    t: &mut RunTimings,
) {
    use crate::cipher::bfv::pasta::{self, PastaBfv};
    use fhe::bfv::Ciphertext;

    let spec = CipherSpec::Bfv(cipher);
    let params = cipher.pasta_params();
    let block = params.t;
    let num_parties = bits_per_party.len();
    assert!(num_parties > 0);
    let num_bits = bits_per_party[0].len();
    let sample = sample_bits_cap.min(num_bits).max(1);
    let blocks_total = sample.div_ceil(block);
    let nonce = [0xA5A5_5A5Au64, 0x5A5A_A5A5u64];

    if !matches!(cipher, crate::cipher::CipherBfv::Pasta) {
        eprintln!(
            "[TRANSCIPHER] {} is not implemented on the BFV pipeline (only Pasta is); \
             refusing so it can't be mislabelled as Pasta.",
            cipher.name(),
        );
        record_cipher_metadata(spec, sample, t);
        t.transcipher_matches_plaintext = Some(false);
        t.transcipher_sop_matches_plaintext = Some(false);
        return;
    }

    record_cipher_metadata(spec, sample, t);
    t.transcipher_parties_transciphered = Some(num_parties);

    let ceil_log2 = |n: usize| {
        if n <= 1 {
            0
        } else {
            (usize::BITS - (n - 1).leading_zeros()) as usize
        }
    };
    let sop_levels = ceil_log2(circuit.threshold) + ceil_log2(circuit.num_terms());

    println!(
        "[TRANSCIPHER] BFV secure keygen (Pasta-{} rounds, +{} SOP level(s)) ...",
        params.rounds, sop_levels
    );
    let t0 = Instant::now();
    let pb = match PastaBfv::new_secure(params, sop_levels) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[TRANSCIPHER] BFV setup failed: {e:#}");
            t.transcipher_matches_plaintext = Some(false);
            return;
        }
    };
    t.transcipher_fhe_keygen_s = Some(t0.elapsed().as_secs_f64());
    let lanes = pb.lanes();
    let perms = blocks_total.div_ceil(lanes);

    println!(
        "\n[TRANSCIPHER bfv TPSI] {} on {} party filter(s), {} bit(s) each \
         ({} block(s) of t={}; {} lane(s)/perm => {} permutation(s)/party)",
        cipher.name(),
        num_parties,
        sample,
        blocks_total,
        block,
        lanes,
        perms,
    );

    let mut total_sym_keygen_s = 0.0;
    let mut total_sym_encrypt_s = 0.0;
    let mut total_key_encrypt_s = 0.0;
    let mut total_sym_bits = 0usize;
    let mut party_c: Vec<Vec<u64>> = Vec::with_capacity(num_parties);
    let mut key_cts: Vec<Ciphertext> = Vec::with_capacity(num_parties);
    for (pi, bf) in bits_per_party.iter().enumerate() {
        let t0 = Instant::now();
        let key = random_pasta_key(2 * block, 0xCAFE_BABE ^ pi as u64);
        total_sym_keygen_s += t0.elapsed().as_secs_f64();

        let msg: Vec<u64> = bf[..sample].iter().map(|&b| b as u64).collect();
        let t0 = Instant::now();
        let c = pasta::encrypt(&key, &msg, nonce, params);
        total_sym_encrypt_s += t0.elapsed().as_secs_f64();
        total_sym_bits += c.len() * cipher.bits_per_word();

        let t0 = Instant::now();
        let key_ct = match pb.pack_key(&key[..block], &key[block..]) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[TRANSCIPHER] pack_key failed: {e:#}");
                t.transcipher_matches_plaintext = Some(false);
                return;
            }
        };
        total_key_encrypt_s += t0.elapsed().as_secs_f64();
        party_c.push(c);
        key_cts.push(key_ct);
    }

    let mut total_recover_s = 0.0;
    let mut sop_eval_s = 0.0;
    let mut sop_dec_s = 0.0;
    let mut sop_bits: Vec<bool> = Vec::with_capacity(sample);
    let mut roundtrip_ok = true;
    for ch in 0..perms {
        let first = ch * lanes;
        let last = ((ch + 1) * lanes).min(blocks_total);
        let bids: Vec<u64> = (first..last).map(|b| b as u64).collect();
        let lens: Vec<usize> = bids
            .iter()
            .map(|&b| block.min(sample - b as usize * block))
            .collect();

        let mut party_cts: Vec<Ciphertext> = Vec::with_capacity(num_parties);
        for pi in 0..num_parties {
            let words: Vec<&[u64]> = bids
                .iter()
                .map(|&b| {
                    let start = b as usize * block;
                    let stop = (start + block).min(sample);
                    &party_c[pi][start..stop]
                })
                .collect();
            let t0 = Instant::now();
            let rec = match pb.transcipher_recover_blocks(&key_cts[pi], nonce, &bids, &words) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[TRANSCIPHER] recover failed: {e:#}");
                    t.transcipher_matches_plaintext = Some(false);
                    return;
                }
            };
            total_recover_s += t0.elapsed().as_secs_f64();
            if let Ok(rt) = pb.decrypt_lane_bits(&rec, &lens) {
                let cstart = first * block;
                if rt.as_slice() != &bits_per_party[pi][cstart..cstart + rt.len()] {
                    roundtrip_ok = false;
                }
            }
            party_cts.push(rec);
        }

        let t0 = Instant::now();
        let res = match pb.evaluate_sop(&party_cts, circuit) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[TRANSCIPHER] SOP failed: {e:#}");
                t.transcipher_sop_matches_plaintext = Some(false);
                return;
            }
        };
        sop_eval_s += t0.elapsed().as_secs_f64();
        let t0 = Instant::now();
        let bits = pb.decrypt_lane_bits(&res, &lens).unwrap_or_default();
        sop_dec_s += t0.elapsed().as_secs_f64();
        sop_bits.extend(bits);
    }

    let avg_recover_s = total_recover_s / num_parties as f64;
    t.transcipher_sym_keygen_s = Some(total_sym_keygen_s);
    t.transcipher_sym_encrypt_s = Some(total_sym_encrypt_s);
    t.transcipher_key_encrypt_s = Some(total_key_encrypt_s);
    t.transcipher_init_s = Some(0.0); // leveled BFV has no fixed PBS-style init
    t.transcipher_per_bit_total_s = Some(avg_recover_s);
    t.transcipher_homomorphic_decrypt_s = Some(avg_recover_s);
    t.transcipher_sym_ciphertext_bits = Some(total_sym_bits / num_parties);
    t.transcipher_matches_plaintext = Some(roundtrip_ok);
    println!(
        "[TRANSCIPHER] all-parties roundtrip: {}",
        if roundtrip_ok { "PASS" } else { "FAIL" },
    );

    t.transcipher_sop_evaluate_s = Some(sop_eval_s);
    t.transcipher_sop_decrypt_s = Some(sop_dec_s);
    t.transcipher_sop_total_s = Some(sop_eval_s + sop_dec_s);
    println!(
        "[TRANSCIPHER] SOP eval={:.3}s, decrypt={:.3}s",
        sop_eval_s, sop_dec_s
    );

    let plaintext_prefix: Vec<bool> = plaintext_sop_result.iter().take(sample).copied().collect();
    let sop_match = sop_bits == plaintext_prefix;
    t.transcipher_sop_matches_plaintext = Some(sop_match);
    println!(
        "[TRANSCIPHER] SOP match vs plaintext: {}",
        if sop_match { "PASS" } else { "FAIL" },
    );

    let mut intersection_full: Vec<bool> = plaintext_sop_result.to_vec();
    intersection_full[..sample].copy_from_slice(&sop_bits);
    let recovered = wl.recovered_count(&intersection_full);
    t.transcipher_num_recovered = Some(recovered);
    println!(
        "[TRANSCIPHER] recovered {} candidate IP(s) from BFV TPSI",
        recovered,
    );

    let total = t.transcipher_fhe_keygen_s.unwrap_or(0.0)
        + total_sym_keygen_s
        + total_sym_encrypt_s
        + total_key_encrypt_s
        + total_recover_s
        + sop_eval_s
        + sop_dec_s;
    t.transcipher_total_s = Some(total);
}
