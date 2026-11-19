use std::collections::HashSet;

use fhe::bfv::Ciphertext;

use crate::bloom::HashFamilies;
use crate::pasta_fhe::{ct_fingerprint_multi, PastaFhe, TransievePasta};
use crate::sig::Verifier;
use crate::ttp::eval_msg;
use crate::types::{fresh_token, Sid};
use crate::{Error, Result};

pub struct TeeHostInputPasta {
    pub d1_prime: Vec<Vec<u8>>,
    pub hashes: HashFamilies,
    pub k_sym: Vec<u8>,
}

impl Drop for TeeHostInputPasta {
    fn drop(&mut self) {
        // A3: wipe the symmetric key (and the ciphertexts it protects).
        use zeroize::Zeroize;
        self.k_sym.zeroize();
        for e in &mut self.d1_prime {
            e.zeroize();
        }
    }
}

pub struct Tee1Pasta {
    ctx: transieve::cipher::bfv::pasta::PastaBfv,
    fhe: TransievePasta,
    ttp_verifier: Box<dyn Verifier>,
    s1_verifier: Box<dyn Verifier>,
    host_input: Option<TeeHostInputPasta>,
    sigma: Option<usize>,
    used_sids: HashSet<Sid>,
}

impl Tee1Pasta {
    pub fn new(
        ctx: transieve::cipher::bfv::pasta::PastaBfv,
        fhe: TransievePasta,
        ttp_verifier: Box<dyn Verifier>,
        s1_verifier: Box<dyn Verifier>,
    ) -> Self {
        Self {
            ctx,
            fhe,
            ttp_verifier,
            s1_verifier,
            host_input: None,
            sigma: None,
            used_sids: HashSet::new(),
        }
    }

    pub fn ctx(&self) -> &transieve::cipher::bfv::pasta::PastaBfv {
        &self.ctx
    }
    pub fn fhe(&self) -> &TransievePasta {
        &self.fhe
    }

    /// Host input (D1', H, k_sym^(1)). Accettato una sola volta e solo se σ
    /// non è ancora stato registrato (Passo 3 del PDF).
    pub fn submit_host_input(&mut self, input: TeeHostInputPasta) -> Result<()> {
        if self.sigma.is_some() {
            return Err(Error::TeeAbort("sigma already registered".into()));
        }
        if self.host_input.is_some() {
            return Err(Error::TeeAbort("host input already submitted".into()));
        }
        self.host_input = Some(input);
        Ok(())
    }

    /// σ firmato dal TTP. Accettato una sola volta.
    pub fn register_sigma(&mut self, sigma: usize, signed_msg: &[u8], sig: &[u8]) -> Result<()> {
        if !self.ttp_verifier.verify(signed_msg, sig) {
            return Err(Error::TeeAbort("bad TTP signature on sigma".into()));
        }
        if self.sigma.is_some() {
            return Err(Error::TeeAbort("sigma already registered".into()));
        }
        self.sigma = Some(sigma);
        Ok(())
    }

    /// Unico punto di ingresso per `Eval`.
    ///
    /// Atomicamente:
    ///   1. rifiuta sid già usato (anti-replay)
    ///   2. ricalcola fingerprint di `e_b` e verifica firma S1 su `eval_msg(sid, fp)`
    ///   3. richiede σ e host input già registrati
    ///   4. decifra `e_b`, calcola Out
    ///   5. marca il sid come usato
    ///
    /// Il ciphertext `e_b` non è serializzato: è passato in-process. La firma
    /// di S1 è sul fingerprint SHAKE256, non sui byte serde.
    pub fn process_eval(
    &mut self,
    sid: &Sid,
    e_b: &[Ciphertext],
    sig: &[u8],
    num_bits: usize,
) -> Result<Vec<(Vec<u8>, [u8; 32])>> {
    // 1. anti-replay
    if self.used_sids.contains(sid) {
        return Err(Error::TeeAbort("sid already used".into()));
    }
    // 2. firma S1 sul fingerprint dell'intera sequenza di gruppi
    let fp = ct_fingerprint_multi(e_b);
    let signed_msg = eval_msg(sid, &fp);
    if !self.s1_verifier.verify(&signed_msg, sig) {
        return Err(Error::TeeAbort("bad S1 signature on Eval".into()));
    }
    // 3. numero di gruppi coerente con num_bits
    let per_group = self.ctx.lanes() * self.fhe.params.t;
    let expected_groups = (num_bits + per_group - 1) / per_group;
    if e_b.len() != expected_groups {
        return Err(Error::TeeAbort(format!(
            "expected {} ciphertext groups, got {}", expected_groups, e_b.len()
        )));
    }
    // 4. stato preregistrato
    let sigma = self
        .sigma
        .ok_or_else(|| Error::TeeAbort("sigma not registered".into()))?;
    let host = self
        .host_input
        .take()
        .ok_or_else(|| Error::TeeAbort("host input missing".into()))?;
    // 5. decifra ogni gruppo e concatena
    let mut b_bits: Vec<bool> = Vec::with_capacity(num_bits);
    for (g, ct) in e_b.iter().enumerate() {
        let nb = per_group.min(num_bits - g * per_group);
        b_bits.extend(self.fhe.decrypt_bits(&self.ctx, ct, nb)?);
    }
    let family = host.hashes.get(sigma);
    let mut out = Vec::with_capacity(host.d1_prime.len());
    for ct in &host.d1_prime {
        let x = crate::sim::dec_with_nonce(&host.k_sym, ct)
            .ok_or_else(|| Error::TeeAbort("SIM decrypt failed on D1'".into()))?;
        let all_one = family
            .positions(&x, b_bits.len())
            .iter()
            .all(|&p| b_bits[p]);
        let token = if all_one { fresh_token() } else { [0u8; 32] };
        out.push((x, token));
    }
    // 6. marca usato
    self.used_sids.insert(*sid);
    Ok(out)
}

    /// Solo per diagnostica/test.
    pub fn used_sid_count(&self) -> usize {
        self.used_sids.len()
    }
}
