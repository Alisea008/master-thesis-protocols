chat 1: https://chat.deepseek.com/share/dxovaz91uqk9sq6ja8
# HANDOFF — PSI/PMI con Transieve (BFV + Pasta-3)

Documento di passaggio autosufficiente. Include tutto il codice finale, la storia delle modifiche, i comandi e lo stato attuale.

---

## 1. OBIETTIVO DEL PROGETTO

**Obiettivo.** Implementare in Rust il protocollo PSI/PMI descritto nel PDF allegato (`Algorithm 1: OT 1-out-of-U`, `Algorithm 2: PSI/PMI con Bloom filter, transciphering e TEE`), usando il framework **Transieve** (RRas, GitHub) come backend FHE per il transciphering omomorfo.

**Contesto e vincoli.**
- Linguaggio: Rust edition 2021, target x86_64.
- OS di sviluppo: Windows + Git Bash (UCRT64).
- Transieve clonato come sibling dir `../Transieve-main` (path dependency).
- Backend FHE: **BFV + Pasta-3** (feature `bfv` di Transieve). TFHE-Boolean scartato.
- TEE1 **simulato in-process** (Transieve non espone serializzazione di `PastaBfv`).
- Target d'uso: tesi di laurea. Serve un prototipo funzionante + numeri di benchmark.
- Path del progetto: `D:\download\Tesi\code_test\pipeline_official\psi-pmi`.

---

## 2. DECISIONI PRESE

| # | Decisione | Motivazione | Alternative scartate |
|---|---|---|---|
| 1 | Backend BFV + Pasta-3 | Ciphertext **packed**, AND **slot-wise**; allineato al PDF | TFHE-Boolean (bit-per-bit, no packing) |
| 2 | `PastaBfv` di Transieve come adapter, non reimplementato | Transieve espone già keygen, transcipher, evaluate_sop, decrypt | Reimplementare da zero (troppo lavoro) |
| 3 | TEE simulato in-process | Transieve non serializza `PastaBfv` (sk, ek, rk) | Forkare Transieve (rinviato) |
| 4 | SIM = ChaCha20 per D_1' + stream cipher Pasta per i filtri | Il PDF richiede SIM.enc sui filtri; Pasta fornisce `encrypt/decrypt` nativi | Solo ChaCha20 (non compatibile con transcipher Pasta) |
| 5 | Chiave SIM derivata via SHAKE256 con domain `PSI-PMI/Pasta/key/v1` | Stessa derivazione in `pack_key` e `pasta_sim::enc` | KDF diverso (incompatibile) |
| 6 | OT su Ristretto255 con `curve25519-dalek` | Curva veloce, group ops semplici, "divisione" = sottrazione punti | Altri gruppi EC |
| 7 | Tag OT a 48 bit, primo match con warning | Il PDF non specifica cosa fare su collisioni | Errore su multi-match (troppo fragile) |
| 8 | Firma `Eval` su **fingerprint SHAKE256** del ciphertext, non su byte serializzati | `fhe::bfv::Ciphertext` non implementa serde; `fhe_traits::DeserializeParametrized` richiede i parametri BFV non esposti | Serializzare con `to_bytes` e firmare quello (fragile, espone byte opachi) |
| 9 | `process_eval` unificato nel TEE | Anti-replay, verifica firma, decifratura e marcatura sid atomici | `verify_eval` + `finish` separati (race condition) |
| 10 | n>2 DO supportato con `sop_levels = ceil(log2 n)` | Permette n=3,4,5 senza codice ad-hoc | Solo n=2 |
| 11 | Test negativi TEE con `force_degree = Some(2048)` | Con degree 8192 il test harness esaurisce RAM (7 keygen in parallelo) | Degree 8192 (OOM su Windows) |

**Alternative scartate con motivazione:**
- **MockFhe**: prima versione funzionante ma senza FHE reale. Sostituito dall'adapter `TransievePasta`.
- **Serializzazione `bincode` di `Ciphertext`**: non implementa `serde::Serialize`. Sostituita da fingerprint.

---

## 3. CODICE E FILE CREATI

Struttura finale:

```
psi-pmi/
├── Cargo.toml
├── .gitignore
├── NOTES.md
├── README.md
├── src/
│   ├── lib.rs
│   ├── types.rs
│   ├── sig.rs
│   ├── bloom.rs
│   ├── sim.rs
│   ├── pasta_fhe.rs
│   ├── ot.rs
│   ├── ttp.rs
│   ├── tee.rs
│   └── psi.rs
└── tests/
    ├── protocol.rs
    ├── e2e_pasta.rs
    └── tee_negative.rs
```

Tutti i file sotto sono nella **versione finale**. Non ci sono versioni obsolete da conservare.

---

### `psi-pmi/Cargo.toml`

```toml
[package]
name = "psi-pmi"
version = "0.1.0"
edition = "2021"

[dependencies]
transieve = { path = "../Transieve-main", features = ["bfv"] }
fhe = "0.1.1"
fhe-traits = "0.1"
bincode = "1"
anyhow = "1"

curve25519-dalek = { version = "4", features = ["rand_core"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
sha3 = "0.10"
rand = "0.8"
rand_core = "0.6"
zeroize = { version = "1", features = ["derive"] }
thiserror = "1"
chacha20poly1305 = "0.10"
hex = "0.4"
```

**Nota sul path:** se `Transieve-main/` contiene direttamente `Cargo.toml`, usa `path = "../Transieve-main"`. Se invece contiene una sottocartella `Transieve-main/Transieve-main/`, usa `path = "../Transieve-main/Transieve-main"`.

---

### `psi-pmi/.gitignore`

```
/target
Cargo.lock
```

---

### `psi-pmi/src/lib.rs`

```rust
pub mod bloom;
pub mod ot;
pub mod pasta_fhe;
pub mod psi;
pub mod sig;
pub mod sim;
pub mod tee;
pub mod ttp;
pub mod types;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("channel: {0}")]
    Channel(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("tee abort: {0}")]
    TeeAbort(String),
    #[error("fhe: {0}")]
    Fhe(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Fhe(format!("{e:#}"))
    }
}
```

**Storia.** Nella prima versione c'era anche `pub mod net;` (poi rimosso perché `net.rs` non era usato). La struct `Error` ha aggiunto `Fhe` per wrappare `anyhow::Error` da Transieve.

---

### `psi-pmi/src/types.rs`

```rust
use rand::RngCore;

pub type Sid = [u8; 16];
pub type Token = [u8; 32];

pub fn fresh_sid() -> Sid {
    let mut s = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn fresh_token() -> Token {
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    t
}
```

---

### `psi-pmi/src/sig.rs`

```rust
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

pub trait Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verifying_key_bytes(&self) -> Vec<u8>;
}

pub trait Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            key: SigningKey::generate(&mut rng),
        }
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }
    fn verifying_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = b.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&arr).ok()?;
        Some(Self { key })
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(arr) = <[u8; 64]>::try_from(sig) else {
            return false;
        };
        let sig = Signature::from_bytes(&arr);
        self.key.verify(msg, &sig).is_ok()
    }
}
```

---

### `psi-pmi/src/bloom.rs`

```rust
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Clone)]
pub struct Family {
    seed: [u8; 32],
    k: usize,
}

impl Family {
    pub fn new(seed: [u8; 32], k: usize) -> Self {
        Self { seed, k }
    }
    pub fn k(&self) -> usize {
        self.k
    }

    pub fn positions(&self, x: &[u8], n_bits: usize) -> Vec<usize> {
        let mut h = Shake256::default();
        h.update(b"PSI-PMI/Bloom/positions/v1");
        h.update(&self.seed);
        h.update(&(x.len() as u64).to_le_bytes());
        h.update(x);
        let mut reader = h.finalize_xof();
        let mut buf = vec![0u8; 8 * self.k];
        reader.read(&mut buf);
        buf.chunks_exact(8)
            .map(|c| {
                let v = u64::from_le_bytes(c.try_into().unwrap());
                (v as usize) % n_bits
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct HashFamilies {
    families: Vec<Family>,
}

impl HashFamilies {
    pub fn new(seeds: Vec<[u8; 32]>, k: usize) -> Self {
        Self {
            families: seeds.into_iter().map(|s| Family::new(s, k)).collect(),
        }
    }
    pub fn get(&self, u: usize) -> &Family {
        &self.families[u]
    }
    pub fn len(&self) -> usize {
        self.families.len()
    }
    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct BloomFilter {
    n_bits: usize,
    bits: Vec<u8>,
}

impl BloomFilter {
    pub fn new(n_bits: usize) -> Self {
        assert!(n_bits % 8 == 0, "n_bits must be multiple of 8");
        Self {
            n_bits,
            bits: vec![0u8; n_bits / 8],
        }
    }
    pub fn n_bits(&self) -> usize {
        self.n_bits
    }
    pub fn get(&self, idx: usize) -> bool {
        self.bits[idx / 8] & (1 << (idx % 8)) != 0
    }
    fn set(&mut self, idx: usize) {
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    pub fn insert(&mut self, x: &[u8], family: &Family) {
        for p in family.positions(x, self.n_bits) {
            self.set(p);
        }
    }

    pub fn contains(&self, x: &[u8], family: &Family) -> bool {
        family.positions(x, self.n_bits).iter().all(|&p| self.get(p))
    }

    pub fn to_bit_slots(&self) -> Vec<u8> {
        (0..self.n_bits).map(|i| self.get(i) as u8).collect()
    }
}
```

**Storia.** Nella primissima versione il Bloom filter usava `siphasher` (come Transieve). Sostituito con SHAKE256 con domain separation per coerenza con il resto del protocollo.

---

### `psi-pmi/src/sim.rs`

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

pub const SIM_NONCE_LEN: usize = 12;

pub trait SymmetricCipher {
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8>;
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>>;
}

pub struct Sim;
impl Sim {
    pub fn fresh_nonce() -> [u8; SIM_NONCE_LEN] {
        let mut n = [0u8; SIM_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut n);
        n
    }
}

impl SymmetricCipher for Sim {
    fn enc(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], pt: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key len");
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: pt,
                    aad: b"PSI-PMI/SIM/v1",
                },
            )
            .expect("enc")
    }
    fn dec(&self, key: &[u8], nonce: &[u8; SIM_NONCE_LEN], ct: &[u8]) -> Option<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: b"PSI-PMI/SIM/v1",
                },
            )
            .ok()
    }
}

pub fn enc_with_nonce(key: &[u8], pt: &[u8]) -> Vec<u8> {
    let nonce = Sim::fresh_nonce();
    let ct = Sim.enc(key, &nonce, pt);
    let mut out = Vec::with_capacity(SIM_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn dec_with_nonce(key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < SIM_NONCE_LEN {
        return None;
    }
    let (nb, ct) = input.split_at(SIM_NONCE_LEN);
    let nonce: [u8; SIM_NONCE_LEN] = nb.try_into().ok()?;
    Sim.dec(key, &nonce, ct)
}

// -------------------------------------------------------------------------
// SIM "Pasta-shaped": stream cipher di Pasta, chiave derivata da k_sym.
// -------------------------------------------------------------------------

use transieve::cipher::bfv::pasta::{encrypt as pasta_encrypt, P};

pub fn derive_pasta_key(k_sym: &[u8], t: usize) -> Vec<u64> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/Pasta/key/v1");
    h.update(k_sym);
    let mut r = h.finalize_xof();
    let mut buf = vec![0u8; 8 * 2 * t];
    r.read(&mut buf);
    buf.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) % P)
        .collect()
}

pub mod pasta_sim {
    use super::{derive_pasta_key, pasta_encrypt, P};
    use transieve::cipher::bfv::pasta::PastaParams;

    pub fn enc(bits: &[u8], k_sym: &[u8], nonce: [u64; 2], params: PastaParams) -> Vec<u8> {
        assert!(bits.len() <= params.t, "bits must fit in one Pasta lane");
        let key = derive_pasta_key(k_sym, params.t);
        let mut msg: Vec<u64> = bits.iter().map(|&b| (b & 1) as u64).collect();
        msg.resize(params.t, 0);
        words_to_bytes(&pasta_encrypt(&key, &msg, nonce, params))
    }

    pub fn words_to_bytes(words: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 8);
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()) % P)
            .collect()
    }
}
```

**Storia.** Fix applicato: rimosso `PastaParams` dall'import a livello di file (era unused perché importato nel submodulo `pasta_sim`).

---

### `psi-pmi/src/pasta_fhe.rs`

```rust
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
        ctx.decrypt_bits(ct, num_bits)
    }
}

// -------------------------------------------------------------------------
// Fingerprint canonico di un ciphertext (per firmare E_B senza serializzare)
// -------------------------------------------------------------------------

/// Restituisce SHAKE256("PSI-PMI/Eval/ct-fingerprint/v1" || len || bytes(ct)).
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
```

**Storia (importante).**
1. Prima versione: metodo `serialize_ct`/`deserialize_ct` su trait usando `bincode::serialize(ct)`. **Falliva** perché `fhe::bfv::Ciphertext` non implementa `serde::Serialize`.
2. Secondo tentativo: `ct.to_bytes()` + `Ciphertext::from_bytes()`. **Falliva** perché `from_bytes` è di `fhe_traits::DeserializeParametrized`, che richiede i parametri BFV (non esposti da `PastaBfv`).
3. Versione finale: **fingerprint SHAKE256**, niente serializzazione di `E_B`. La firma di S1 è sul fingerprint; il ciphertext resta in-process.
4. `#[derive(Clone)]` aggiunto perché `tee_negative.rs` lo richiedeva.

---

### `psi-pmi/src/ot.rs`

```rust
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{Error, Result};

pub const TAG_BITS: usize = 48;

fn h_ct(k: &RistrettoPoint, j: usize, out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/OT/Hct/v1");
    h.update(&k.compress().to_bytes());
    h.update(&(j as u64).to_le_bytes());
    let mut r = h.finalize_xof();
    let mut buf = vec![0u8; out_len];
    r.read(&mut buf);
    buf
}

fn h_tag(k: &RistrettoPoint, j: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/OT/Htag/v1");
    h.update(&k.compress().to_bytes());
    h.update(&(j as u64).to_le_bytes());
    let mut r = h.finalize_xof();
    let n = (TAG_BITS + 7) / 8;
    let mut buf = vec![0u8; n];
    r.read(&mut buf);
    let extra = n * 8 - TAG_BITS;
    if extra > 0 {
        buf[n - 1] &= 0xffu8 >> extra;
    }
    buf
}

fn point_from_bytes(b: &[u8]) -> Result<RistrettoPoint> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| Error::Invalid("point len".into()))?;
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| Error::Invalid("invalid ristretto point".into()))
}

pub struct OtDoState {
    pub r: Scalar,
    pub c: Vec<RistrettoPoint>,
    pub u: usize,
}

pub struct OtPhase1Msg {
    pub c: Vec<Vec<u8>>,
    pub g_r: Vec<u8>,
}

pub fn ot_phase1(
    u: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> (OtDoState, OtPhase1Msg) {
    assert!(u >= 1);
    let r = Scalar::random(rng);
    let mut c = Vec::with_capacity(u);
    c.push(RISTRETTO_BASEPOINT_POINT);
    for _ in 1..u {
        c.push(RistrettoPoint::random(rng));
    }
    let g_r = (RISTRETTO_BASEPOINT_POINT * r)
        .compress()
        .to_bytes()
        .to_vec();
    let c_ser: Vec<Vec<u8>> = c[1..]
        .iter()
        .map(|p| p.compress().to_bytes().to_vec())
        .collect();
    (OtDoState { r, c, u }, OtPhase1Msg { c: c_ser, g_r })
}

pub struct OtTtpOutput {
    pub pk0_bytes: Vec<u8>,
    pub t: RistrettoPoint,
    pub sigma: usize,
}

pub fn ot_phase2(
    u: usize,
    phase1: &OtPhase1Msg,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<OtTtpOutput> {
    let sigma = rng.gen_range(0..u);
    ot_phase2_with_sigma(u, phase1, sigma, rng)
}

pub fn ot_phase2_with_sigma(
    u: usize,
    phase1: &OtPhase1Msg,
    sigma: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<OtTtpOutput> {
    assert!(sigma < u);
    let _ = u;
    let k = Scalar::random(rng);
    let g_r = point_from_bytes(&phase1.g_r)?;
    let t = g_r * k;
    let pk_sigma = RISTRETTO_BASEPOINT_POINT * k;

    let pk0 = if sigma == 0 {
        pk_sigma
    } else {
        let c_sigma = point_from_bytes(&phase1.c[sigma - 1])?;
        c_sigma - pk_sigma
    };

    Ok(OtTtpOutput {
        pk0_bytes: pk0.compress().to_bytes().to_vec(),
        t,
        sigma,
    })
}

#[derive(Clone)]
pub struct OtCiphertext {
    pub ct: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn ot_phase3(
    state: &OtDoState,
    pk0_bytes: &[u8],
    messages: &[Vec<u8>],
) -> Result<Vec<OtCiphertext>> {
    assert_eq!(messages.len(), state.u);
    let pk0 = point_from_bytes(pk0_bytes)?;
    let k0 = pk0 * state.r;
    let mut out = Vec::with_capacity(state.u);

    {
        let mut ct = h_ct(&k0, 0, messages[0].len());
        for (a, b) in ct.iter_mut().zip(&messages[0]) {
            *a ^= b;
        }
        out.push(OtCiphertext {
            ct,
            tag: h_tag(&k0, 0),
        });
    }

    for j in 1..state.u {
        let k_j = state.c[j] * state.r - k0;
        let mut ct = h_ct(&k_j, j, messages[j].len());
        for (a, b) in ct.iter_mut().zip(&messages[j]) {
            *a ^= b;
        }
        out.push(OtCiphertext {
            ct,
            tag: h_tag(&k_j, j),
        });
    }
    Ok(out)
}

pub fn ot_phase4(t: &RistrettoPoint, cts: &[OtCiphertext]) -> Result<(usize, Vec<u8>)> {
    let mut found: Option<usize> = None;
    let mut matches = 0usize;
    for (j, c) in cts.iter().enumerate() {
        if h_tag(t, j) == c.tag {
            matches += 1;
            if found.is_none() {
                found = Some(j);
            }
        }
    }
    if matches > 1 {
        eprintln!(
            "[ot_phase4] WARNING: {} tag collisions (tag_bits={}); using first match",
            matches, TAG_BITS
        );
    }
    let j = found.ok_or_else(|| Error::Protocol("no tag match".into()))?;
    let mut m = h_ct(t, j, cts[j].ct.len());
    for (a, b) in m.iter_mut().zip(&cts[j].ct) {
        *a ^= b;
    }
    Ok((j, m))
}
```

**Storia.**
1. Le firme `ot_phase1`, `ot_phase2`, `ot_phase2_with_sigma` hanno aggiunto `+ rand::CryptoRng` per soddisfare `curve25519-dalek` 4.x.
2. `ot_phase4` modificata per ritornare il **primo** match (non errore su multi-match).

---

### `psi-pmi/src/ttp.rs`

```rust
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::sig::Ed25519Signer;
use crate::types::Sid;

pub const DOM_SIGMA: &[u8] = b"PSI-PMI/v1/TTP/sigma";
pub const DOM_T: &[u8] = b"PSI-PMI/v1/TTP/T";
pub const DOM_EVAL: &[u8] = b"PSI-PMI/v1/S1/eval";

pub fn sigma_msg(sid: &Sid, sigma: usize) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_SIGMA);
    m.extend_from_slice(sid);
    m.extend_from_slice(&(sigma as u64).to_le_bytes());
    m
}

pub fn t_msg(sid: &Sid, t: &RistrettoPoint) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_T);
    m.extend_from_slice(sid);
    m.extend_from_slice(&t.compress().to_bytes());
    m
}

pub fn eval_msg(sid: &Sid, e_b_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_EVAL);
    m.extend_from_slice(sid);
    m.extend_from_slice(e_b_bytes);
    m
}

pub struct Ttp {
    pub signer: Ed25519Signer,
}

impl Ttp {
    pub fn new() -> Self {
        Self {
            signer: Ed25519Signer::generate(),
        }
    }
}
```

---

### `psi-pmi/src/tee.rs`

```rust
use std::collections::HashSet;

use fhe::bfv::Ciphertext;

use crate::bloom::HashFamilies;
use crate::pasta_fhe::{ct_fingerprint, PastaFhe, TransievePasta};
use crate::sig::Verifier;
use crate::ttp::eval_msg;
use crate::types::{fresh_token, Sid};
use crate::{Error, Result};

pub struct TeeHostInputPasta {
    pub d1_prime: Vec<Vec<u8>>,
    pub hashes: HashFamilies,
    pub k_sym: Vec<u8>,
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

    pub fn process_eval(
        &mut self,
        sid: &Sid,
        e_b: &Ciphertext,
        sig: &[u8],
        num_bits: usize,
    ) -> Result<Vec<(Vec<u8>, [u8; 32])>> {
        // 1. anti-replay
        if self.used_sids.contains(sid) {
            return Err(Error::TeeAbort("sid already used".into()));
        }
        // 2. firma S1 sul fingerprint del ciphertext
        let fp = ct_fingerprint(e_b);
        let signed_msg = eval_msg(sid, &fp);
        if !self.s1_verifier.verify(&signed_msg, sig) {
            return Err(Error::TeeAbort("bad S1 signature on Eval".into()));
        }
        // 3. stato preregistrato
        let sigma = self
            .sigma
            .ok_or_else(|| Error::TeeAbort("sigma not registered".into()))?;
        let host = self
            .host_input
            .take()
            .ok_or_else(|| Error::TeeAbort("host input missing".into()))?;
        // 4. decifra e calcola Out
        let b_bits = self.fhe.decrypt_bits(&self.ctx, e_b, num_bits)?;
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
        // 5. marca usato
        self.used_sids.insert(*sid);
        Ok(out)
    }

    pub fn used_sid_count(&self) -> usize {
        self.used_sids.len()
    }
}
```

**Storia.** Prima versione aveva `verify_eval` + `finish` separati (race condition). Unificati in `process_eval` che è atomico: verifica firma, richiede σ+host input, decifra, calcola Out, marca sid. `verify_eval` prendeva `&[u8]` per il ciphertext; ora prende `&Ciphertext` perché la firma è sul fingerprint.

---

### `psi-pmi/src/psi.rs`

```rust
//! Orchestrazione end-to-end (Algorithm 2).

use std::time::Instant;

use crate::bloom::HashFamilies;
use crate::ot::{ot_phase1, ot_phase2, ot_phase2_with_sigma, ot_phase3, ot_phase4};
use crate::pasta_fhe::{ct_fingerprint, PastaFhe, TransievePasta};
use crate::sig::{Ed25519Signer, Ed25519Verifier, Signer};
use crate::sim::{enc_with_nonce, pasta_sim};
use crate::tee::{Tee1Pasta, TeeHostInputPasta};
use crate::ttp::{eval_msg, sigma_msg, Ttp};
use crate::types::{fresh_sid, Sid};
use crate::{Error, Result};

use transieve::cipher::bfv::pasta::PastaParams;

pub struct DataOwnerInput {
    pub elements: Vec<Vec<u8>>,
    pub k_sym: Vec<u8>,
}

pub struct E2eConfig {
    pub u: usize,
    pub n_bits: usize,
    pub hash_k: usize,
    pub seeds: Vec<[u8; 32]>,
}

pub struct E2eResult {
    pub sid: Sid,
    pub sigma: usize,
    pub do1_out: Vec<(Vec<u8>, [u8; 32])>,
    pub expected_intersection: Vec<Vec<u8>>,
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
    println!(
        "[psi] === E2E start === n={} U={} n_bits={} hash_k={} Pasta_t={} Pasta_rounds={} force_degree={:?}",
        n, cfg.u, cfg.n_bits, cfg.hash_k, params.t, params.rounds, force_degree
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

    let s1 = Ed25519Signer::generate();
    let s1_vk = s1.verifying_key_bytes();
    let s1_verifier = Box::new(
        Ed25519Verifier::from_bytes(&s1_vk)
            .ok_or_else(|| Error::Crypto("bad S1 verifying key".into()))?,
    );
    println!(
        "[psi] [sign]        Ed25519 keygen (TTP + S1): {:.3} ms",
        t_sig.elapsed().as_secs_f64() * 1e3
    );

    let sop_levels = (n as f64).log2().ceil() as usize;
    let fhe = TransievePasta {
        params,
        force_degree,
    };

    let t0 = Instant::now();
    let ctx = fhe.setup(sop_levels)?;
    println!(
        "[psi] [fhe setup]   PastaBfv::new (keygen + eval keys, sop_levels={}): {:.3} s",
        sop_levels,
        t0.elapsed().as_secs_f64()
    );

    let t0 = Instant::now();
    let per_do_keys: Vec<_> = do_inputs
        .iter()
        .map(|d| fhe.pack_key(&ctx, &d.k_sym))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    println!(
        "[psi] [pack_key]    encrypt_key for n={} DOs: {:.3} ms",
        n,
        t0.elapsed().as_secs_f64() * 1e3
    );

    let t0 = Instant::now();
    let u = hashes.len();
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
    println!(
        "[psi] [SIM enc]     {} filters x {} DOs: {:.3} ms",
        u,
        n,
        t0.elapsed().as_secs_f64() * 1e3
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
        let cts = ot_phase3(&states[a], &ttp_outs[a].pk0_bytes, &per_do_messages[a])?;
        let (_j, m_sigma) = ot_phase4(&ttp_outs[a].t, &cts)?;
        m_sigmas.push(m_sigma);
    }
    println!(
        "[psi] [OT]          n={} U={} sigma={}: {:.3} ms",
        n,
        u,
        sigma,
        t0.elapsed().as_secs_f64() * 1e3
    );

    let sig_sigma = ttp.signer.sign(&sigma_msg(&sid, sigma));
    tee.register_sigma(sigma, &sigma_msg(&sid, sigma), &sig_sigma)?;

    let nonce = [sigma as u64, 0u64];
    let mut e_a_vec = Vec::with_capacity(n);
    for a in 0..n {
        let words = pasta_sim::bytes_to_words(&m_sigmas[a]);
        let len = words.len();
        let t0 = Instant::now();
        let ct = tee
            .fhe()
            .transcipher(tee.ctx(), &per_do_keys[a], nonce, &[0], &[words])?;
        println!(
            "[psi] [transcipher] DO_{} ({} cipher words): {:.3} s",
            a + 1,
            len,
            t0.elapsed().as_secs_f64()
        );
        e_a_vec.push(ct);
    }

    let t0 = Instant::now();
    let e_b = tee.fhe().eval_and_all(tee.ctx(), &e_a_vec, n)?;
    println!(
        "[psi] [eval_and]    slot-wise AND across n={} DOs: {:.3} s",
        n,
        t0.elapsed().as_secs_f64()
    );

    let t0 = Instant::now();
    let fp = ct_fingerprint(&e_b);
    let signed_msg = eval_msg(&sid, &fp);
    let sig_eval = s1.sign(&signed_msg);
    let out = tee.process_eval(&sid, &e_b, &sig_eval, cfg.n_bits)?;
    println!(
        "[psi] [TEE]         |D1'|={} tokens in {:.3} ms (used sid count: {})",
        out.len(),
        t0.elapsed().as_secs_f64() * 1e3,
        tee.used_sid_count()
    );

    let set1: std::collections::HashSet<_> = do_inputs[0].elements.iter().cloned().collect();
    let expected: Vec<Vec<u8>> = do_inputs[1]
        .elements
        .iter()
        .filter(|x| set1.contains(*x))
        .cloned()
        .collect();

    println!(
        "[psi] === E2E done in {:.3} s | sigma={} | expected_intersection={:?} ===",
        t_run.elapsed().as_secs_f64(),
        sigma,
        expected
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect::<Vec<_>>()
    );

    Ok(E2eResult {
        sid,
        sigma,
        do1_out: out,
        expected_intersection: expected,
    })
}
```

**Storia.**
1. Prima versione: `assert_eq!(do_inputs.len(), 2)` e chiamate dirette `tee.fhe().transcipher(...)`. Con n=3 non compilava logicamente.
2. Aggiunti i `println!` di timing.
3. Fix del borrow-of-moved: `let len1 = words1.len();` **prima** del `transcipher`.
4. Fix: firma `Eval` da S1 sul fingerprint; `process_eval` invece di `decrypt_bits` diretto.
5. Rimosso `aggregate_bits` da `E2eResult` (era diagnostica).
6. Fix `unwrap()` su verifier: `.ok_or_else(|| Error::Crypto(...))`.

---

### `psi-pmi/tests/protocol.rs`

```rust
use psi_pmi::bloom::{BloomFilter, Family};
use psi_pmi::ot::{ot_phase1, ot_phase2, ot_phase3, ot_phase4};

#[test]
fn bloom_no_false_negatives() {
    let seed = [7u8; 32];
    let f = Family::new(seed, 3);
    let mut bf = BloomFilter::new(8192);
    let items: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_le_bytes().to_vec()).collect();
    for x in &items {
        bf.insert(x, &f);
    }
    for x in &items {
        assert!(bf.contains(x, &f));
    }
}

#[test]
fn ot_all_sigmas() {
    let u = 4;
    let messages: Vec<Vec<u8>> = (0..u).map(|i| vec![i as u8; 64]).collect();
    for _ in 0..20 {
        let mut rng = rand::thread_rng();
        let (state, p1) = ot_phase1(u, &mut rng);
        let ttp_out = ot_phase2(u, &p1, &mut rng).unwrap();
        let cts = ot_phase3(&state, &ttp_out.pk0_bytes, &messages).unwrap();
        let (j, m) = ot_phase4(&ttp_out.t, &cts).unwrap();
        assert_eq!(j, ttp_out.sigma);
        assert_eq!(m, messages[ttp_out.sigma]);
    }
}
```

---

### `psi-pmi/tests/e2e_pasta.rs`

```rust
//! Test end-to-end con BFV+Pasta-3. Degree 8192 = veloce, NON 128-bit safe.

use psi_pmi::psi::{run_e2e_pasta, DataOwnerInput, E2eConfig};
use transieve::cipher::bfv::pasta::PASTA3;

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() {
        *b = i.wrapping_add(j as u8);
    }
    s
}

fn cfg() -> E2eConfig {
    E2eConfig {
        u: 4,
        n_bits: 128,
        hash_k: 3,
        seeds: vec![seed(1), seed(2), seed(3), seed(4)],
    }
}

fn do_input(names: &[&[u8]], k: u8) -> DataOwnerInput {
    DataOwnerInput {
        elements: names.iter().map(|n| n.to_vec()).collect(),
        k_sym: vec![k; 32],
    }
}

#[test]
fn e2e_n2_pasta3() {
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let res = run_e2e_pasta(PASTA3, Some(8192), &cfg(), vec![do1, do2])
        .expect("n=2 must succeed");

    assert_eq!(res.do1_out.len(), 3);
    assert!(res.sigma < 4);

    for name in [b"bob".as_slice(), b"carol".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(
            e.1,
            [0u8; 32],
            "{} must be in intersection",
            String::from_utf8_lossy(name)
        );
    }
    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice must be outside");
}

#[test]
fn e2e_n3_pasta3() {
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let do3 = do_input(&[b"bob", b"eve", b"frank"], 11);

    let res = run_e2e_pasta(PASTA3, Some(8192), &cfg(), vec![do1, do2, do3])
        .expect("n=3 must succeed");

    let bob = res.do1_out.iter().find(|(x, _)| x == b"bob").unwrap();
    assert_ne!(bob.1, [0u8; 32], "bob must be in 3-way intersection");

    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice is only in DO_1");
}
```

---

### `psi-pmi/tests/tee_negative.rs`

```rust
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
        force_degree: Some(2048),
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
    let (mut tee, fhe, ttp, s1) = mk_tee();
    let sid = fresh_sid();
    tee.submit_host_input(mk_host_input()).unwrap();
    let msg_sigma = sigma_msg(&sid, 0);
    let sig_sigma = ttp.signer.sign(&msg_sigma);
    tee.register_sigma(0, &msg_sigma, &sig_sigma).unwrap();

    let fake_e_b = fhe.pack_key(tee.ctx(), &[3u8; 32]).unwrap();
    let fp = ct_fingerprint(&fake_e_b);
    let msg = eval_msg(&sid, &fp);
    let sig = s1.sign(&msg);

    let _ = tee.process_eval(&sid, &fake_e_b, &sig, 128).unwrap();
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
```

**Storia.**
1. Prima versione con `force_degree = Some(8192)` → OOM su Windows.
2. Ridotto a `Some(2048)` e `--test-threads=1`.
3. `mk_host_input` con `d1_prime: vec![vec![1, 2, 3]]` → `SIM decrypt failed on D1'` in `eval_replay_rejected`. Fix: `d1_prime: vec![]`.

---

### `psi-pmi/NOTES.md`

```markdown
# NOTES

## Cosa espone Transieve
- `transieve::cipher::bfv::pasta::{PastaBfv, PASTA3, PastaParams, P, encrypt, decrypt}`
- `PastaBfv::{new_secure, new_with_sop, pack_key, transcipher_recover_blocks,
  evaluate_sop, decrypt_bits, decrypt_lane_bits}`
- `transieve::circuit::ThresholdCircuit::new(n, t)`

## Cosa NON è esposto
- Serializzazione di `PastaBfv` (sk, ek, rk) → TEE resta in-process.
- Serializzazione serde di `Ciphertext` → usiamo fingerprint SHAKE256.

## Scelte
- Backend BFV + Pasta-3 (packed, AND slot-wise). TFHE-Boolean scartato.
- Test e2e con degree 8192 (veloce, non 128-bit safe).
- Test negativi TEE con degree 2048 (più leggero).
- U filtri per DO, un ciphertext SIM per H_u, nonce = `[u, 0]`.
- σ comune alle n istanze OT, passato a `ot_phase2_with_sigma`.
- Tag OT: 48 bit. `H_ct` = SHAKE256. `H_tag` con domain separation.
- AND: `ThresholdCircuit::new(n, n)` su Pasta (albero interno, ⌈log₂ n⌉).
- k_sym (32 B): ChaCha20 per D_1' e seed SHAKE256 per `derive_pasta_key` (2t
  field element mod 65537). Stessa derivazione in `pack_key` e `pasta_sim::enc`.
- Firma `Eval` da S1: sul **fingerprint SHAKE256** di `E_B`, non sui byte serde
  (il tipo `fhe::bfv::Ciphertext` non implementa `serde::Serialize`).

## Mapping PDF → codice
| PDF                    | Codice                                        |
|------------------------|-----------------------------------------------|
| Alg.1 Fase 1 (DO)      | `ot::ot_phase1`                               |
| Alg.1 Fase 2 (TTP)     | `ot::ot_phase2_with_sigma`                    |
| Alg.1 Fase 3 (DO)      | `ot::ot_phase3`                               |
| Alg.1 Fase 4 (S)       | `ot::ot_phase4`                               |
| Alg.2 Setup (1–4)      | `psi::run_e2e_pasta` + `Tee1Pasta::submit_host_input` |
| Alg.2 Aggregation (6–7)| `PastaFhe::transcipher` + `eval_and_all`      |
| Alg.2 Delivery (8)     | `Tee1Pasta::process_eval` (verifica firma S1) |
| Alg.2 Decrypt (9–10)   | `PastaFhe::decrypt_bits` + `Tee1Pasta::finish`|
```

---

### `psi-pmi/README.md`

```markdown
# psi-pmi

PSI/PMI con Bloom filter, transciphering e TEE (Algorithm 1 + 2), sopra
Transieve (BFV + Pasta-3).

## Moduli

- `types`      Sid/Token
- `sig`        Ed25519 (FSIG)
- `bloom`      Bloom filter + famiglie H_0..H_{U-1}
- `sim`        ChaCha20 (per D_1') + stream cipher Pasta (per i filtri)
- `pasta_fhe`  adapter PastaBfv di Transieve
- `ot`         Algorithm 1 (1-out-of-U)
- `ttp`        TTP
- `tee`        TEE_1 simulato
- `psi`        Algorithm 2 end-to-end

## Build

```bash
cargo build --release
cargo test --release --test protocol
cargo test --release --test tee_negative -- --test-threads=1
cargo test --release --test e2e_pasta -- --nocapture
```

Il test e2e usa `new_with_sop(PASTA3, 8192, 1)` per n=2 e `sop_levels=2` per n=3:
veloce, NON 128-bit sicuro. Per la versione sicura, `force_degree = None`
(degree 32768, molto più lento).

## Limiti

- TEE simulato in-process (Transieve non serializza `PastaBfv`).
- E[T] consegnato nel modello (FSC); in produzione HPKE/ECIES.
- Un filtro per lane: con PASTA3 `t=128`, quindi `n_bits ≤ 128`.
```

---

## 4. PROTOCOLLO / PROCEDURA SEGUITA

### Setup iniziale
1. Clonato Transieve in `Transieve-main/` (sibling di `psi-pmi/`).
2. Creato workspace Rust `psi-pmi/` con `src/` e `tests/`.
3. Aggiunto `transieve = { path = "../Transieve-main", features = ["bfv"] }` in `Cargo.toml`.

### Ordine di lavoro (seguito fedelmente)
1. **Analisi Transieve** (API `PastaBfv`, `ThresholdCircuit`, cipher Pasta) → `NOTES.md`.
2. **Adapter `PastaFhe`** in `pasta_fhe.rs`.
3. **Bridge SIM** in `sim.rs` (ChaCha20 + Pasta stream cipher).
4. **Riscrittura `psi.rs`** end-to-end con `PastaBfv`.
5. **Test veloci** (`protocol.rs`).
6. **Test e2e** (`e2e_pasta.rs`).
7. **Test negativi TEE** (`tee_negative.rs`).
8. **Fix iterativi** (vedi Sezione 5).

### Comandi finali (tutti in Git Bash da `psi-pmi/`)
```bash
cargo build --release
cargo test --release --test protocol
cargo test --release --test tee_negative -- --test-threads=1
cargo test --release --test e2e_pasta -- --nocapture
```

### Convenzioni stabilite
- Domain separation in tutti gli hash:
  - `PSI-PMI/Bloom/positions/v1`
  - `PSI-PMI/OT/Hct/v1`, `PSI-PMI/OT/Htag/v1`
  - `PSI-PMI/Pasta/key/v1`
  - `PSI-PMI/Eval/ct-fingerprint/v1`
  - `PSI-PMI/v1/TTP/sigma`, `PSI-PMI/v1/TTP/T`, `PSI-PMI/v1/S1/eval`
  - `PSI-PMI/SIM/v1` (AAD ChaCha20)
- Log con prefisso `[psi]` per filtrare i timing.
- Errori con `Result<T, Error>` custom (no `unwrap` in libreria).
- Nonce per ciascuno degli U filtri = `[u as u64, 0u64]`.
- `TAG_BITS = 48`.

---

## 5. STATO ATTUALE

### Funziona e testato ✅

| Test | Esito | Tempo |
|---|---|---|
| `bloom_no_false_negatives` | ✅ ok | <1 s |
| `ot_all_sigmas` | ✅ ok | <1 s |
| `e2e_n2_pasta3` (n=2, U=4, degree 8192) | ✅ ok | ~69 s |
| `e2e_n3_pasta3` (n=3, sop_levels=2, degree 8192) | ✅ ok | ~92 s |
| 7 test in `tee_negative.rs` | ✅ ok (con `--test-threads=1`) | ~118 s |

### Numeri e2e (dal tuo ultimo output)

| Fase | n=2 | n=3 |
|---|---|---|
| `fhe setup` | 24.5 s | 33.5 s |
| `pack_key` | 108 ms | 87 ms |
| `SIM enc` | 871 ms | 846 ms |
| `OT` | 90 ms | 12 ms |
| `transcipher` per DO | ~34 s (primo) / 8.5 s (secondo) | 29.5 / 14 / 13 s |
| `eval_and` | 157 ms | 419 ms |
| `TEE` (decrypt + Out) | 62 ms | 80 ms |
| **Totale** | **~69 s** | **~92 s** |

### Non funziona / incompleto ❌

1. **S_a non è un ruolo esplicito** — è fuso dentro `run_e2e_pasta`. Il PDF lo modella come server separato.
2. **`net.rs` non è usato** — era nella struttura iniziale ma non è stato importato in `lib.rs` (rimosso).
3. **`E[T]` non è cifrato** — consegnato in chiaro nel modello (FSC). Il PDF non lo richiede esplicitamente (il canale è FSC), ma in produzione serve HPKE/ECIES.
4. **`zeroize` non utilizzato** — `k_sym`, `r`, `sk` restano in memoria.
5. **`force_degree = Some(8192)` non è 128-bit sicuro** — per la tesi serve almeno un run con `force_degree = None` (degree 32768).
6. **Nessun binario `bench`** — i timing sono dentro test, non c'è un CSV esportabile.
7. **Nessun confronto con TFHE-Boolean** — che è il potenziale contributo scientifico.

### Errori incontrati e risolti ✅

| # | Errore | Causa | Fix |
|---|---|---|---|
| 1 | `impl rand::RngCore: CryptoRngCore is not satisfied` | `curve25519-dalek` 4.x richiede `CryptoRng` | Aggiunto bound `+ rand::CryptoRng` a `ot_phase1/2/2_with_sigma` |
| 2 | `unused import eval_msg` / `PastaParams` / `PastaFhe` | Import ridondanti | Rimossi |
| 3 | `borrow of moved value: words1` | `&[words1]` sposta il Vec | Salvato `let len1 = words1.len();` prima della chiamata |
| 4 | `Ciphertext: serde::Serialize not satisfied` | `fhe::bfv::Ciphertext` non ha serde | Sostituito serializzazione con fingerprint SHAKE256 |
| 5 | `no associated function 'from_bytes'` per `Ciphertext` | `fhe_traits::DeserializeParametrized` non in scope e richiede parametri BFV | Rimosso completamente il round-trip |
| 6 | `TransievePasta: Clone not satisfied` | Manca derive | Aggiunto `#[derive(Clone)]` |
| 7 | Test `tee_negative` OOM (STATUS_STACK_BUFFER_OVERRUN) | 7 keygen BFV degree 8192 in parallelo | Ridotto degree a 2048 + `--test-threads=1` |
| 8 | `SIM decrypt failed on D1'` in `eval_replay_rejected` | `d1_prime = vec![vec![1,2,3]]` non è un ciphertext SIM valido | `d1_prime: vec![]` |
| 9 | `setup.sh` errore heredoc "wanted EOF" | File troncato | Copia manuale dei 16 file |

---

## 6. PROSSIMI PASSI

### Priorità

| # | Gruppo | Cosa | Costo | Rischio | Valore tesi |
|---|---|---|---|---|---|
| 1 | Fix rapido | Fix `tee_negative` degree | 2 min | nullo | (fatto) |
| 2 | **Gruppo 3** | `examples/bench_e2e` + sweep + CSV | 2 h + 30-60 min runtime | basso | **ALTO** |
| 3 | **Gruppo 2** | Ruolo `Server` esplicito + `net.rs` + zeroize | 2-3 h | basso | ALTO |
| 4 | **Gruppo 4** | Confronto TFHE-Boolean | 3-4 h + runtime lungo | medio | **MASSIMO** |

### Punto esatto di ripartenza
Tutti i test passano. Lo stato è **verde**. Il prossimo passo è il **Gruppo 3** (bench), perché senza numeri la tesi non sta in piedi.

### Domande aperte / dubbi irrisolti
- **`force_degree = None` (128-bit) — va testato?** Non è mai stato provato. Il codice è pronto (`new_secure` invece di `new_with_sop`), ma potrebbe essere troppo lento (>30 min per un e2e).
- **n=4:** con `sop_levels = 2` e degree 8192, il rumore BFV potrebbe non reggere. Se fallisce, aumentare a 16384.
- **Transieve supporta `n_bits > 128`?** Con Pasta-3 `t=128`, un filtro più grande non ci sta in una lane. Servirebbe usare `transcipher_recover_blocks` con più blocchi (l'adapter lo supporta già passando `blocks.len() > 1`).
- **`pasta_sim::enc` accetta solo `bits.len() <= params.t`:** questo limita `n_bits` a 128 con PASTA3.

---

## 7. INFORMAZIONI CRITICHE

### Percorsi
- Progetto: `D:\download\Tesi\code_test\pipeline_official\psi-pmi`
- Transieve: `D:\download\Tesi\code_test\pipeline_official\Transieve-main` (verificare se ha sottocartella `Transieve-main/Transieve-main`)
- Cargo registry: `D:\Programmi\Rust\registry\src\index.crates.io-1949cf8c6b5b557f\`
- Shell: Git Bash UCRT64 su Windows

### Versioni
- Rust: stable edition 2021, x86_64
- Transieve: `0.1.0`
- `fhe`: `0.1.1`
- `fhe-traits`: `0.1`
- `tfhe`: `0.8` (usato da Transieve, non direttamente da noi)
- `curve25519-dalek`: `4`
- `ed25519-dalek`: `2`
- `sha3`: `0.10`

### Nomi chiave del codice
- `PastaBfv` (Transieve) — backend BFV + Pasta-3
- `PASTA3` — `PastaParams { t: 128, rounds: 3 }`
- `P` — `65537` (modulo field Pasta)
- `ThresholdCircuit::new(n, t)` — circuito di soglia (per AND: `new(n, n)`)
- `Tee1Pasta`, `TeeHostInputPasta`, `process_eval`
- `TransievePasta`, `PastaFhe`
- `run_e2e_pasta`
- `DataOwnerInput`, `E2eConfig`, `E2eResult`
- `ct_fingerprint`
- `derive_pasta_key`, `pasta_sim::enc/words_to_bytes/bytes_to_words`

### Link / repo
- Transieve: `https://github.com/RRas/Transieve`
- Documentazione implementation: `Transieve-main/docs/implementation/*.md`

### Parametri di default usati nei test
- `U = 4`, `n_bits = 128`, `hash_k = 3`
- `PASTA3` (t=128, rounds=3)
- `force_degree = Some(8192)` (e2e), `Some(2048)` (tee_negative)
- n = 2, 3

### Cose che se perse farebbero perdere tempo
1. **La derivazione della chiave Pasta** deve essere IDENTICA in `derive_pasta_key` (usata da `pack_key` e `pasta_sim::enc`). Se cambia in un solo posto, `transcipher` fallisce.
2. **Domain separation**: cambiare una costante di dominio invalida tutti i ciphertext precedenti.
3. **`force_degree`**: con `Some(d)` bypassa la scelta 128-bit di Transieve. `None` = sicuro, `Some(8192)` = test veloce.
4. **`sop_levels = ceil(log2 n)`**: n=2 → 1, n=3 → 2, n=4 → 2. Va aggiornato se n cambia.
5. **Le firme Ed25519 devono essere verificate PRIMA di accettare input**: ordine in `process_eval` è critico.

---

## MESSAGGIO DI AVVIO

*(Copia e incolla il blocco seguente nella nuova chat)*

---

Stiamo riprendendo un lavoro da una chat precedente. Ecco il contesto completo:

**Progetto:** implementazione Rust del protocollo PSI/PMI (Algorithm 1: OT 1-out-of-U, Algorithm 2: PSI/PMI con Bloom filter, transciphering e TEE) sopra il framework FHE **Transieve** (RRas su GitHub). Path: `D:\download\Tesi\code_test\pipeline_official\psi-pmi`. Backend: BFV + Pasta-3. TEE simulato in-process. Test target: tesi di laurea.

**Stato attuale:** tutti i test passano (protocol.rs, tee_negative.rs, e2e_pasta.rs). Numeri: n=2 → ~69 s, n=3 → ~92 s (degree 8192, non 128-bit safe).

**Prossimo passo:** Gruppo 3 — creare `examples/bench_e2e.rs` (binario CLI che prende `--u`, `--n-bits`, `--n-do`, `--degree`, `--runs`, stampa CSV con i timing di ogni fase), più script di sweep, per produrre le figure della tesi.

**Poi:** Gruppo 2 (ruolo `Server` esplicito + `net.rs` + zeroize) e Gruppo 4 (confronto con TFHE-Boolean).

**File del progetto (versione finale):**
- `Cargo.toml`, `.gitignore`, `README.md`, `NOTES.md`
- `src/lib.rs`, `src/types.rs`, `src/sig.rs`, `src/bloom.rs`, `src/sim.rs`, `src/pasta_fhe.rs`, `src/ot.rs`, `src/ttp.rs`, `src/tee.rs`, `src/psi.rs`
- `tests/protocol.rs`, `tests/e2e_pasta.rs`, `tests/tee_negative.rs`

Tutti i contenuti integrali di questi file sono nel documento di handoff che ho preparato. Fammi sapere se vuoi che te li ripassi per intero, oppure partiamo direttamente dal Gruppo 3 (bench).

**Comandi già funzionanti:**
```bash
cd psi-pmi
cargo build --release
cargo test --release --test protocol
cargo test --release --test tee_negative -- --test-threads=1
cargo test --release --test e2e_pasta -- --nocapture
```

**Decisioni chiave:**
- Backend BFV + Pasta-3 (packed, AND slot-wise). TFHE-Boolean scartato.
- Firma `Eval` da S1 sul **fingerprint SHAKE256** del ciphertext (non su byte serde, perché `fhe::bfv::Ciphertext` non implementa `serde::Serialize`).
- `process_eval` unificato nel TEE (anti-replay, verifica firma, decifratura, marcatura sid).
- n>2 DO supportato con `sop_levels = ceil(log2 n)`.
- Test negativi TEE con `force_degree = Some(2048)` e `--test-threads=1` (OOM con 8192).
- `mk_host_input` con `d1_prime: vec![]` per evitare `SIM decrypt failed`.

**Prossimo compito:** Gruppo 3 (bench). Dammi il via e procediamo.