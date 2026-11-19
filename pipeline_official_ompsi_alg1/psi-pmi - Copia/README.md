# PSI-PMI

A Rust implementation of a **Private Set Intersection with Pattern Matching / Multi-party Intersection (PSI-PMI)** protocol built on top of a **BFV + PASTA-3** homomorphic encryption backend (via [Transieve](https://github.com/)), combining:

- **Bloom filter** encoding of each party's set,
- **Oblivious Transfer (OT)** based on the Ristretto255 group to privately hand each data owner the correct ciphertext of the reference set,
- **PASTA-3 transciphering** from the symmetric (ChaCha20-Poly1305) domain into the FHE domain,
- a **Threshold AND** over all parties' ciphertexts,
- a **TEE (S_1)** that, after verification of signatures from the TTP and the S_1 signer, decrypts the final ciphertext and emits per-element authentication **tokens** for elements in the intersection.

The protocol is fully **multi-block**: the Bloom filter can be arbitrarily large (not constrained by `params.t`), and blocks are grouped so that each FHE ciphertext processes up to `lanes` PASTA blocks in a single AND evaluation.

---

## Table of contents

- [Architecture](#architecture)
- [Crates and modules](#crates-and-modules)
- [Protocol flow](#protocol-flow)
- [Usage](#usage)
  - [Running the end-to-end benchmark](#running-the-end-to-end-benchmark)
  - [CLI options](#cli-options)
  - [Multi-block sanity check](#multi-block-sanity-check)
- [Testing](#testing)
- [Security model](#security-model)
- [Communication cost](#communication-cost)
- [Security notices](#security-notices)
- [License](#license)

---

## Architecture

```
┌────────────┐       OT (Ristretto255)       ┌────────────┐
│  DO_1..n   │◀─────────────────────────────▶│    TTP     │
│            │   signed T_i  /  signed σ     │            │
└─────┬──────┘                               └────────────┘
      │  m_σᵢ = SIM-blocks of Bloom_σᵢ
      │  D1' = ChaCha20Poly1305(D_1)
      ▼
┌──────────────────────────────────────────────────────────┐
│                       S_1 / TEE                          │
│  1. verifies TTP signatures on T_i and σ                 │
│  2. transciphers each m_σᵢ → E_Aᵢ                         │
│  3. computes E_B = AND(E_A₁, …, E_Aₙ)  (Threshold SOP)   │
│  4. verifies S_1 signature over fingerprint(E_B)         │
│  5. decrypts E_B → bit-slots, evaluates Bloom σ          │
│  6. emits (element, token) pairs for DO_1                │
└──────────────────────────────────────────────────────────┘
```

- **Data Owners (DOs)** each hold a set and a symmetric key. They build a Bloom filter using `u` hash families and encrypt it block-by-block under their symmetric key.
- The **TTP** runs a 1-out-of-`u` OT per DO. The same index `σ` is used for every DO, so the AND makes sense (only family `σ` survives).
- The **TEE (S_1)** is the only party that holds the BFV decryption key, and it only acts after verifying that both the TTP chose `σ` and the S_1 signer approved the final `E_B` (via a SHAKE256 fingerprint of the ciphertexts).

---

## Crates and modules

| Module       | Responsibility                                                                                  |
|--------------|-------------------------------------------------------------------------------------------------|
| `bloom`      | `Family` / `HashFamilies`: SHAKE256-based positions; `BloomFilter` with bit packing and slot export |
| `ot`         | Ristretto255 1-out-of-`u` OT (4 phases) with 48-bit truncated tags and scalar zeroization       |
| `pasta_fhe`  | `PastaFhe` trait + `TransievePasta` adapter; `ct_fingerprint(_multi)` for signing ciphertexts   |
| `sim`        | ChaCha20-Poly1305 SIM + PASTA-3-shaped multi-block keystream encryption (`pasta_sim::enc_blocks`) |
| `psi`        | End-to-end orchestration (`run_e2e_pasta`), multi-block pipeline, timings, comm cost            |
| `sig`        | Ed25519 signer/verifier trait wrappers                                                          |
| `tee`        | `Tee1Pasta`: anti-replay by `sid`, host input gating, signature verification, decryption       |
| `ttp`        | Trusted Third Party: Ed25519 keys, domain-separated message builders (`sigma_msg`, `t_msg`, `eval_msg`) |
| `types`      | `Sid`, `Token`, freshness helpers                                                              |

---

## Protocol flow

1. **Setup.** Each DO picks a random symmetric key `k_sym^(i)`. The TEE (S_1) generates an Ed25519 keypair. The TTP generates an Ed25519 keypair. A fresh `sid` is generated.
2. **DO encodes.** For each of the `u` hash families, DO `i` builds a Bloom filter of size `n_bits`, then SIM-encrypts it block-by-block (PASTA-shaped keystream), producing `u` messages of `m_sigma_len` bytes each.
3. **DO_1 submits host input.** `D_1'` = each element of DO_1 individually encrypted with `k_sym^(1)`; `H` = the hash family set; `k_sym^(1)` is also submitted to the TEE.
4. **OT phase 1–2.** Each DO picks random scalars and sends `g^r` plus `u-1` Ristretto points. The TTP picks `σ ∈ [1, u]`, derives `pk_0`, and signs `T`. The *same* `σ` is forced for every DO.
5. **OT phase 3–4.** Each DO uses `pk_0` to produce `u` ciphertexts + tags, then recovers `m_σ^i` (the SIM ciphertext of the Bloom filter for family `σ`).
6. **Transcipher.** For each group of `lanes` blocks, S_1 calls `transcipher` on each `m_σ^i` to obtain `E_A^i` ciphertexts.
7. **AND over all parties.** `ThresholdCircuit` (n-out-of-n) is evaluated over the `E_A^i` to obtain `E_B`.
8. **Sign + decrypt.** S_1 signs `SHAKE256(fingerprint(E_B))` via the domain-separated `eval_msg(sid, fp)`. The TEE verifies this signature **and** the TTP signature over `σ`, then decrypts `E_B` into bit slots, and for each `x ∈ D_1'`, checks whether `Bloom_σ(x)` is all-ones. If so, it emits a fresh 32-byte token; otherwise a zero token.

---

## Usage

Add as a dependency (path or git):

```toml
[dependencies]
psi-pmi = { git = "https://github.com/<you>/psi-pmi" }
transieve = { git = "https://github.com/<you>/transieve" }
```

### Running the end-to-end benchmark

```bash
cargo run --release --example bench_e2e -- \
    --n 2 --u 4 --n-bits 128 --hash-k 3 \
    --set-size 10 --overlap 3 \
    --degree 8192 --runs 3 \
    --out bench_results.csv
```

A CSV is written with per-run timings (FHE setup, pack key, SIM enc, OT, transcipher, AND, TEE), ciphertext sizes, communication cost, and false positive / false negative counts.

### CLI options

| Flag          | Default               | Meaning                                                       |
|---------------|-----------------------|---------------------------------------------------------------|
| `--n`         | `2`                   | Number of data owners (≥ 2)                                   |
| `--u`         | `4`                   | Number of hash families / OT choices                          |
| `--n-bits`    | `128`                 | Bloom filter size in bits (multi-block if > `params.t`)       |
| `--hash-k`    | `3`                   | Hash functions per family                                     |
| `--degree`    | `8192`                | FHE degree (`0` = secure / 32768)                             |
| `--runs`      | `3`                   | Number of benchmark repetitions                               |
| `--set-size`  | `10`                  | Elements per DO                                               |
| `--overlap`   | `set_size / 3`        | Shared elements across all DOs                                |
| `--out`       | `bench_results.csv`   | CSV output path                                               |
| `--append`    | off                   | Append to existing CSV                                        |

Multi-block sizing for PASTA-3 (`t = 128`):

- `n_bits ≤ 128` → 1 block
- `degree 8192` → 16 lanes → up to **2048 bit** per ciphertext
- `degree 16384` → 32 lanes → up to **4096 bit**
- `degree 32768` → 64 lanes → up to **8192 bit**

Beyond that, additional ciphertexts are produced; RAM is the practical limit.

### Multi-block sanity check

```bash
cargo run --release --example multiblock_check
```

Verifies that for a set of `n_bits` values (including non-multiples of `t`) the transcipher + decrypt round-trip is exact.

---

## Testing

```bash
cargo test --release
```

The test suite covers:

- `protocol::bloom_no_false_negatives` — Bloom filter inserts and lookups
- `protocol::ot_all_sigmas` — the 4-phase OT recovers the intended message for every `σ`
- `e2e_pasta::e2e_n2_pasta3`, `e2e_n3_pasta3` — full 2-party and 3-party protocol with real tokens
- `tee_negative::*` — every gate in the TEE:
  - double host input,
  - bad / replay σ signature,
  - `Eval` before σ is registered,
  - bad S_1 signature,
  - **`sid` replay**,
  - host input submitted after σ.

Release mode is strongly recommended: a debug build of the PASTA-3 backend is an order of magnitude slower.

---

## Security model

- **Threat model.** Semi-honest data owners; a semi-honest-but-curious TTP that is nonetheless trusted to sample `σ` uniformly and not to collude with the TEE; a malicious TEE is only detectable via the S_1 signature over the fingerprint of `E_B`.
- **Symmetric key material.** `k_sym` is zeroized on drop in `DataOwnerInput` and `TeeHostInputPasta`. OT scalars are zeroized on drop in `OtDoState`.
- **Anti-replay.** The TEE rejects any `sid` it has already processed (`used_sids` set).
- **Signatures.**
  - TTP signs `T` for each DO and `σ` (both domain-separated).
  - S_1 signs `SHAKE256("PSI-PMI/Eval/ct-fingerprint-multi/v1" || n || fp₁ || … || fpₙ)` where each `fpᵢ = SHAKE256("PSI-PMI/Eval/ct-fingerprint/v1" || len || to_bytes(ctᵢ))`.
  - The fingerprint approach avoids serialising the BFV ciphertext through serde and binds the signature to the exact ciphertext bytes.
- **Domain separation.** All hashed/tagged messages carry a versioned prefix (`PSI-PMI/.../v1`).

### What the TEE learns

The TEE learns the final AND result (bit slots of `E_B`) and, through `k_sym^(1)`, the plaintext of `D_1`. It does **not** learn other DOs' elements. The TTP learns only OT handles (`g^r`, `c_j`), never plaintext elements.

---

## Communication cost

For each party (`n` parties, `u` hash families, `num_blocks` PASTA blocks):

| Path          | Bytes (per party)                          |
|---------------|--------------------------------------------|
| DO → TTP      | `(u-1) * 32 + 32` (points + `g^r`)         |
| TTP → DO      | `32` (`pk_0`)                              |
| TTP → S_1     | `32` (signed `σ`)                          |
| DO → S_1/S_1' | `u * (m_sigma_len + 6)` (tag is 6 bytes)   |
| S_1 → TEE     | `sum(ct_size_bytes)` (fingerprinted)       |
| S_1 → TEE     | same as above (delivered to the TEE)       |

For a `n_bits = 2048`, `degree = 8192` (single ciphertext, 16 lanes) run, this typically lands in the low hundreds of kilobytes per party plus the BFV ciphertext cost.

---

## Security notices

- The default `force_degree = 8192` used by `bench_e2e` and tests is **NOT 128-bit secure**. It is only meant for fast iteration. Use `--degree 0` (→ `new_secure`, degree 32768) for anything resembling production.
- The TEE holds the BFV secret key. Compromise of the TEE breaks confidentiality of the AND result. The S_1 signature gate is designed to make *undetected* tampering with `E_B` infeasible, not to protect against a fully compromised TEE.
- `ChaCha20-Poly1305` uses a fresh random nonce in `enc_with_nonce` but a **deterministic** nonce (`[hash_family, block_id]`) in `pasta_sim::enc_blocks`. This is safe as long as `k_sym` is unique per DO and the message is the Bloom filter (which is `u * num_blocks` distinct nonces per DO). Do not reuse a `k_sym` across runs.
- The OT tag is truncated to **48 bits**, which is fine for a semi-honest setting but gives roughly `2^-48` collision probability per query. `ot_phase4` warns on collisions and picks the first match.

---
The code currently depends on:

- [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) — Ristretto255
- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — signatures
- [`sha3`](https://crates.io/crates/sha3) — SHAKE256
- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) — SIM encryption
- [`zeroize`](https://crates.io/crates/zeroize) — key wiping
- [`rayon`](https://crates.io/crates/rayon) — parallel block encryption
- [`transieve`](https://github.com/) — BFV + PASTA-3 backend (external)
- [`fhe`](https://crates.io/crates/fhe) — BFV primitives
