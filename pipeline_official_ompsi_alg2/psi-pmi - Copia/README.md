# PSI-PMI

A Rust implementation of a **Private Set Intersection with Party Membership Inference (PSI-PMI)** protocol, based on Algorithm 2 (alternative variant): no TEE, simulated CMUX, and multi-block support.

The protocol lets multiple data owners find the intersection of their private sets while keeping every non-shared element confidential. It combines a **symmetric-cipher transcipher** (Pasta stream cipher over a BFV FHE scheme) with an **oblivious transfer (OT)** layer based on Ristretto255 and a **Bloom-filter** encoding.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
- [Protocol Flow](#protocol-flow)
- [Multi-Block Support](#multi-block-support)
- [Security Notes](#security-notes)
- [Installation](#installation)
- [Usage](#usage)
  - [Running Tests](#running-tests)
  - [Running the Benchmark](#running-the-benchmark)
- [Benchmark Output](#benchmark-output)
- [Crate Dependencies](#crate-dependencies)
- [Testing](#testing)
- [License](#license)

---

## Overview

This crate implements the **Algorithm 2 "Alternative"** variant of a PSI-PMI protocol. Its main features:

- **No TEE (Trusted Execution Environment)**: all steps are done with cryptographic primitives and FHE.
- **Simulated CMUX**: the CMUX (conditional multiplexer) step is replaced by a plaintext lookup, as described in `NOTES.md`.
- **Multi-block**: Bloom filter sizes and the index matrix can exceed the Pasta lane size (`t = 128`), and are transparently split across multiple blocks.

The core idea:

1. Each data owner encodes its set into a **Bloom filter**, then encrypts it using the **Pasta stream cipher** (symmetric SIM).
2. The encrypted filters are transferred through an **oblivious transfer** protocol so that no party learns the others' encodings.
3. A **transcipher** step converts the Pasta ciphertexts into **BFV homomorphic ciphertexts**, using a key packed under FHE.
4. A homomorphic **slot-wise AND** across all data owners yields the intersection filter.
5. The result is decrypted and used (via a simulated CMUX) to decide membership for each element of DO₁.

---

## Architecture

```
┌──────────────┐   SIM (Pasta)    ┌──────────┐   OT (Ristretto)   ┌──────────┐
│ Data Owners  │ ───────────────▶ │  TTP     │ ─────────────────▶ │  DO₁ /   │
│ (Bloom filt) │                  │ (σ, key) │                    │  Server  │
└──────────────┘                  └──────────┘                    └──────────┘
        │                                                               │
        │                                                               ▼
        │                                              ┌──────────────────────────┐
        └───────────────▶ Transcipher (BFV + Pasta) ──▶│  FHE AND → decrypt bits   │
                                                        │  CMUX (simulated lookup)  │
                                                        └──────────────────────────┘
```

---

## Modules

| Module | Description |
|--------|-------------|
| `bloom` | Shake256-based hash families and Bloom filter construction. |
| `net` | In-memory network simulation (`Network`, `DirectChannel`) for OT messaging. |
| `ot` | 1-out-of-U Oblivious Transfer over Ristretto255 with 48-bit tags. |
| `pasta_fhe` | Adapter for Transieve's BFV+Pasta-3 backend (`PastaFhe` trait). |
| `psi` | End-to-end orchestration of Algorithm 2 (`run_e2e_pasta_alt`). |
| `sig` | Ed25519 signing / verification traits and implementations. |
| `sim` | ChaCha20-Poly1305 SIM cipher + Pasta-shaped SIM for the transcipher. |
| `ttp` | Trusted Third Party: signing keys, domain-separated messages (`σ`, `T`, `Eval`). |
| `types` | Common types: `Sid`, `Token`, and fresh-generation helpers. |

---

## Protocol Flow

The end-to-end function is `psi::run_e2e_pasta_alt`. It proceeds as follows:

1. **FHE setup** — Create a BFV context with SOP depth `ceil(log₂(n))` (enough levels for the n-way AND).
2. **Key packing** — Each data owner's symmetric key `k_sym` is derived (via SHAKE256) into `2t` field elements and packed into an FHE ciphertext.
3. **SIM encryption** — Each data owner encodes its set into `U` Bloom filters, each encrypted with Pasta in multi-block mode. DO₁ additionally builds an index matrix that maps each of its elements to its hash positions.
4. **Oblivious Transfer** — The encrypted filters and index matrix are transferred to the server via OT, all bound to a single shared `σ` established by the TTP:
   - `ot_phase1`: DO generates a random scalar `r` and points `c`.
   - `ot_phase2` / `ot_phase2_with_sigma`: TTP generates `k` and outputs `pk₀`, `t`, and `σ`.
   - `ot_phase3`: DO produces ciphertexts `ct_j` and 48-bit tags.
   - `ot_phase4`: TTP extracts the message `m_σ`.
5. **TTP signs σ** — Ed25519 signature authenticates σ between servers.
6. **Transcipher + AND + decrypt** — For each group of `lanes` blocks:
   - The Pasta ciphertexts are transciphered into BFV ciphertexts.
   - A homomorphic slot-wise AND across all data owners yields `E_B`.
   - `E_B` is decrypted to plaintext bits (simulated CMUX).
7. **Membership decision** — DO₁ declares an element to be in the intersection iff all `h` hash lookups succeed (all bits are 1).
8. **Ground truth check** — The function returns the expected and found intersections, plus false-positive/false-negative counts.

---

## Multi-Block Support

Pasta processes messages in lanes of `t = 128` field elements. This implementation handles arbitrary `n_bits` (Bloom filter size) and arbitrary set sizes by splitting both the filter and the index matrix into multiple Pasta blocks:

- `n_b = ceil(n_bits / t)` — filter blocks.
- `n_a = ceil(idx_bits_total / t)` — index-matrix blocks.

Nonces are domain-separated:
- Filter blocks: `[σ, 0]`
- Index blocks: `[U + σ, 0]`

The **global block counter** (`block_ids`) is preserved across groups so that the keystream generation stays consistent between the SIM side and the FHE transcipher side.

---

## Security Notes

- **Zeroization**: `DataOwnerInput` and `OtDoState` use `zeroize` to wipe sensitive material (symmetric keys, OT scalars) on drop.
- **Authenticated encryption**: ChaCha20-Poly1305 is used with a fixed AAD (`PSI-PMI/SIM/v1`).
- **Domain separation**: All SHAKE256 and signing domains are prefixed (`PSI-PMI/.../v1`) to avoid cross-protocol collisions.
- **OT tags**: 48-bit tags with collision detection in `ot_phase4` (a warning is printed on collision; the first match is used).
- **TTP signature**: σ is signed and verified before use, binding it to the session ID `sid`.

> ⚠️ **This is a research prototype.** The CMUX is **simulated** (plaintext lookup instead of a real homomorphic conditional multiplexer). See `NOTES.md` for details. Do not use it in production without a full security review.

---

## Installation

Add the crate to your `Cargo.toml` (path or git dependency):

```toml
[dependencies]
psi-pmi = { path = "../psi-pmi" }
```

The crate depends on `transieve` for the BFV+Pasta-3 backend.

---

## Usage

### Running Tests

```bash
cargo test
```

The test suite (`psi.rs`) covers:

- `e2e_alt_n2_pasta3` — 2 data owners, single block.
- `e2e_alt_n3_pasta3` — 3 data owners, single block.
- `e2e_alt_no_false_negatives_larger_set` — larger sets, no false negatives.
- `e2e_alt_multi_block_filters` — `n_bits = 200 > t = 128`.
- `e2e_alt_multi_block_large_set` — `set_size = 20`, `n_bits = 500`.

### Running the Benchmark

```bash
cargo run --release --example bench_e2e_alt -- [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--n <N>` | `2` | Number of data owners |
| `--u <U>` | `4` | Hash families / OT choices |
| `--n-bits <B>` | `128` | Bloom filter size in bits |
| `--hash-k <K>` | `3` | Hash functions per family |
| `--degree <D>` | `8192` | FHE polynomial degree (`0` = secure default) |
| `--runs <R>` | `3` | Number of runs |
| `--set-size <S>` | `10` | Elements per data owner |
| `--overlap <O>` | `set_size/3` | Number of shared elements |
| `--out <PATH>` | `bench_alg2.csv` | CSV output path |
| `--append` | — | Append to an existing CSV |
| `--help`, `-h` | — | Show help |

**Example:**

```bash
cargo run --release --example bench_e2e_alt -- \
  --n 3 --u 4 --n-bits 200 --hash-k 3 \
  --set-size 20 --overlap 5 --runs 5 \
  --out results.csv
```

---

## Benchmark Output

Each successful run writes one CSV row with the following columns:

| Column | Description |
|--------|-------------|
| `run` | Run index |
| `n`, `u`, `n_bits`, `hash_k` | Configuration |
| `degree` | FHE degree (`secure` for none) |
| `set_size`, `overlap` | Input generation parameters |
| `backend` | Always `bfv+pasta3-alt` |
| `n_b_blocks`, `n_a_blocks` | Number of filter / index blocks |
| `sigma` | OT selection index |
| `total_s` | Total wall-clock time (s) |
| `fhe_setup_s` | FHE context setup time |
| `pack_key_s` | Key packing time |
| `sim_enc_s` | SIM encryption time |
| `ot_s` | OT protocol time |
| `transcipher_s` | Transcipher time |
| `eval_and_s` | Homomorphic AND time |
| `cmux_sim_s` | Decrypt + simulated CMUX time |
| `expected_intersection_size` | Ground-truth intersection size |
| `found_intersection_size` | Reported intersection size |
| `false_positives`, `false_negatives` | Error counts |
| `match` | `true` if FP = FN = 0 |

A summary is printed to stdout after all runs:

```
=== summary ALG2 (N runs) ===
n=... u=... n_bits=... hash_k=... degree=... set_size=... overlap=...
n_b_blocks=... n_a_blocks=...

phase                    mean (s)     stddev (s)
total_s                    ...
fhe_setup_s                ...
...
```

---

## Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `chacha20poly1305` | Symmetric authenticated cipher (SIM). |
| `curve25519-dalek` | Ristretto255 group operations (OT). |
| `ed25519-dalek` | TTP signing / verification. |
| `fhe` | BFV ciphertext type. |
| `fhe-traits` | Ciphertext serialization trait. |
| `rand` | Cryptographic randomness. |
| `rayon` | Per-block parallel SIM encryption. |
| `sha3` | SHAKE256 XOF (key derivation, hashing, fingerprints). |
| `thiserror` | Error type derivation. |
| `transieve` | BFV+Pasta-3 backend (`PastaBfv`, `PastaParams`, `keystream_block`, `ThresholdCircuit`). |
| `zeroize` | Sensitive data erasure on drop. |

---

## Testing

```bash
# Run all tests
cargo test

# Run with output (to see timing logs)
cargo test -- --nocapture

# Run a single test
cargo test e2e_alt_multi_block_filters -- --nocapture
```

---

