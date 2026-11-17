# BFV Backend Implementation Notes

Code:

- `src/backend/bfv.rs`
- `src/cipher/bfv/mod.rs`
- `src/cipher/bfv/prototype.rs`
- `src/cipher/bfv/pasta.rs`
- `src/cipher/bfv/rasta.rs`
- `src/runtime/pipeline.rs`

BFV support is behind the `bfv` feature.

```powershell
cargo test --release --features bfv bfv_
```

## Representation

The BFV backend uses the pure-Rust `fhe` crate. Plaintexts live in SIMD slots
modulo a plaintext modulus. The active prime is:

```text
p = 65537
```

This gives prime-field arithmetic and SIMD packing for valid ring degrees where
`2n` divides `p - 1`.

## Direct Threshold SOP Baseline

`src/backend/bfv.rs` evaluates the same threshold circuit as the TFHE backend, but
slot-wise:

1. Build BFV parameters.
2. Generate secret key and relinearization/evaluation keys.
3. Pack many Bloom bits into one SIMD plaintext.
4. Encrypt one packed ciphertext per party chunk.
5. Evaluate the threshold circuit in every slot.
6. Decrypt and unpack result bits.

Boolean operations are encoded over field elements `0` and `1`:

```text
AND(a,b) = a * b
OR(a,b)  = a + b - a*b
```

Products are relinearized. The direct SOP baseline does not need rotations
because each slot is independent.

## Prototype Rotation Test

`src/cipher/bfv/prototype.rs` verifies the rotation primitive needed by packed
cipher linear layers.

The prototype:

1. Builds a BFV SIMD context.
2. Enables selected column rotations.
3. Probes the slot permutation induced by rotation.
4. Evaluates a rotate-and-add expression such as:

```text
v + rot(v,1) + rot(v,2)
```

5. Checks the decrypted result against a plaintext oracle.

The same pattern is used by Pasta's matrix-vector product.

## BFV Cipher Dispatch

`src/cipher/bfv/mod.rs` defines the BFV cipher side. The implemented full
pipeline cipher is Pasta:

```text
--transcipher pasta
```

The pipeline route is:

```text
CipherSpec::Bfv(CipherBfv::Pasta)
    -> pipeline::run_transcipher_stage_bfv_tpsi
    -> PastaBfv::transcipher_recover_blocks
    -> BFV slot-wise threshold SOP
```

`--baseline bfv` selects the direct BFV SOP baseline. When `--transcipher pasta`
is used, the baseline is auto-coupled to BFV so the ciphertexts remain in one
backend.

## Key and Evaluation Material

Pasta and packed BFV operations need:

- encryption/decryption keys
- relinearization keys for ciphertext-ciphertext multiplication
- Galois/evaluation keys for rotations

Rotation keys are enabled for the amounts used by:

- Pasta baby-step rotations
- Pasta giant-step rotations
- branch replication
- Feistel shift
- row swap

The code also enables complementary rotation amounts where needed so indexing
can remain direction-agnostic.

## Correctness Checks

BFV correctness checks should cover:

- packed slot order
- actual rotation direction/permutation
- field arithmetic preserving `0`/`1` semantics for the SOP
- relinearization after products
- modulus-chain depth for the full circuit
- plaintext oracle agreement for every cipher path

Relevant tests include the `bfv_` tests and the Pasta tests described in
[Pasta on BFV](pasta-bfv.md).

## Practical Limits in This Implementation

- The BFV backend is feature-gated to keep default builds lightweight.
- The active BFV path is single-key.
- The direct SOP baseline uses slot-wise packed arithmetic; it does not rotate.
- Pasta uses rotations and packed linear layers.
- The pure-Rust `fhe` crate does not expose rotation hoisting, so the current
  Pasta measurements use ordinary rotations.
