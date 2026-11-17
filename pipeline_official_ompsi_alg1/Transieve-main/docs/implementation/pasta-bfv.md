# Pasta on BFV

Code: `src/cipher/bfv/pasta.rs`

This file contains the stripped implementation details for the BFV Pasta
transciphering path: cipher spec, packing, homomorphic linear layers, S-boxes,
lane packing, and validation.

## Cipher Shape

State:

```text
x in F_p^(2t)
x = x_L || x_R
x_L, x_R in F_p^t
p = 65537
```

Permutation:

```text
A_r o S_cube o A_{r-1} o S_feistel o ... o A_1 o S_feistel o A_0
```

There are `r + 1` affine layers. The first `r - 1` S-box layers are Feistel
layers; the last S-box layer is a cube.

Instances:

| Instance | Rounds `r` | Key words `2t` | Output words `t` |
|---|---:|---:|---:|
| Pasta-3 | 3 | 256 | 128 |
| Pasta-4 | 4 | 64 | 32 |

## Affine Layer

For each layer `j`:

```text
A_j(x) =
    [[2I, I], [I, 2I]]
    * [
        M_{j,L} * x_L + c_{j,L}
        M_{j,R} * x_R + c_{j,R}
      ]
```

Implementation details:

- `M_{j,L}`, `M_{j,R}`, `c_{j,L}`, and `c_{j,R}` are public.
- The layer generator is deterministic from block/counter inputs.
- The two branch matrices are evaluated together using two-row packing.
- The branch mix `[[2I,I],[I,2I]]` is implemented as:

```text
y = 2*u + row_swap(u)
```

## S-boxes

Feistel layer:

```text
S'(y)_0 = y_0
S'(y)_l = y_l + y_{l-1}^2       for l > 0
```

Homomorphic implementation:

1. Rotate by one slot.
2. Mask slot 0 and spill positions.
3. Square with one ciphertext-ciphertext multiply.
4. Add to the original state.

Cube layer:

```text
S(x)_i = x_i^3
```

Homomorphic implementation:

```text
x2 = x * x
x3 = x2 * x
```

Products are relinearized.

## Keystream and Symmetric Encryption

Pasta uses truncation:

```text
keystream block i = left_t(Pasta_pi(sk, N, i))
Enc: c_i = m_i + keystream_i
Dec: m_i = c_i - keystream_i
```

In BFV, `c_i` is public field data and the keystream is encrypted, so recovery is
public subtraction from encrypted slots.

## Two-row Packing

BFV slots are treated as a two-row grid:

```text
row 0: x_L
row 1: x_R
```

`pack_key` places both branches in one ciphertext. Column rotations rotate both
rows simultaneously; row rotation swaps the two rows.

Benefits for the implementation:

- one ciphertext holds the full Pasta state
- one matrix-vector routine handles both branches
- the MDS branch mix is one row swap plus additions
- S-boxes apply to both branches at once

The keystream is read from row 0, slots `0..t`.

## Matrix-vector Product

The diagonal method computes:

```text
M*x = sum_k diag_k(M) * rot_k(x)
diag_k(M)[i] = M[i][(i+k) mod t]
```

Diagonals are public plaintexts, so multiplying by a diagonal is plaintext-
ciphertext multiplication and does not consume ciphertext-ciphertext depth.

## Baby-step/Giant-step

The implementation factors `k = i*t1 + j`:

```text
M*x =
    sum_i rot_{i*t1}(
        sum_j diag'_{i*t1+j}(M) * rot_j(x)
    )
```

Setup:

```text
t1 = ceil(sqrt(t))
t2 = ceil(t / t1)
```

This reduces rotations from `t` to about `t1 + t2`. Padded indices where
`k >= t` are skipped.

The pre-rotation of diagonals is folded into plaintext placement in
`diag_plaintext`.

## Replication Trick

Homomorphic column rotations wrap over the whole row, but Pasta needs cyclic
rotation over only the active `t` columns. The implementation first replicates a
branch:

```text
[x] -> [x | x]
```

Then rotations by `k < t` read from the second copy on wrap and behave like
cyclic rotations over length `t`.

## Rotation Direction Probe

The code probes `rotates_columns_by(1)` once by rotating an index vector and
reading the resulting slot position. This avoids hardcoding whether the crate's
positive rotation means left or right.

## Lane Packing

At large BFV degrees, one two-row Pasta state uses only `2t` columns. The
implementation tiles independent states side by side:

```text
L = cols / (2t)
```

Each lane has:

- the same key
- a distinct block counter
- distinct public affine layers
- valid output in the first `t` columns of its `2t` segment

Rotations used by Pasta are smaller than `t`, so they remain inside each
`2t`-wide segment. Plaintext operands are tiled per lane.

The lane mask keeps the second half of each segment zero so global cyclic wrap
does not leak data between lanes.

Relevant functions:

- `keystream_blocks`
- `transcipher_recover_blocks`
- `decrypt_lane_bits`

## Depth and Parameter Selection

The linear layers use plaintext diagonals. The only ciphertext-ciphertext
multiplications are in the S-boxes.

The secure constructor:

```rust
PastaBfv::new_secure(...)
```

selects a BFV degree from the modulus chain and the HES table. With `p = 65537`,
the SIMD degree is capped by `2n | 65536`, so `n <= 32768`.

Development constructors keep degree explicit for small tests.

## Validation

Plaintext oracle:

- `keystream_block`
- plaintext roundtrip checks

Homomorphic tests:

- `pasta_bfv_keystream_matches_plaintext`
- `pasta_bfv_bsgs_padded_split_matches_plaintext`
- `pasta_bfv_multilane_keystream_matches_plaintext`
- `pasta_bfv_multilane_transcipher_sop_matches_plaintext`

The tests compare decrypted BFV outputs against the plaintext Pasta oracle and,
for the full pipeline test, against the plaintext threshold SOP.

## Implementation Notes

- Public Pasta layers are generated deterministically with `StdRng`.
- Public symmetric ciphertext words are subtracted from encrypted keystream
  slots; they are not encrypted as BFV inputs.
- Rotation hoisting is not implemented because the current `fhe` crate API does
  not expose the needed key-switch decomposition hook.
- The BFV pipeline processes Pasta blocks in chunks of `L` lanes.

