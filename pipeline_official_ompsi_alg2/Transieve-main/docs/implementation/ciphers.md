# Cipher Implementation Notes

These notes keep only cipher specs, code layout, implementation details, and
practical FHE tricks. Paths are relative to the repository root.

## Kreyvium-128

Code: `src/cipher/boolean/kreyvium.rs`

### State

| Register | Bits | Stored as | Role |
|---|---:|---|---|
| `a` | 93 | encrypted `EncBit` | NLFSR 1 |
| `b` | 84 | encrypted `EncBit` | NLFSR 2 |
| `c` | 111 | encrypted `EncBit` | NLFSR 3 |
| `K*` | 128 | encrypted `EncBit` | rotating key feedback |
| `IV*` | 128 | public `bool` | rotating IV feedback |

Registers are stored in spec order: `a[0]` is `a_1`, `a[92]` is
`a_93`. The shifted-out end is the highest index, and new feedback enters at
index 0.

### Initialization

```text
a   = k_0..k_92
b   = iv_0..iv_83
c   = iv_84..iv_127 || 66 ones || 0
K*  = k_0..k_127
IV* = iv_0..iv_127
```

Then run 1152 warm-up cycles and discard their outputs.

### Step Function

```text
t1 = a_66 XOR a_93  XOR (a_91  AND a_92 ) XOR b_78  XOR iv*_127
t2 = b_69 XOR b_84  XOR (b_82  AND b_83 ) XOR c_87
t3 = c_66 XOR c_111 XOR (c_109 AND c_110) XOR a_69  XOR k*_127
z  = t1 XOR t2 XOR t3
```

Then:

```text
a   <- t3 || a_1..a_92
b   <- t1 || b_1..b_83
c   <- t2 || c_1..c_110
K*  <- k*_127 || k*_0..k*_126
IV* <- iv*_127 || iv*_0..iv*_126
```

### Implementation Tricks

- Public-bit XOR uses `xor_const`: `x XOR 0` is clone/no-op, `x XOR 1` is
  `sk.not(x)`.
- `IV*` stays plaintext because it is public and only appears through
  `xor_const`.
- The `step` function uses 1-indexed closures (`a(i)`, `b(i)`, `c(i)`) so code
  mirrors the spec taps.
- `keystream_plain` is the bool reference implementation used by tests and by
  sender-side symmetric encryption.

### Tests

- `fhe_matches_plaintext_keystream`: compares decrypted FHE keystream bits with
  `keystream_plain` after the 1152-cycle warm-up.

Run:

```powershell
cargo test --release --lib cipher::kreyvium
```

## Grain-128a

Code: `src/cipher/boolean/grain128a.rs`

### Variant

| Item | Value |
|---|---|
| Mode | Grain-128a, `IV0 = 0`, encryption-only/no-auth |
| Key | 128 bits |
| IV | 96 bits |
| State | 128-bit NFSR + 128-bit LFSR |
| Startup | 256 cycles |
| Output | 1 keystream bit per cycle |

### State and Indexing

The code stores registers in natural spec order:

```rust
nfsr[k] = b_{i+k}
lfsr[k] = s_{i+k}
```

So spec tap `b_{i+67}` is `self.nfsr[67]`. At the end of a cycle:

```rust
reg.rotate_left(1);
*reg.last_mut().unwrap() = new;
```

### Initialization

- NFSR is the encrypted 128-bit key.
- LFSR is `iv[0..96] || 31 ones || 0`, stored as trivial ciphertexts.
- Current integration uses an all-zero IV.

### Clock Cycle

```text
y       = pre_output()
lfsr_fb = lfsr_feedback()
nfsr_fb = nfsr_feedback()

if init:
    new_lfsr = lfsr_fb XOR y
    new_nfsr = nfsr_fb XOR y
else:
    new_lfsr = lfsr_fb
    new_nfsr = nfsr_fb
```

Then both registers rotate left and insert the new feedback bit.

### Pre-output Filter

```text
h(x) =
    x0*x1 XOR x2*x3 XOR x4*x5 XOR x6*x7 XOR x0*x4*x8

y_i =
    h(x) XOR s_{i+93}
    XOR b_{i+2} XOR b_{i+15} XOR b_{i+36} XOR b_{i+45}
    XOR b_{i+64} XOR b_{i+73} XOR b_{i+89}
```

Mapped state bits:

```text
x0=b12, x1=s8,  x2=s13, x3=s20, x4=b95,
x5=s42, x6=s60, x7=s79, x8=s94
```

The filter costs four quadratic products plus one cubic product.

### Feedback

LFSR taps:

```rust
[0, 7, 38, 70, 81, 96]
```

NFSR feedback has:

- linear taps: `[0, 26, 56, 91, 96]`
- seven quadratic terms
- two cubic terms
- one quartic term `(88, 92, 93, 95)`
- an added `s_i` term

### Implementation Tricks

- Public ciphertext-bit XOR uses `xor_const` instead of encrypting constants.
- Startup and output timing are split in `decrypt_stream_timed`.
- The plaintext reference is shared by tests and `Cipher::encrypt_stream`.

### CLI Names

```text
grain
grain128a
grain-128a
```

## AES-128 CTR

Code:

- Boolean: `src/cipher/boolean/aes128.rs`
- Shortint: `src/cipher/shortint/aes128.rs`

### Variant

| Item | Value |
|---|---|
| Mode | AES-128 CTR keystream |
| Key | 128 bits |
| Block | 128 bits |
| Rounds | 10 |
| State layout | 16 bytes, column-major |
| Byte layout | MSB-first bits |
| S-box | Boyar-Peralta size-optimized netlist |

### BitEngine Pattern

AES is written once against:

```rust
trait BitEngine {
    type Bit: Clone;
    fn xor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn and(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn xnor(&self, a: &Self::Bit, b: &Self::Bit) -> Self::Bit;
    fn not(&self, a: &Self::Bit) -> Self::Bit;
    fn constant(&self, v: bool) -> Self::Bit;
}
```

Engines:

- `PlainEngine`: bool oracle and sender-side keystream.
- `FheEngine`: `tfhe::boolean::Ciphertext`.
- `ShortintEngine`: `tfhe::shortint::Ciphertext`, reusing the same netlist.

This keeps the S-box, MixColumns, key schedule, and CTR loop in sync across
plaintext and FHE execution.

### State Operations

- `sbox`: direct Boyar-Peralta netlist; bottom XNOR gates fold in AES affine
  constant `0x63`.
- `shift_rows`: pure byte reindexing; no gates.
- `xtime`: multiply by 2 in GF(2^8) with the `0x1B` reduction.
- `mix_columns`: standard MDS column transform built from `xtime` and XOR.
- `expand_key`: AES-128 key schedule; SubWord S-boxes run homomorphically
  because the key is encrypted.
- `counter_block`: 128-bit counter input; current code starts at counter 0.

### CTR Decryption

For counter `ctr`, evaluate `AES_K(counter_block(ctr))` and XOR the resulting
keystream bits with public symmetric ciphertext bits. Public-bit XOR is:

```rust
if c_bit { sk.not(&kbit) } else { kbit }
```

### Tests

- `sbox_matches_table`: all 256 S-box inputs.
- `aes_kat_fips197`: FIPS-197 known-answer vector.
- `fhe_sbox_matches_plain`: Boolean FHE S-box vs plaintext.
- `fhe_keystream_matches_plain`: ignored slow end-to-end CTR check.

## Rasta-525-5

Code:

- Boolean: `src/cipher/boolean/rasta.rs`
- Shortint: `src/cipher/shortint/rasta.rs`
- BFV mismatch demo: `src/cipher/bfv/rasta.rs`

### Variant

| Item | Value |
|---|---|
| State | 525 bits |
| Rounds | 5 |
| Key | 525 bits |
| Block | 525 keystream bits |

### Block Function

```text
state = encrypted key

for r in 0..5:
    state = affine_layer(A_r, c_r, state)
    state = chi_layer(state)

state = affine_layer(A_5, c_5, state)
state = state XOR encrypted key
```

The final state is the keystream block.

### Chi Layer

```text
y_i = x_i XOR ((NOT x_{i+1}) AND x_{i+2})
```

The code computes into a fresh vector so reads are from the old state. Indices
wrap modulo `n`.

### Affine Layer

For each output row:

```text
out_i = XOR over state[j] where A[i][j] = 1, then XOR c[i]
```

The matrix is row-major. If a row has no set bits, the implementation returns
`trivial_encrypt(c[i])`, keeping ciphertext shape valid.

### Public Layers and PRG

`generate_round_layers(nonce, block_counter)` creates `R + 1` matrices and
constants in interleaved order:

```text
matrix 0, constant 0, matrix 1, constant 1, ..., matrix R, constant R
```

The local implementation uses `StdRng` seeded from:

```text
nonce[0] || nonce[1] || block_counter
```

Both the plaintext and FHE paths call the same layer generator.

### Block Boundaries

Rasta always computes a full 525-bit block. For a partial final block, unused
keystream bits are discarded.

### Shortint Rasta

Shortint reuses the plaintext Rasta scaffolding and changes only the FHE
primitives:

| Step | Shortint implementation |
|---|---|
| Affine XOR fold | `unchecked_add` into carry slot; clean only when needed |
| `(NOT a) AND b` | fused bivariate LUT |
| Whitening/XOR | leveled add |

Parameter set:

```text
PARAM_MESSAGE_2_CARRY_2_KS_PBS
```

The larger message/carry space lets long affine XOR rows accumulate before a
cleanup PBS.

### Tests

- `plaintext_roundtrip`
- `fhe_matches_plaintext_keystream`

