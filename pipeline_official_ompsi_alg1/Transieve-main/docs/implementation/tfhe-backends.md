# TFHE Backend Implementation Notes

Code:

- Boolean SOP: `src/backend/boolean.rs`
- Shortint SOP: `src/backend/shortint.rs`
- Boolean cipher trait/dispatch: `src/cipher/mod.rs`
- Shortint cipher trait/dispatch: `src/cipher/shortint/mod.rs`

## Boolean Backend

Type:

```rust
pub type EncBit = tfhe::boolean::Ciphertext;
```

Keys:

```rust
pub struct Keys {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
}
```

Gate behavior:

| Operation | API | Cost shape |
|---|---|---|
| AND | `sk.and` | one Boolean gate/PBS |
| OR | `sk.or` | one Boolean gate/PBS |
| XOR | `sk.xor` | one Boolean gate/PBS |
| XNOR | `sk.xnor` | one Boolean gate/PBS |
| NOT | `sk.not` | cheap unary op |
| Public constant | `sk.trivial_encrypt` | trivial ciphertext |

Used for:

- direct threshold SOP baseline in `fhe::run_baseline`
- Boolean transciphering ciphers: Kreyvium, Grain-128a, AES-128, Rasta

## Shortint Backend

Type:

```rust
pub type EncBitShortint = tfhe::shortint::Ciphertext;
```

Each ciphertext still represents one encrypted bit. The bit lives in the
least-significant message slot; the carry slot is used as headroom for leveled
XOR accumulation.

Keys:

```rust
pub struct ShortintKeys {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
    pub xor_lut: LookupTableOwned,
    pub parameters: ClassicPBSParameters,
}
```

The `xor_lut` maps an accumulated value back to `x & 1`.

### Primitive Costs

| Operation | Implementation |
|---|---|
| XOR | `unchecked_add` into message/carry space |
| Public-bit XOR | scalar add |
| Clean to bit | apply `x & 1` LUT |
| AND | `sk.bitand` or bivariate LUT |
| OR | `sk.bitor` or arithmetic equivalent |

The helper logic keeps track of whether another leveled add is possible. If not,
it cleans before adding.

### Parameter Sets

Each shortint cipher selects parameters through
`TranscipherDecryptShortint::PARAMETERS`.

| Cipher | Parameter set | Implementation reason |
|---|---|---|
| Rasta-shortint | `PARAM_MESSAGE_2_CARRY_2_KS_PBS` | long affine XOR rows need carry headroom |
| AES-shortint | `PARAM_MESSAGE_1_CARRY_2_KS_PBS` | short XOR chains around S-boxes |

## Backend Dispatch

Parsing produces a backend-tagged cipher spec:

```rust
pub enum CipherSpec {
    Boolean(Cipher),
    Shortint(CipherShortint),
    Bfv(CipherBfv),
}
```

Rules:

- bare `rasta` means Boolean Rasta
- `rasta-shortint`, `shortint-rasta`, or `rasta-si` selects shortint
- `pasta` selects the BFV cipher when built with `--features bfv`

Pipeline split:

- Boolean transciphering reuses Boolean baseline keys.
- Shortint transciphering creates a shortint keyset under the cipher's selected
  parameter set.
- Shortint full TPSI evaluates the threshold SOP in `src/backend/shortint.rs`.

## Implementation Rules

- Do not mix Boolean and shortint ciphertexts.
- Treat public-bit XOR as NOT/no-op or scalar add; do not encrypt public bits
  unless the downstream API requires a ciphertext.
- Clean shortint accumulators before non-linear gates.
- Keep plaintext references for every cipher path and compare FHE outputs to
  those references in tests.
