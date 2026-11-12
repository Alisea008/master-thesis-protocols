# psi-pmi

Implementazione Rust del protocollo PSI/PMI con Bloom filter, transciphering e TEE
(Algorithm 1 + Algorithm 2 del PDF allegato), sopra il framework
[Transieve](https://github.com/RRas/Transieve) per il transciphering BFV+Pasta-3.

## Layout

- `src/types.rs`   — `Sid`, `Token`
- `src/net.rs`     — canali FSC simulati (`Network`, `DirectChannel`)
- `src/sig.rs`     — Ed25519 (FSIG)
- `src/bloom.rs`   — Bloom filter e famiglie di hash `H_0..H_{U-1}`
- `src/sim.rs`     — SIM: ChaCha20 (per D_1') + stream cipher Pasta (per i filtri)
- `src/pasta_fhe.rs` — adapter `PastaBfv` di Transieve (keygen/transcipher/AND/decrypt)
- `src/ot.rs`      — Algorithm 1 (1-out-of-U OT su Ristretto255)
- `src/ttp.rs`     — TTP (firma σ, T)
- `src/tee.rs`     — TEE_1 simulato (stato persistente, anti-replay, anti-rollback)
- `src/psi.rs`     — Orchestrazione end-to-end (Algorithm 2)

## Requisiti

- Rust stable, edition 2021, x86_64
- Transieve clonato come sibling directory: `../Transieve` (path dependency).

Se il path è diverso, modifica `Cargo.toml` → `[dependencies] transieve.path`.

## Build & test

```bash
cargo build --release
cargo test --release --test protocol        # test veloci (no FHE)
cargo test --release --test e2e_pasta       # end-to-end (FHE, lento)
