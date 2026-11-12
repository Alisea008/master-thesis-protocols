
# NOTES

## Cosa espone Transieve
- `transieve::cipher::bfv::pasta::{PastaBfv, PASTA3, PastaParams, P, encrypt, decrypt}`
- `PastaBfv::{new_secure, new_with_sop, pack_key, transcipher_recover_blocks,
  evaluate_sop, decrypt_bits, decrypt_lane_bits}`
- `transieve::circuit::ThresholdCircuit::new(n, t)`

## Cosa NON è esposto
- Serializzazione di `PastaBfv` (sk, ek, rk) → TEE resta in-process.

## Scelte
- Backend BFV + Pasta-3 (packed, AND slot-wise). TFHE-Boolean scartato.
- Test con degree 8192 (veloce, non 128-bit safe).
- U filtri per DO, un ciphertext SIM per H_u, nonce = `[u, 0]`.
- σ comune alle n istanze OT, passato a `ot_phase2_with_sigma`.
- Tag OT: 48 bit. `H_ct` = SHAKE256. `H_tag` con domain separation.
- AND: `ThresholdCircuit::new(n, n)` su Pasta (albero interno, ⌈log₂ n⌉).
- k_sym (32 B): ChaCha20 per D_1' e seed SHAKE256 per `derive_pasta_key` (2t
  field element mod 65537). Stessa derivazione in `pack_key` e `pasta_sim::enc`.

## Mapping PDF → codice
| PDF                    | Codice                                        |
|------------------------|-----------------------------------------------|
| Alg.1 Fase 1 (DO)      | `ot::ot_phase1`                               |
| Alg.1 Fase 2 (TTP)     | `ot::ot_phase2_with_sigma`                    |
| Alg.1 Fase 3 (DO)      | `ot::ot_phase3`                               |
| Alg.1 Fase 4 (S)       | `ot::ot_phase4`                               |
| Alg.2 Setup (1–4)      | `psi::run_e2e_pasta` + `Tee1Pasta::submit_host_input` |
| Alg.2 Aggregation (6–7)| `PastaFhe::transcipher` + `eval_and_all`      |
| Alg.2 Delivery (8)     | `Tee1Pasta::verify_eval`                      |
| Alg.2 Decrypt (9–10)   | `PastaFhe::decrypt_bits` + `Tee1Pasta::finish`|