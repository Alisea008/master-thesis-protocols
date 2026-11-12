## Protocollo alternativo (senza TEE)

Implementato in `psi::run_e2e_pasta_alt`. Segue Algorithm "Alternative":

| Fase | Codice |
|------|--------|
| Setup FHE + pack_key per DO | `run_e2e_pasta_alt` (setup) |
| DO_a cifra i filtri + DO_1 cifra A_u | `pasta_sim::enc` + `pasta_sim::enc_indices` |
| Due OT con stesso σ (filtri + indici) | `ot_phase{1,2,3,4}` + `ot_phase2_with_sigma` |
| S_a transciphers M^a_σ → E^(a) | `PastaFhe::transcipher` |
| S_1 transciphers M^A_σ → E_A | `PastaFhe::transcipher` |
| S_1 calcola AND slot-wise | `PastaFhe::eval_and_all` |
| S_1 applica CMUX (R = B[A_σ]) | **simulato** — vedi sotto |
| DO_1 riceve R e decide | `r_bits[j*h+l]` + AND su `l` |

### Gap di simulazione (CMUX)

Transieve non espone PBS/CMUX di TFHE. La simulazione in
`run_e2e_pasta_alt`:

1. **S_1 ha accesso alla `sk`** del contesto FHE → decifra E_B ed E_A.
   In produzione S_1 avrebbe solo `pk`+`evk` e userebbe PBS su `E_A`.
2. **R è in chiaro** nel ritorno da S_1 a DO_1. In produzione `E_R` sarebbe
   un ciphertext FHE che DO_1 decifra con `sk`.
3. **nessun controllo anti-replay** su `sid` (il TEE non esiste in questo
   protocollo). In produzione la freshness è garantita dal meccanismo
   di sessione (σ fresca per ogni esecuzione).

Queste gap **non alterano il flusso del protocollo né l'output funzionale**,
ma **non sono adatte alla produzione**: il test end-to-end verifica solo la
correttezza funzionale (intersezione trovata = intersezione attesa, FP/FN=0).

### Confronto con Algorithm 1

| Aspetto | Alg. 1 (`run_e2e_pasta`) | Alternativa (`run_e2e_pasta_alt`) |
|---------|--------------------------|-----------------------------------|
| TEE | sì (in DO_1) | no |
| sk | TEE | DO_1 (in produzione) / S_1 (simulato) |
| Membership test | in chiaro nel TEE | CMUX FHE (simulato) |
| Dati extra via OT | nessuno | matrice A_u cifrata |
| Output a DO_1 | `(x, ρ_x)` | bit `R[j,l]` |
| Costo FHE | transcipher + AND | transcipher + AND + CMUX |