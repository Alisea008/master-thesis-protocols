Ecco un recap completo dei **tre binari** (test) che hai a disposizione, cosa fa ciascuno, e i comandi esatti per farli girare su Windows.

Assumo che tu abbia già:
1. Compilato con successo con `cargo build --release` (e che la DLL `libfftw3-3.dll` sia stata copiata in `target\release\` grazie al `build.rs`).
2. Le cartelle `experiments\` e `results\` presenti.

---

## 1. `attack_single.exe` — L'attacco base (Single Bloom Filter)

**Cosa fa:** È l'attacco classico del paper. Costruisce **un solo** Bloom filter, calcola l'attack set tramite la funzione `snipe`, e misura il vantaggio dell'attaccante nell'indovinare se un certo target è nel set della vittima.

**Come testarlo (Smoke test veloce, pochi secondi):**
Apri `cmd` nella root del progetto e lancia:
```cmd
target\release\attack_single.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 -v
```
*Cosa aspettarti:* Stampa i parametri del filtro, il numero di thread, e alla fine una riga con il vantaggio (es. `0.85000 \\ % [...]`).

**Come lanciare i test veri (da ore):**
```cmd
target\release\attack_single.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 -v
```

---

## 2. `attack.exe` — L'attacco Doppio (Dual Bloom Filter)

**Cosa fa:** Simula un protocollo in cui vengono usati **due** Bloom filter con famiglie di hash diverse. L'attaccante cerca di trovare un "target comune" che funzioni per entrambi i filtri (con un massimo di tentativi, altrimenti fa fallback su target individuali). Misura il vantaggio separatamente per BF1 e BF2.

**Come testarlo (Smoke test veloce):**
```cmd
target\release\attack.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 -v
```
*Cosa aspettarti:* Stampa due righe finali: `BF1 Advantage: ...` e `BF2 Advantage: ...`.

**Come lanciare i test veri:**
```cmd
target\release\attack.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 -v
```

---

## 3. `plausible_deniability.exe` — L'esperimento per la tua Tesi (U filtri + σ)

**Cosa fa:** È il test che hai richiesto per dimostrare l'efficacia della contromisura con **U filtri** e l'indice segreto **σ** (sigma). Il data owner costruisce `U` filtri con hash diversi. Lo STTP ne sceglie uno a caso. L'attaccante proverà tre strategie diverse per capire quanto vantaggio ottiene.

**Come testarlo (Smoke test veloce):**
```cmd
target\release\plausible_deniability.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 --num-filters=4 --strategy=single_u -v
```
*Cosa aspettarti:* Alla fine stamperà una riga tipo `U=4 strategy=single_u advantage=0.25 \\ % ...`. Se l'esperimento funziona, noterai che l'advantage scende drasticamente rispetto a `U=1`.

**Le 3 strategie (flag `--strategy`):**
*   `single_u`: l'attaccante scommette su un solo filtro (sigma).
*   `union`: l'attaccante unisce gli attacchi per tutti i filtri.
*   `same_target`: l'attaccante attacca lo stesso elemento (equivalente a metterlo nel proprio set, quindi vantaggio = 0).

**Come lanciare i test veri (sweep su U):**
```cmd
target\release\plausible_deniability.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 --num-filters=16 --strategy=single_u -v
```

---

## 🐍 Automazione con Python (per i grafici della tesi)

Per non dover lanciare a mano decine di comandi, usa gli script Python. **Attenzione**: su Windows devi usare `python` (non `python3`) e assicurarti che gli script puntino ai file `.exe` con il percorso corretto (es. `r"..\target\release\attack_single.exe"`).

Apri `cmd`, entra nella cartella `experiments` ed esegui:

```cmd
cd experiments

:: 1. Testa l'attacco base
python -u run_attack_single.py > ..\results\attack_single.txt 2>&1

:: 2. Testa l'attacco doppio (con la ricerca del target comune)
python -u run_experiments.py > ..\results\attack_dual.txt 2>&1

:: 3. Testa la contromisura (U filtri) e salva i risultati in JSON
python -u run_plausible_deniability.py > ..\results\deniability.txt 2>&1

:: 4. Genera i grafici (Advantage vs U) in experiments/results/
python plot_results.py
```

Se gli script ci mettono troppo (perché `universe_size=32` è pesante), apri i file `.py` e cambia `universe_size = 26` e `trials = 100000`. I grafici mostreranno comunque la tendenza corretta (l'Advantage che crolla all'aumentare di U) in pochi minuti.

---
