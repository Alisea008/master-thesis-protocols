
# Available Binaries and Execution Guide

Overview of the **three binaries** (tests) available in the project, what each one does, and the exact commands to run them on Windows.

### Prerequisites
1. The project has been compiled with `cargo build --release` (and `libfftw3-3.dll` has been copied to `target\release\` via `build.rs`).
2. The `experiments\` and `results\` directories exist in the project root.

---

## 1. `attack_single.exe` — Baseline Attack (Single Bloom Filter)

**Overview:** Implements the standard attack from the reference paper. It builds a **single** Bloom filter, computes the attack set via the `snipe` function, and measures the attacker's advantage in guessing whether a specific target belongs to the victim's set.

**Smoke test (quick verification, takes a few seconds):**
Open `cmd` in the project root and run:
```cmd
target\release\attack_single.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 -v

```

*Expected output:* Prints the filter parameters, the thread count, and a final line reporting the advantage (e.g., `0.85000 \\ % [...]`).

**Full benchmark (multi-hour run):**

```cmd
target\release\attack_single.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 -v

```

---

## 2. `attack.exe` — Dual Attack (Dual Bloom Filter)

**Overview:** Simulates a protocol using **two** Bloom filters with distinct hash families. The attacker attempts to find a "common target" that works across both filters (up to a maximum number of attempts, falling back to individual targets otherwise). Measures the advantage separately for BF1 and BF2.

**Smoke test (quick verification):**

```cmd
target\release\attack.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 -v

```

*Expected output:* Prints two final lines: `BF1 Advantage: ...` and `BF2 Advantage: ...`.

**Full benchmark:**

```cmd
target\release\attack.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 -v

```

---

## 3. `plausible_deniability.exe` — Countermeasure Experiment ($U$ Filters + $\sigma$)

**Overview:** Evaluates the effectiveness of the countermeasure using **$U$ filters** and a secret index **$\sigma$** (sigma). The data owner builds $U$ filters with different hash functions, and the STTP randomly selects one. The attacker tests three distinct strategies to evaluate the resulting advantage.

**Smoke test (quick verification):**

```cmd
target\release\plausible_deniability.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 --num-filters=4 --strategy=single_u -v

```

*Expected output:* Prints a final line formatted as `U=4 strategy=single_u advantage=0.25 \\ % ...`. The advantage drops significantly compared to `U=1`.

**Available strategies (`--strategy` flag):**

* `single_u`: The attacker guesses a single filter ($\sigma$).
* `union`: The attacker takes the union of attacks across all filters.
* `same_target`: ... (equivalent to including it in their own set; the advantage is ≈ 1 − ε for every U, since this is the inherent PSI leakage that σ does not protect).

**Full benchmark (sweep over $U$):**

```cmd
target\release\plausible_deniability.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 --num-filters=16 --strategy=single_u -v

```

---

## Python Automation (Plotting Results)

To avoid running dozens of commands manually, use the provided Python scripts. **Note:** On Windows, invoke `python` (not `python3`) and verify that the scripts point to the `.exe` binaries using the proper relative path (e.g., `r"..\target\release\attack_single.exe"`).

Open `cmd`, navigate to the `experiments` directory, and run:

```cmd
cd experiments

:: 1. Run the baseline attack
python -u run_attack_single.py > ..\results\attack_single.txt 2>&1

:: 2. Run the dual attack (with common target search)
python -u run_experiments.py > ..\results\attack_dual.txt 2>&1

:: 3. Run the countermeasure experiment (U filters) and save results to JSON
python -u run_plausible_deniability.py > ..\results\deniability.txt 2>&1

:: 4. Generate plots (Advantage vs U) in experiments/results/
python plot_results.py

```

*Performance tip:* If the scripts take too long to complete (`universe_size=32` is computationally heavy), open the `.py` files and set `universe_size = 26` and `trials = 100000`. This will still capture the expected trend (advantage decreasing as $U$ increases) within a few minutes.

```

```
