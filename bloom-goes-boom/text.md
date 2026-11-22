# Available Binaries and Execution Guide

Overview of the **three binaries** (tests) available in the project, what each one does, and the exact commands to run them on Windows.

### Prerequisites
1. The project has been compiled with `cargo build --release` (and `libfftw3-3.dll` has been copied to `target\release\` via `build.rs`). **Re-run `cargo build --release` after any change to `src\` or `lib.rs`.**
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

**Overview:** Evaluates the effectiveness of the countermeasure using **$U$ filters** and a secret index **$\sigma$** (sigma). The data owner builds $U$ filters with different hash families over the same victim set, and the STTP picks $\sigma$ uniformly at random. The attacker only observes $BF_\sigma$ and tries one of three strategies.

**Smoke test (quick verification):**

```cmd
target\release\plausible_deniability.exe --universe-size=22 --universe-client-factor=2 --max-set-size=4 --client-set-size=4 --false-positives=10 --trials=100 --num-filters=4 --strategy=single_u -v
```

*Expected output:* Prints a final line formatted as `U=4 strategy=single_u |X1|=... advantage=0.25 ... \\ % ...`. The advantage drops significantly compared to `U=1`.

**Available strategies (`--strategy` flag):**

* `single_u`: The attacker crafts the attack set for family 0 only and hopes that $\sigma = 0$ (probability $1/U$).
* `split_union`: The attacker computes one attack set per family, each with budget $k/U$, and uses the union of all of them as $X_1$.
* `same_target`: The attacker fixes the target $t^*$ (chosen on family 0) and builds $X_1$ from the elements $y$ that snipe $t^*$ **simultaneously in all $U$ families** (joint candidates), truncated to the budget $k$. If $t^*$ is in the victim set, these $y$ hit $BF_\sigma$ whatever $\sigma$ is. The number of joint candidates shrinks quickly as $U$ grows; if none exist, $X_1$ is empty and the advantage is 0. The final line reports `|X1|`, so you can see when this happens.

**Joint-candidate count (`--joint-count`):**

Prints how many elements $y$ snipe $t^*$ in all of the first $j$ families, for $j = 1 \dots U$, then exits (no trials are run):

```cmd
target\release\plausible_deniability.exe --universe-size=26 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --num-filters=16 --joint-count -v
```

*Expected output:* One line per $j$, e.g. `U=1 joint_candidates=...` up to `U=16 joint_candidates=...`. This explains the behaviour of `same_target`: when the count reaches 0, the strategy has no advantage.

**Full benchmark (sweep over $U$):**

```cmd
target\release\plausible_deniability.exe --universe-size=32 --universe-client-factor=2 --max-set-size=8 --client-set-size=8 --false-positives=10 --trials=1000000 --num-filters=16 --strategy=same_target -v
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

:: 3. Run the countermeasure experiment (all three strategies for each U,
::    plus a --joint-count pass) and save results to JSON
python -u run_plausible_deniability.py > ..\results\deniability.txt 2>&1

:: 4. Generate plots (Advantage vs U) in experiments/results/
python plot_results.py
```

*Performance tip:* If the scripts take too long to complete (`universe_size=32` is computationally heavy), open the `.py` files and set `UNIVERSE_SIZE = 26` and `TRIALS = 100000`. This will still capture the expected trend (advantage decreasing as $U$ increases) within a few minutes. The `--joint-count` pass is run once per configuration with `U = max(U_VALUES)`.
