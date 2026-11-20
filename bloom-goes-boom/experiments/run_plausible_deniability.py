import subprocess, json, os

EXE = "../target/release/plausible_deniability"
TRIALS = 1_000_000
U_VALUES = [1, 2, 4, 8, 16]
STRATEGIES = ["single_u", "union", "same_target"]

# (false_positives, log2_k, universe_client_factor) — casi facili del paper
CONFIGS = [(10, 8, 2), (20, 8, 2), (10, 12, 2)]

UNIVERSE_SIZE = 26

os.makedirs("results", exist_ok=True)

results = []
for fp, k, f in CONFIGS:
    for U in U_VALUES:
        for strat in STRATEGIES:
            cmd = [
                EXE,
                f"--universe-size={UNIVERSE_SIZE}",
                f"--universe-client-factor={f}",
                f"--client-set-size={k}",
                f"--max-set-size={k}",
                f"--false-positives={fp}",
                f"--trials={TRIALS}",
                f"--num-filters={U}",
                f"--strategy={strat}",
                "-v",
            ]
            print(f"% {' '.join(cmd)}")
            out = subprocess.check_output(cmd, text=True)
            print(out.strip())
            results.append({
                "fp": fp, "k": k, "f": f,
                "U": U, "strategy": strat, "output": out,
            })

with open("results/deniability.json", "w") as fh:
    json.dump(results, fh, indent=2)
print("Saved results/deniability.json")