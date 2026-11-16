import json, re, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

with open("results/deniability.json") as fh:
    data = json.load(fh)

adv_re = re.compile(r"advantage=([\-\d\.]+)")

groups = {}
for r in data:
    key = (r["fp"], r["k"], r["f"])
    groups.setdefault(key, {}).setdefault(r["strategy"], []).append(
        (r["U"], float(adv_re.search(r["output"]).group(1)))
    )

for (fp, k, f), per_strat in groups.items():
    fig, ax = plt.subplots(figsize=(6, 4))
    for strat, pts in per_strat.items():
        pts = sorted(pts)
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker="o", label=strat)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("U (number of filters)")
    ax.set_ylabel("advantage")
    ax.set_title(f"fp={fp}, k={k}, u2_factor={f}")
    ax.axhline(0, color="k", lw=0.5, ls="--")
    ax.legend()
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    out = f"results/adv_vs_U_fp{fp}_k{k}_f{f}.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Saved {out}")