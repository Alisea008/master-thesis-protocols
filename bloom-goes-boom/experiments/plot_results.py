import json, re, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

with open("results/deniability.json") as fh:
    data = json.load(fh)

adv_re = re.compile(r"advantage=([\-\d\.]+)")
se_re = re.compile(r"\bse=([\d\.]+)")

groups = {}
for r in data:
    key = (r["fp"], r["k"], r["f"])
    groups.setdefault(key, {}).setdefault(r["strategy"], []).append(
        (r["U"],
         float(adv_re.search(r["output"]).group(1)),
         float(se_re.search(r["output"]).group(1)))
    )

for (fp, k, f), per_strat in groups.items():
    fig, ax = plt.subplots(figsize=(6, 4))
    for strat, pts in per_strat.items():
        pts = sorted(pts)
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        es = [1.96 * p[2] for p in pts]          # 95% CI
        ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=strat)

    # theoretical prediction A_1 / U, with A_1 taken from single_u at U = 1
    base = {p[0]: p[1] for p in per_strat.get("single_u", [])}
if 1 in base:
    us = sorted({p[0] for pts in per_strat.values() for p in pts})
    ax.plot(us, [base[1] / u for u in us], "k--", lw=1, label=r"$A_1/U$")    ax.set_xscale("log", base=2)
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