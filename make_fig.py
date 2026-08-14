# Headline figure: dumbbell chart of AI-agent mention rate vs full-block rate per language.
# Encodes gradient (position) + decomposition (short gaps = blocking tracks naming).
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
a = json.load(open(f"{D}/analysis_v3.json"))

NAME = {"eng_Latn": "English", "deu_Latn": "German", "fra_Latn": "French", "jpn_Jpan": "Japanese",
        "ind_Latn": "Indonesian", "tha_Thai": "Thai", "tur_Latn": "Turkish",
        "azj_Latn": "Azerbaijani", "vie_Latn": "Vietnamese", "sun_Latn": "Sundanese",
        "yor_Latn": "Yoruba", "uig_Arab": "Uyghur", "gle_Latn": "Irish", "swh_Latn": "Swahili"}
# Okabe-Ito, colorblind-safe
TIER_C = {"high": "#0072B2", "mid": "#E69F00", "low": "#009E73"}
TIER_LABEL = {"high": "High tier", "mid": "Mid tier", "low": "Low tier"}

langs = []
for tier in ["high", "mid", "low"]:
    ts = [(l, o) for l, o in a["per_lang"].items() if o["tier"] == tier]
    ts.sort(key=lambda x: x[1]["optout"], reverse=True)
    langs.extend(ts)

fig, ax = plt.subplots(figsize=(3.03, 2.85), dpi=300)
ys = list(range(len(langs), 0, -1))
for (l, o), y in zip(langs, ys):
    c = TIER_C[o["tier"]]
    lo, hi = o["ci"]
    ax.plot([lo, hi], [y, y], color=c, lw=0.8, alpha=0.35, solid_capstyle="round", zorder=1)
    ax.plot([o["optout"], o["names"]], [y, y], color=c, lw=1.4, zorder=2)
    ax.plot(o["names"], y, "o", mfc="white", mec=c, mew=1.3, ms=5, zorder=3)
    ax.plot(o["optout"], y, "o", color=c, ms=5, zorder=4)

ax.set_yticks(ys)
ax.set_yticklabels([NAME[l] for l, _ in langs], fontsize=7)
for tick, (l, o) in zip(ax.get_yticklabels(), langs):
    tick.set_color(TIER_C[o["tier"]])
ax.set_xlim(0, 0.55)
ax.set_ylim(0.3, len(langs) + 0.7)
ax.set_xlabel("Share of reachable domains", fontsize=7.5)
ax.tick_params(axis="x", labelsize=7)
ax.spines[["top", "right", "left"]].set_visible(False)
ax.tick_params(axis="y", length=0)
ax.xaxis.grid(True, color="#dddddd", lw=0.5, zorder=0)
ax.set_axisbelow(True)

from matplotlib.lines import Line2D
handles = [
    Line2D([], [], marker="o", color="#555555", ls="", ms=5, label="Blocks $\\geq$1 AI agent"),
    Line2D([], [], marker="o", mfc="white", mec="#555555", mew=1.3, ls="", ms=5,
           label="Names $\\geq$1 AI agent"),
]
leg = ax.legend(handles=handles, fontsize=6.5, loc="lower right", frameon=False,
                handletextpad=0.3, borderaxespad=0.2)
# tier separators
n_high, n_mid = 4, 5
ax.axhline(len(langs) - n_high + 0.5, color="#bbbbbb", lw=0.5, ls=":")
ax.axhline(len(langs) - n_high - n_mid + 0.5, color="#bbbbbb", lw=0.5, ls=":")

fig.tight_layout(pad=0.3)
out = os.path.join(os.path.dirname(D), "fig_gradient.pdf")
fig.savefig("fig_gradient.pdf")
print("saved")
