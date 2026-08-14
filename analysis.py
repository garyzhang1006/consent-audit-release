# Analysis: fixes Allow-directive parse gap, adds language-cluster
# exact permutation tests (the correct unit of analysis), reachability failure
# breakdown, and every statistic cited in the paper. Single source of truth.
import json, gzip, random, math, os, re
from collections import Counter, defaultdict
from itertools import combinations

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SEED = 20260811
AI_AGENTS = ["gptbot", "chatgpt-user", "ccbot", "google-extended", "claudebot", "anthropic-ai",
             "claude-web", "perplexitybot", "bytespider", "cohere-ai", "applebot-extended",
             "meta-externalagent", "omgilibot", "diffbot", "ai2bot"]
LANGS = {
    "eng_Latn": "high", "deu_Latn": "high", "jpn_Jpan": "high", "fra_Latn": "high",
    "ind_Latn": "mid", "tur_Latn": "mid", "vie_Latn": "mid", "tha_Thai": "mid", "azj_Latn": "mid",
    "swh_Latn": "low", "sun_Latn": "low", "yor_Latn": "low", "uig_Arab": "low", "gle_Latn": "low",
}
N_HEAD = 175

def parse_robots(body):
    """v3: records Allow: directives too, so agents mentioned only in Allow rules count as named."""
    out = {}
    cur_agents, rules_open = [], False
    for raw in body.splitlines()[:4000]:
        line = raw.split("#")[0].strip()
        if not line: continue
        m = re.match(r"(?i)user-agent\s*:\s*(.+)", line)
        if m:
            if rules_open: cur_agents = []
            cur_agents.append(m.group(1).strip().lower()); rules_open = False
            continue
        m = re.match(r"(?i)disallow\s*:\s*(.*)", line)
        if m and cur_agents:
            rules_open = True
            path = m.group(1).strip()
            for a in cur_agents:
                key = "*" if a == "*" else a
                if path == "/":
                    out[key] = "full"
                elif path and out.get(key) != "full":
                    out[key] = "partial"
                elif not path and key not in out:
                    out[key] = "allow"
            continue
        m = re.match(r"(?i)allow\s*:\s*(.*)", line)
        if m and cur_agents:
            rules_open = True
            for a in cur_agents:
                key = "*" if a == "*" else a
                if key not in out:
                    out[key] = "allow"
    return out

def blocks_ai(rules):
    return bool(rules) and any(rules.get(a) == "full" for a in AI_AGENTS)

def names_ai(rules):
    return bool(rules) and any(a in rules for a in AI_AGENTS)

def classify_err(r):
    if r.get("status", -1) != -1:
        s = r["status"]
        return f"http_{s//100}xx"
    e = r.get("error", "")
    if e.startswith("HTTPError"):
        m = re.search(r"HTTP Error (\d)", e)
        return f"http_{m.group(1)}xx" if m else "http_other"
    if any(s in e for s in ("Name or service not known", "No address associated",
                            "Temporary failure in name resolution", "nodename nor servname",
                            "getaddrinfo failed")):
        return "dns"
    if "timed out" in e or "TimeoutError" in e:
        return "timeout"
    if any(s in e for s in ("Connection refused", "Connection reset", "ConnectionReset")):
        return "conn"
    if "SSL" in e or "certificate" in e.lower():
        return "ssl"
    return "other"

# ---- load, re-parse every archived body with the fixed parser ----
lang_data = {}
for lang, tier in LANGS.items():
    rob = json.load(gzip.open(f"{D}/robots_{lang}.json.gz", "rt", encoding="utf-8"))
    census = json.load(open(f"{D}/census_{lang}.json"))
    res = rob["results"]
    # Archived bodies are truncated to 20k chars, but the archived ai_rules were parsed
    # from the full body at fetch time. Block status therefore comes from the original
    # parse; the re-parse (with the Allow: fix) only ADDS agents that appeared solely in
    # Allow rules. Merge with the original taking precedence per agent.
    for r in res:
        if r.get("body") is not None:
            reparsed = parse_robots(r["body"])
            orig = r.get("ai_rules") or {}
            r["ai_rules"] = {**reparsed, **orig}
    reach = [r for r in res if r.get("status") == 200]
    head_set = set(rob["sampled"][:N_HEAD])
    lang_data[lang] = dict(tier=tier, res=res, reach=reach, head_set=head_set,
                           dm=census["doc_mass"], tm=census["tok_mass"],
                           capped=census["capped"], docs=census["docs_streamed"])

# ---- per-language stats ----
per_lang = {}
for lang, ld in lang_data.items():
    reach, dm, tm = ld["reach"], ld["dm"], ld["tm"]
    n = len(reach)
    block_flags = [1 if blocks_ai(r["ai_rules"]) else 0 for r in reach]
    name_flags = [1 if names_ai(r["ai_rules"]) else 0 for r in reach]
    rng = random.Random(SEED + 17)
    boots = []
    for _ in range(2000):
        bs = [block_flags[rng.randrange(n)] for _ in range(n)]
        boots.append(sum(bs) / n)
    boots.sort()
    ci = [boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]]
    reach_mass = sum(dm.get(r["domain"], 0) for r in reach)
    opt_mass = sum(dm.get(r["domain"], 0) for r in reach if blocks_ai(r["ai_rules"]))
    fails = Counter(classify_err(r) for r in ld["res"] if r.get("status") != 200)
    per_lang[lang] = {
        "tier": ld["tier"], "n_sampled": len(ld["res"]), "n_reach": n,
        "reach_rate": n / len(ld["res"]),
        "optout": sum(block_flags) / n, "ci": ci,
        "names": sum(name_flags) / n,
        "cond_block": (sum(block_flags[i] for i in range(n) if name_flags[i]) /
                       max(1, sum(name_flags))),
        "n_named": sum(name_flags),
        "mass_wt": opt_mass / max(1, reach_mass),
        "wildcard": sum(1 for r in reach if r["ai_rules"].get("*") == "full") / n,
        "fail_breakdown": dict(fails), "capped": ld["capped"],
    }

# ---- pooled tier rates (descriptive) + domain-pooled perm (descriptive only) ----
def pool(flag_fn, subset_fn=lambda r, ld: True):
    p = defaultdict(list)
    for lang, ld in lang_data.items():
        for r in ld["reach"]:
            if subset_fn(r, ld):
                v = flag_fn(r)
                if v is not None:
                    p[ld["tier"]].append(v)
    return p

def perm_p(a, b, n=100000):
    rng = random.Random(SEED)
    obs = sum(a) / len(a) - sum(b) / len(b)
    comb = a + b; na = len(a); cnt = 0
    for _ in range(n):
        rng.shuffle(comb)
        d = sum(comb[:na]) / na - sum(comb[na:]) / (len(comb) - na)
        if abs(d) >= abs(obs): cnt += 1
    return obs, cnt / n

# ---- language-cluster exact permutation: the primary test ----
HIGH = [l for l, t in LANGS.items() if t == "high"]
LOW = [l for l, t in LANGS.items() if t == "low"]
MID = [l for l, t in LANGS.items() if t == "mid"]

def cluster_exact(langs_a, langs_b, rate_of, weight_of):
    """Exact permutation over all C(len(a)+len(b), len(a)) splits.
    Returns (obs_unw, p_unw, obs_w, p_w)."""
    all_l = langs_a + langs_b
    na = len(langs_a)
    def stat(sel):
        rest = [l for l in all_l if l not in sel]
        unw = sum(rate_of(l) for l in sel) / len(sel) - sum(rate_of(l) for l in rest) / len(rest)
        wa = sum(weight_of(l) for l in sel); wb = sum(weight_of(l) for l in rest)
        w = (sum(rate_of(l) * weight_of(l) for l in sel) / wa -
             sum(rate_of(l) * weight_of(l) for l in rest) / wb)
        return unw, w
    obs_u, obs_w = stat(tuple(langs_a))
    cu = cw = tot = 0
    for sel in combinations(all_l, na):
        u, w = stat(sel)
        tot += 1
        if abs(u) >= abs(obs_u) - 1e-12: cu += 1
        if abs(w) >= abs(obs_w) - 1e-12: cw += 1
    return {"gap_unweighted": obs_u, "p_unweighted": cu / tot,
            "gap_weighted": obs_w, "p_weighted": cw / tot, "n_splits": tot}

def mk_rate(field, subset=None):
    def rate_of(l):
        ld = lang_data[l]
        rs = ld["reach"] if subset is None else [r for r in ld["reach"] if subset(r, ld)]
        if field == "optout":
            flags = [blocks_ai(r["ai_rules"]) for r in rs]
        elif field == "names":
            flags = [names_ai(r["ai_rules"]) for r in rs]
        elif field == "cond":
            named = [r for r in rs if names_ai(r["ai_rules"])]
            flags = [blocks_ai(r["ai_rules"]) for r in named]
        return sum(flags) / max(1, len(flags))
    def weight_of(l):
        ld = lang_data[l]
        rs = ld["reach"] if subset is None else [r for r in ld["reach"] if subset(r, ld)]
        if field == "cond":
            rs = [r for r in rs if names_ai(r["ai_rules"])]
        return len(rs)
    return rate_of, weight_of

in_head = lambda r, ld: r["domain"] in ld["head_set"]
in_tail = lambda r, ld: r["domain"] not in ld["head_set"]

cluster = {}
for name, field, subset in [
    ("optout_all", "optout", None), ("optout_head", "optout", in_head),
    ("optout_tail", "optout", in_tail), ("names_all", "names", None),
    ("cond_all", "cond", None),
]:
    ro, wo = mk_rate(field, subset)
    cluster[f"high_vs_low_{name}"] = cluster_exact(HIGH, LOW, ro, wo)
    cluster[f"high_vs_rest_{name}"] = cluster_exact(HIGH, MID + LOW, ro, wo)
ro, wo = mk_rate("optout", None)
cluster["mid_vs_low_optout"] = cluster_exact(MID, LOW, ro, wo)

# reach cluster test
reach_rate = lambda l: per_lang[l]["reach_rate"]
reach_w = lambda l: per_lang[l]["n_sampled"]
cluster["high_vs_low_reach"] = cluster_exact(HIGH, LOW, reach_rate, reach_w)

# ---- domain-pooled descriptive tests ----
pooled = {}
bp = pool(lambda r: 1 if blocks_ai(r["ai_rules"]) else 0)
np_ = pool(lambda r: 1 if names_ai(r["ai_rules"]) else 0)
cp = pool(lambda r: (1 if blocks_ai(r["ai_rules"]) else 0) if names_ai(r["ai_rules"]) else None)
hp = pool(lambda r: 1 if blocks_ai(r["ai_rules"]) else 0, in_head)
tp = pool(lambda r: 1 if blocks_ai(r["ai_rules"]) else 0, in_tail)
for name, p in [("optout", bp), ("names", np_), ("cond", cp), ("head", hp), ("tail", tp)]:
    obs, pv = perm_p(list(p["high"]), list(p["low"]))
    obs_ml, pv_ml = perm_p(list(p["mid"]), list(p["low"]))
    pooled[name] = {t: {"rate": sum(v) / len(v), "n": len(v)} for t, v in p.items()}
    pooled[name]["high_low"] = {"gap": obs, "perm_p": pv}
    pooled[name]["mid_low"] = {"gap": obs_ml, "perm_p": pv_ml}

# Wald CI on conditional high-low gap
ph, nh = pooled["cond"]["high"]["rate"], pooled["cond"]["high"]["n"]
pl, nl = pooled["cond"]["low"]["rate"], pooled["cond"]["low"]["n"]
se = math.sqrt(ph * (1 - ph) / nh + pl * (1 - pl) / nl)
pooled["cond"]["high_low"]["wald_ci95"] = [abs(ph - pl) - 1.96 * se, abs(ph - pl) + 1.96 * se]

# ---- Spearman (language-level, respects clustering) ----
def spearman(x, y):
    def rank(v):
        idx = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(idx):
            j = i
            while j + 1 < len(idx) and v[idx[j + 1]] == v[idx[i]]: j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1): r[idx[k]] = avg
            i = j + 1
        return r
    rx, ry = rank(x), rank(y)
    n = len(x); mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den

tier_num = {"low": 0, "mid": 1, "high": 2}
langs = list(LANGS)
tiers_v = [tier_num[LANGS[l]] for l in langs]
spear = {}
for name, vals in [("optout", [per_lang[l]["optout"] for l in langs]),
                   ("names", [per_lang[l]["names"] for l in langs]),
                   ("reach", [per_lang[l]["reach_rate"] for l in langs])]:
    rho = spearman(tiers_v, vals)
    rng = random.Random(SEED); cnt = 0; NP = 100000
    for _ in range(NP):
        tv = tiers_v[:]; rng.shuffle(tv)
        if abs(spearman(tv, vals)) >= abs(rho) - 1e-12: cnt += 1
    spear[name] = {"rho": rho, "perm_p": cnt / NP}

# ---- blocked-agent counts (unchanged by Allow fix, recomputed for completeness) ----
agent_counts = Counter()
for lang, ld in lang_data.items():
    for r in ld["reach"]:
        if blocks_ai(r["ai_rules"]):
            for a in AI_AGENTS:
                if r["ai_rules"].get(a) == "full":
                    agent_counts[a] += 1

# ---- wildcard-inclusive pooled tier rates ----
wc = pool(lambda r: 1 if (blocks_ai(r["ai_rules"]) or r["ai_rules"].get("*") == "full") else 0)
pooled["full_or_wildcard"] = {t: {"rate": sum(v) / len(v), "n": len(v)} for t, v in wc.items()}

final = {"per_lang": per_lang, "pooled": pooled, "cluster": cluster, "spearman": spear,
         "agent_counts": dict(agent_counts.most_common()),
         "capped": {l: per_lang[l]["capped"] for l in langs}}
json.dump(final, open(f"{D}/analysis_v3.json", "w"), indent=1)

print("== per-language (names / optout / cond / n_named) ==")
for l in langs:
    o = per_lang[l]
    print(f"{l} {o['tier']:4s} reach {o['reach_rate']:.2f} names {o['names']:.3f} "
          f"opt {o['optout']:.3f} ci [{o['ci'][0]:.3f},{o['ci'][1]:.3f}] cond {o['cond_block']:.3f} "
          f"(n={o['n_named']}) mass {o['mass_wt']:.3f} capped {o['capped']}")
print("\n== pooled ==")
for k in ("optout", "names", "cond", "head", "tail", "full_or_wildcard"):
    row = {t: f"{pooled[k][t]['rate']:.3f}(n={pooled[k][t]['n']})" for t in ("high", "mid", "low")}
    extra = ""
    if "high_low" in pooled[k]:
        extra = f" HL gap {pooled[k]['high_low']['gap']:.3f} p {pooled[k]['high_low']['perm_p']:.4g}" \
                f" | ML gap {pooled[k]['mid_low']['gap']:.3f} p {pooled[k]['mid_low']['perm_p']:.4g}"
    print(k, row, extra)
print("cond wald ci95 on |gap|:", pooled["cond"]["high_low"]["wald_ci95"])
print("\n== cluster exact ==")
for k, v in cluster.items():
    print(f"{k}: unw gap {v['gap_unweighted']:.3f} p {v['p_unweighted']:.4f} | "
          f"w gap {v['gap_weighted']:.3f} p {v['p_weighted']:.4f} ({v['n_splits']} splits)")
print("\n== spearman ==", json.dumps(spear))
print("\n== top agents ==", dict(Counter(agent_counts).most_common(6)))
print("\n== fail breakdown (uig, eng) ==")
print("uig:", per_lang["uig_Arab"]["fail_breakdown"])
print("eng:", per_lang["eng_Latn"]["fail_breakdown"])
