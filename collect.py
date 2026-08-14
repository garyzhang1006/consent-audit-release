# Consent-infrastructure inequality across the languages of web corpora.
# Measures AI-crawler opt-out rates in live robots.txt, stratified by the language of the
# FineWeb-2 / FineWeb subset a domain feeds. CPU + network only. Checkpoints per language.

import os, json, time, random, gzip, itertools, re
from collections import Counter, defaultdict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

T0 = time.time()
WORK = "/kaggle/working" if os.path.isdir("/kaggle/working") else "./work"
os.makedirs(WORK, exist_ok=True)
SEED = 20260811
random.seed(SEED)

# language tiers: (config, dataset) — eng comes from FineWeb, rest from FineWeb-2
LANGS = {
    "eng_Latn": ("HuggingFaceFW/fineweb", "sample-10BT", "high"),
    "deu_Latn": ("HuggingFaceFW/fineweb-2", "deu_Latn", "high"),
    "jpn_Jpan": ("HuggingFaceFW/fineweb-2", "jpn_Jpan", "high"),
    "fra_Latn": ("HuggingFaceFW/fineweb-2", "fra_Latn", "high"),
    "ind_Latn": ("HuggingFaceFW/fineweb-2", "ind_Latn", "mid"),
    "tur_Latn": ("HuggingFaceFW/fineweb-2", "tur_Latn", "mid"),
    "vie_Latn": ("HuggingFaceFW/fineweb-2", "vie_Latn", "mid"),
    "tha_Thai": ("HuggingFaceFW/fineweb-2", "tha_Thai", "mid"),
    "swh_Latn": ("HuggingFaceFW/fineweb-2", "swh_Latn", "low"),
    "sun_Latn": ("HuggingFaceFW/fineweb-2", "sun_Latn", "low"),
    "yor_Latn": ("HuggingFaceFW/fineweb-2", "yor_Latn", "low"),
    "uig_Arab": ("HuggingFaceFW/fineweb-2", "uig_Arab", "low"),
    "azj_Latn": ("HuggingFaceFW/fineweb-2", "azj_Latn", "mid"),
    "gle_Latn": ("HuggingFaceFW/fineweb-2", "gle_Latn", "low"),
}
DOC_CAP = 200000          # per-language streaming cap for domain stats (reported, not silent)
N_DOMAINS = 350           # domains sampled per language for robots.txt fetch
AI_AGENTS = ["gptbot", "chatgpt-user", "ccbot", "google-extended", "claudebot", "anthropic-ai",
             "claude-web", "perplexitybot", "bytespider", "cohere-ai", "applebot-extended",
             "meta-externalagent", "omgilibot", "diffbot", "ai2bot"]

def log(msg): print(f"[{time.time()-T0:7.0f}s] {msg}", flush=True)
def cp(name): return os.path.join(WORK, name)

# ---------- Stage A: per-language domain census ----------
def domain_of(url):
    try:
        h = urlparse(url).hostname or ""
        return h[4:] if h.startswith("www.") else h
    except Exception:
        return ""

for lang, (repo, config, tier) in LANGS.items():
    fn = cp(f"census_{lang}.json")
    if os.path.exists(fn):
        continue
    log(f"Stage A census: {lang} ({tier}) from {repo}/{config}")
    from datasets import load_dataset
    ds = load_dataset(repo, name=config, split="train", streaming=True)
    doc_mass = Counter(); tok_mass = Counter(); n = 0
    for x in itertools.islice(ds, DOC_CAP):
        d = domain_of(x.get("url", ""))
        if d:
            doc_mass[d] += 1
            tok_mass[d] += len(x.get("text", "").split())
        n += 1
    json.dump({"lang": lang, "tier": tier, "docs_streamed": n, "capped": n >= DOC_CAP,
               "n_domains": len(doc_mass),
               "doc_mass": dict(doc_mass.most_common(20000)),
               "tok_mass": {d: tok_mass[d] for d, _ in doc_mass.most_common(20000)}},
              open(fn, "w"))
    log(f"  {lang}: {n} docs, {len(doc_mass)} domains")

# ---------- Stage B: sample domains, fetch robots.txt ----------
import urllib.request

def fetch_robots(dom):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{dom}/robots.txt",
                headers={"User-Agent": "Mozilla/5.0 (research; WaC-13 consent audit)"})
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(200000)
                ct = r.headers.get("Content-Type", "")
                if r.status == 200:
                    return {"domain": dom, "status": 200, "scheme": scheme, "ct": ct,
                            "body": body.decode("utf-8", "replace")}
                return {"domain": dom, "status": r.status, "scheme": scheme}
        except Exception as e:
            err = f"{type(e).__name__}: {str(e)[:80]}"
    return {"domain": dom, "status": -1, "error": err}

def parse_robots(body):
    """Per AI agent: 'full' (Disallow: /), 'partial' (some Disallow), or None."""
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
        # Allow: lines also mark the agent as named; never override a stronger state.
        m = re.match(r"(?i)allow\s*:\s*(.*)", line)
        if m and cur_agents:
            rules_open = True
            for a in cur_agents:
                key = "*" if a == "*" else a
                if key not in out:
                    out[key] = "allow"
    return out

for lang in LANGS:
    fn = cp(f"robots_{lang}.json.gz")
    if os.path.exists(fn):
        continue
    census = json.load(open(cp(f"census_{lang}.json")))
    doms_by_mass = list(census["doc_mass"].keys())
    top = doms_by_mass[:N_DOMAINS // 2]
    rest = doms_by_mass[N_DOMAINS // 2:]
    rng = random.Random(SEED + sum(ord(c) for c in lang))
    tail = rng.sample(rest, min(len(rest), N_DOMAINS - len(top)))
    sample = top + tail
    log(f"Stage B robots: {lang}, fetching {len(sample)} domains")
    results = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(fetch_robots, d): d for d in sample}
        for i, f in enumerate(as_completed(futs)):
            results.append(f.result())
            if (i+1) % 100 == 0: log(f"  ...{i+1}/{len(sample)}")
    for r in results:
        if r.get("body"):
            r["ai_rules"] = parse_robots(r["body"])
            r["body"] = r["body"][:20000]     # keep archived copy bounded
    with gzip.open(fn, "wt", encoding="utf-8") as f:
        json.dump({"lang": lang, "sampled": sample, "results": results}, f)
    ok = sum(1 for r in results if r.get("status") == 200)
    log(f"  {lang}: {ok}/{len(sample)} robots.txt fetched")

# ---------- Stage C: opt-out rates, mass-weighted loss, composition shift ----------
def blocks_ai(rules):
    if not rules: return False
    if any(rules.get(a) == "full" for a in AI_AGENTS): return True
    return False

def blocked_agents(rules):
    return [a for a in AI_AGENTS if rules and rules.get(a) == "full"]

summary = {}
for lang, (_, _, tier) in LANGS.items():
    census = json.load(open(cp(f"census_{lang}.json")))
    with gzip.open(cp(f"robots_{lang}.json.gz"), "rt", encoding="utf-8") as f:
        rob = json.load(f)
    res = rob["results"]
    reach = [r for r in res if r.get("status") == 200]
    optout = [r for r in reach if blocks_ai(r.get("ai_rules"))]
    dm, tm = census["doc_mass"], census["tok_mass"]
    reach_mass = sum(dm.get(r["domain"], 0) for r in reach)
    optout_mass = sum(dm.get(r["domain"], 0) for r in optout)
    optout_tokmass = sum(tm.get(r["domain"], 0) for r in optout)
    reach_tokmass = sum(tm.get(r["domain"], 0) for r in reach)
    # domain-level bootstrap CI on opt-out rate
    rng = random.Random(SEED + 17)
    flags = [1 if blocks_ai(r.get("ai_rules")) else 0 for r in reach]
    boots = []
    for _ in range(2000):
        if not flags: break
        bs = [flags[rng.randrange(len(flags))] for _ in flags]
        boots.append(sum(bs) / len(bs))
    boots.sort()
    ci = [boots[int(0.025*len(boots))], boots[int(0.975*len(boots))]] if boots else [None, None]
    agent_counts = Counter(a for r in optout for a in blocked_agents(r.get("ai_rules")))
    summary[lang] = {
        "tier": tier, "sampled": len(res), "reachable": len(reach),
        "reach_rate": len(reach) / max(1, len(res)),
        "optout_domains": len(optout),
        "optout_rate_domains": len(optout) / max(1, len(reach)),
        "optout_rate_ci95": ci,
        "optout_rate_docmass": optout_mass / max(1, reach_mass),
        "optout_rate_tokmass": optout_tokmass / max(1, reach_tokmass),
        "top_blocked_agents": dict(agent_counts.most_common(8)),
        "docs_streamed": census["docs_streamed"], "capped": census["capped"],
    }
    log(f"{lang} ({tier}): reach {summary[lang]['reach_rate']:.2f}, "
        f"opt-out {summary[lang]['optout_rate_domains']:.3f} "
        f"[{ci[0]:.3f},{ci[1]:.3f}] mass-weighted {summary[lang]['optout_rate_docmass']:.3f}"
        if ci[0] is not None else f"{lang}: no reachable domains")

json.dump(summary, open(cp("consent_summary.json"), "w"), indent=2)

by_tier = defaultdict(list)
for lang, s in summary.items(): by_tier[s["tier"]].append(s["optout_rate_docmass"])
tier_means = {t: sum(v)/len(v) for t, v in by_tier.items() if v}
json.dump(tier_means, open(cp("tier_means.json"), "w"), indent=2)
log(f"tier means (doc-mass-weighted opt-out): {tier_means}")
log("ALL STAGES DONE")
