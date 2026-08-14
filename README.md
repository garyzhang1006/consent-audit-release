# Consent-Infrastructure Inequality Across the Languages of Web Corpora

Release for the WaC-13 submission. Contains everything needed to recompute every number in the paper.

## Contents
- `data/robots_<lang>.json.gz` (14 files): every fetched robots.txt response, per language, with the parse recorded at fetch time (`ai_rules`), fetch status, and error strings. Bodies archived up to 20,000 characters; `ai_rules` was parsed from the full body at fetch time.
- `data/consent_summary.json`, `data/analysis_v3.json`, `data/tier_means.json`: derived per-language and pooled statistics.
- `collect.py`: the collection pipeline (census streaming from FineWeb/FineWeb-2, domain sampling, robots.txt fetching, parsing). CPU + network only.
- `analysis.py`: recomputes every statistic in the paper from `data/`, including the naming/blocking decomposition, exact language-cluster permutation tests, strata controls, Spearman ranks, and reachability failure breakdown. Run: `python3 analysis.py`.
- `make_fig.py`: regenerates Figure 1 from `data/analysis_v3.json`.
- `valid_sample.json`, `valid_labels.json`: the stratified 60-body parser-validation sample and independent labels.

## Notes
- Census streaming caps at 200,000 documents per language subset; the cap binds everywhere except Sundanese, Yoruba, and Uyghur (subsets exhausted).
- Fetches were performed 2026-08 from a single cloud vantage point with the User-Agent string recorded in `collect.py`.
- Re-parsing archived bodies alone undercounts blocks for the few files longer than the 20k archive limit; `analysis.py` therefore takes block status from the fetch-time parse and uses the re-parse only to add Allow-only agent naming.
