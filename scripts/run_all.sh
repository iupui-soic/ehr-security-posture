#!/usr/bin/env bash
# Self-contained end-to-end run, safe to leave in tmux across SSH disconnects.
# Continue-on-error per stage (acquire modules are individually idempotent and
# defensive), then transform -> dataset -> analyze -> figures. Re-running resumes:
# already-archived raw is skipped unless --refresh.
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
DATE="$($PY -c 'from src.common import config; print(config.snapshot_date())')"

run() { echo; echo "=== $* ==="; "$@" || echo "!!! stage failed (continuing): $*"; }

echo "########## PIPELINE START snapshot=$DATE ##########"

# Stale GHSA from the pre-token run had 0 advisories -> force a clean re-fetch.
rm -f "data/raw/ghsa/$DATE"/*.json

# --- acquire (cached stages skip fast) ---
run $PY -m src.acquire.github_meta
run $PY -m src.acquire.codeberg_meta
run $PY -m src.acquire.scorecard_run
run $PY -m src.acquire.cve_nvd
run $PY -m src.acquire.osv_query
run $PY -m src.acquire.ghsa
run $PY -m src.acquire.sbom_generate
run $PY -m src.acquire.deps_dev

# --- transform ---
run $PY -m src.transform.cve_classify
run $PY -m src.transform.remediation_latency
run $PY -m src.transform.dependency_graph

# --- dataset + analysis + figures ---
run $PY -m src.transform.build_dataset
run $PY -m src.analyze.descriptive
run $PY -m src.analyze.comparisons
run $PY -m src.analyze.figures

# --- RQ3 OpenMRS scope sensitivity (O3 as-shipped): clones+Syfts frontend repos ---
run $PY -m src.acquire.o3_wide
run $PY -m src.analyze.o3_sensitivity

echo
echo "########## PIPELINE DONE snapshot=$DATE ##########"
echo "processed/:"; ls -1 data/processed/ 2>/dev/null
echo "figures/:";   ls -1 paper/figures/*.png 2>/dev/null
