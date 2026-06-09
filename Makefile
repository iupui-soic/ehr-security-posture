# =============================================================================
# Makefile — EHR security comparative study (Paper #1)
# Reproduce end-to-end against a fixed snapshot:  make all
#
# Python runs in an isolated uv-managed venv (.venv, CPython 3.11).
# scorecard + syft run via their official Docker images (scripts/*.sh) since no
# Go toolchain is installed on the host.
# =============================================================================
.PHONY: help setup check-env acquire transform dataset analyze figures sensitivity test all clean tool-versions

PY := .venv/bin/python
SNAPSHOT := $(shell sed -n 's/^snapshot_date:[[:space:]]*"\(.*\)"/\1/p' config/snapshot.yaml)

help:
	@echo "Targets:"
	@echo "  setup       create py3.11 venv + install pinned deps; pull scorecard/syft images"
	@echo "  acquire     pull raw data (GitHub/Codeberg, Scorecard, NVD, OSV, deps.dev, SBOM) -> data/raw/"
	@echo "  transform   classify CVEs, latency, build dependency graph -> data/interim/"
	@echo "  dataset     join everything -> data/processed/ + schema validation"
	@echo "  analyze     descriptive comparisons (grouped by system_type; no inferential stats)"
	@echo "  figures     regenerate F1-F6, T1-T2 -> paper/figures/"
	@echo "  sensitivity OpenMRS O3 as-shipped scope check (RQ3) -> T3, F6b (needs Docker)"
	@echo "  test        schema + unit tests"
	@echo "  all         acquire -> ... -> figures -> sensitivity"
	@echo "  Snapshot date currently: $(SNAPSHOT)"

setup:
	bash scripts/setup_env.sh
	docker pull gcr.io/openssf/scorecard:stable
	docker pull anchore/syft:latest
	$(MAKE) tool-versions
	@echo "setup OK"

tool-versions:
	bash scripts/tool_versions.sh

check-env:
	@test -f .env || echo "WARN: no .env file (copy .env.example -> .env and add tokens)"
	@test "$(SNAPSHOT)" != "TBD" || { echo "ERROR: set snapshot_date in config/snapshot.yaml"; exit 1; }
	$(PY) -m src.common.check_env
	@echo "env OK (snapshot $(SNAPSHOT))"

acquire: check-env
	$(PY) -m src.acquire.github_meta
	$(PY) -m src.acquire.codeberg_meta
	$(PY) -m src.acquire.scorecard_run
	$(PY) -m src.acquire.cve_nvd
	$(PY) -m src.acquire.osv_query
	$(PY) -m src.acquire.ghsa
	$(PY) -m src.acquire.sbom_generate
	$(PY) -m src.acquire.deps_dev

transform:
	$(PY) -m src.transform.cve_classify
	$(PY) -m src.transform.remediation_latency
	$(PY) -m src.transform.dependency_graph

dataset: transform
	$(PY) -m src.transform.build_dataset
	$(MAKE) test

analyze: dataset
	$(PY) -m src.analyze.descriptive
	$(PY) -m src.analyze.comparisons

figures: analyze
	$(PY) -m src.analyze.figures

# RQ3 OpenMRS scope sensitivity (O3 as-shipped): clones + Syfts the frontend repos
# (needs Docker), then recomputes the wide-scope shared-dependency delta -> T3, F6b.
sensitivity: figures
	$(PY) -m src.acquire.o3_wide
	$(PY) -m src.analyze.o3_sensitivity

test:
	$(PY) -m pytest -q

all: acquire transform dataset analyze figures sensitivity
	@echo "Pipeline complete for snapshot $(SNAPSHOT)"

clean:
	rm -rf data/interim/* data/processed/* paper/figures/*
	@touch data/interim/.gitkeep data/processed/.gitkeep paper/figures/.gitkeep
	@echo "cleaned interim/processed/figures (raw data preserved)"
