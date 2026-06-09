# EHR Security Comparative Study (Paper #1)

A reproducible comparison of the **security posture and supply-chain risk** of five
open-source EHR systems, using only public data and open tooling. Framed for IEEE BHI
(health-informatics venue): the security engineering serves a patient-data / care-continuity
argument.

> The config files (`config/systems.yaml`, `config/snapshot.yaml`) and
> `schema/dataset_schema.json` are authoritative for the sample, snapshot, and
> dataset shape.

## Sample (5 systems)

| System | Forge | Type |
|---|---|---|
| OpenMRS | GitHub | clinical application |
| OpenEMR | GitHub | clinical application |
| GNU Health | **Codeberg** | clinical application |
| EHRbase | GitHub | clinical data platform (openEHR CDR) |
| Medplum | GitHub | clinical data platform (FHIR-native) |

Defined authoritatively in `config/systems.yaml` (with repo-scope rules, CPE hints, and
the documented exclusions). At N=5 this is a **comparative study**, not a large-N benchmark.

## Research questions (3)

- **RQ1** — development security practices (OpenSSF Scorecard, per-dimension).
- **RQ2** — disclosed-vulnerability **landscape** (the point is the disclosure *asymmetry*).
- **RQ3** — supply-chain risk, **centerpiece**: vulnerable dependencies + dependencies
  **shared across systems** as cross-system single points of failure.

Project descriptors are reported as *context* (Table 1), not as a question. No inferential
statistics at N=5.

## Prerequisites

- Python 3.11+, the OpenSSF **`scorecard`** CLI, and **`syft`** on PATH.
- Env: `GITHUB_TOKEN` (read-only PAT), `NVD_API_KEY` (free). Optional: `CODEBERG_TOKEN`.
- Set `snapshot_date` in `config/snapshot.yaml` and pin tool versions before acquiring.

## Run

```bash
make setup        # install pinned deps; verify scorecard/syft
make all          # acquire -> transform -> dataset -> analyze -> figures
make test         # schema + unit tests
```

Outputs: `data/processed/ehr_security_dataset.parquet` (schema in `schema/dataset_schema.json`)
and figures/tables in `paper/figures/`. Raw API responses are archived, dated, under
`data/raw/` — re-runs are idempotent.

## Guardrails (read `DISCLOSURE.md`)

- Measurement only — **no exploit code, no PoCs, no malware.**
- **No new-vulnerability hunting** by default (the SAST probe / Construct E is off in
  `config/snapshot.yaml`). If ever enabled: private coordinated disclosure first,
  aggregate-only reporting.
- Public data only; respect API rate limits and terms.
- **GNU Health is on Codeberg** — GitHub-only Scorecard checks are `not_assessable`
  (never imputed); use Syft for its SBOM.
- Do not change the sample without updating `config/systems.yaml`.

## Sets up Paper #2

Over-collect raw signal, freeze the schema, archive dated raw data, and **defer any
composite "security score"** — the patient-risk-weighted index + dataset release is
Paper #2 (JBHI).

## Build phases

Scaffold -> Acquire -> Transform -> Dataset -> Analysis -> Figures -> Paper
integration, each with exit criteria.
