# Datasheet — Open-Source EHR Security Signals (Paper #1)

Datasheet-for-datasets (Gebru et al., 2021) for the dataset produced by this
pipeline. Every figure in `config/snapshot.yaml` is reported "as of"
`snapshot_date` (currently **2026-06-09**). This datasheet is the seed for the
curated/living dataset of Paper #2.

## Motivation
- **Purpose.** Enable a reproducible, multi-dimensional comparison of the security
  posture and supply-chain risk of five open-source EHR systems (OpenMRS, OpenEMR,
  GNU Health, EHRbase, Medplum), using only public data and open tooling.
- **Why these signals.** Each maps to a research question: development security
  practices (RQ1), the disclosed-vulnerability landscape (RQ2), and supply-chain /
  shared-dependency risk (RQ3, the centerpiece). Project descriptors are context,
  not an RQ. No composite "security score" is computed (deferred to Paper #2).

## Composition
Six normalized entities (frozen schema: `schema/dataset_schema.json`), written to
`data/processed/` as `.parquet` + `.csv`, plus a denormalized system-level headline
table `ehr_security_dataset.parquet`:

| Entity | Grain | Construct |
|---|---|---|
| `system` | one row / system | sample definition + CVE-match confidence |
| `practice_scores` | system × repo × Scorecard check | A — RQ1 |
| `disclosed_vuln` | one row / matched CVE | B — RQ2 |
| `dependency` | system × package@version | C — RQ3 |
| `shared_dependency` | package shared by >1 system | C — RQ3 centerpiece |
| `descriptor` | one row / system | D — context |

- **No personal or patient data.** Only source code, repository metadata, and
  public vulnerability records.
- **Array/object fields** (e.g. `cwe`, `vuln_ids`, `systems`, `language_mix`) are
  JSON-encoded strings in the CSV/Parquet outputs; decode with
  `src/analyze/loaders.py`.

## Collection process
- **Sources (all public):** GitHub REST, Codeberg/Gitea API, OpenSSF Scorecard,
  NVD CVE API 2.0, OSV.dev, GitHub Security Advisories, deps.dev, and Syft-generated
  SBOMs. Endpoints + tool versions pinned in `config/snapshot.yaml` /
  `config/tool_versions.lock`.
- **Provenance.** Every raw response is archived verbatim under
  `data/raw/<source>/<snapshot_date>/`; each processed record carries a
  `provenance` pointer to its raw source and a `snapshot_date`.
- **Idempotent + dated.** Re-runs skip already-fetched raw unless `--refresh` is
  passed; rate limits are respected with backoff.

## Preprocessing / labeling
- **CVE↔product matching** uses a hand-validated CPE/keyword dictionary
  (`config/systems.yaml`) with a per-CVE `match_confidence`. Keyword-only hits not
  corroborated by a CPE configuration are `low` and flagged for spot-validation —
  never dropped. (Example validated at build time: `CVE-2026-49120`, a real Medplum
  SSRF, is `low` only because Medplum has no NVD CPE entry.)
- **CWE→OWASP** via `config/cwe_owasp_map.yaml` (OWASP Top-10:2021), highest-priority
  category per CVE.
- **Severity** via CVSS base score (v4>v3.1>v3.0>v2), binned to NVD cutoffs
  (`src/common/severity.py`).
- **Remediation latency** is opportunistic and nullable — computed only when a
  fixed version maps to a known release date; never imputed.
- **Direct vs transitive** from the CycloneDX dependency graph, falling back to the
  manifest-vs-lockfile location of the component.

## Known limitations (read before use)
- **Small N (5).** Descriptive/structural only — **no inferential statistics**.
- **Disclosure bias.** CVE count reflects scrutiny, not security; it is *not* a
  ranking. Triangulate with practices (A) and supply chain (C).
- **System heterogeneity.** Applications vs data platforms; app-layer vuln classes
  are not comparable across types. Reported grouped by `system_type`.
- **Off-GitHub (GNU Health / Codeberg).** Scorecard remote checks are
  `not_assessable` (file-based checks recovered via local mode); never imputed.
- **SBOM completeness varies by ecosystem.** Syft catalogs lockfiles/installed
  packages; projects that declare dependencies only in `pyproject.toml` (PEP 621)
  or un-locked Gradle yield partial/empty SBOMs. Per-system component counts are
  recorded so coverage is transparent. See the SBOM-strategy note in the README.
- **Repo-scope comparability.** Multi-repo (OpenMRS) vs monorepo (OpenEMR);
  documented scope rule + sensitivity analysis.

## Uses
- Intended: the RQ1–RQ3 analyses and figures in Paper #1; the seed corpus for
  Paper #2's patient-risk-weighted index.
- Out of scope: any ranked "most insecure EHR" claim; any exploit development.

## Distribution & maintenance
- **Code license:** Apache-2.0. **Dataset license:** CC-BY-4.0 (decide before
  release). Raw third-party responses retain their sources' terms.
- Regenerate end-to-end with `make all` against the pinned snapshot. Bump
  `snapshot_date` for a new dated snapshot; raw archives are never overwritten.
