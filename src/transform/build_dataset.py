"""Join all constructs into the schema-conforming processed dataset.

Writes one file per schema entity (system, practice_scores, disclosed_vuln,
dependency, shared_dependency, descriptor) as both .parquet and .csv, plus a
denormalized system-level headline table data/processed/ehr_security_dataset.parquet
(the DoD artifact). Array/object fields are JSON-encoded strings for portability.
Validation against schema/dataset_schema.json runs at the end (and in tests/).
"""
from __future__ import annotations

import json

import pandas as pd

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.repos import parse_repo
from ..common.severity import max_bin

log = get_logger("build_dataset")

# Columns that hold arrays/objects -> JSON-encoded for parquet/csv portability.
JSON_COLS = {"primary_languages", "core_repos", "cpe_hints", "cwe", "vuln_ids",
             "systems", "language_mix"}

# Disclosure channels outside the CVE ecosystem (counted apart from "CVEs").
VENDOR_SOURCES = ["vendor_SA", "release_notes", "bug_tracker"]


# --------------------------------------------------------------------------- #
# entity builders
# --------------------------------------------------------------------------- #
def _match_confidence_overall(system_id: str) -> str:
    nvd = provenance.load_or_none("nvd", f"{system_id}.json")
    if not nvd or nvd.get("n_total", 0) == 0:
        return "medium"
    if nvd.get("n_low", 0) == 0:
        return "high"
    if nvd.get("n_high", 0) == 0:
        return "low"
    return "medium"


def build_system() -> list[dict]:
    rows = []
    for s in config.load_systems():
        rows.append({
            "system_id": s.id,
            "display_name": s.display_name,
            "forge": s.forge,
            "system_type": s.system_type,
            "primary_languages": s.primary_languages,
            "license": s.license,
            "repo_scope_rule": s.repo_scope_rule,
            "core_repos": s.core_repos,
            "cpe_hints": s.cpe_hints,
            "match_confidence_overall": _match_confidence_overall(s.id),
            "snapshot_date": config.snapshot_date(),
        })
    return rows


def build_practice_scores() -> list[dict]:
    rows = []
    ver = config.load_snapshot().tool_versions.get("scorecard")
    for s in config.load_systems():
        for repo_str in s.core_repos:
            repo = parse_repo(repo_str)
            sc = provenance.load_or_none("scorecard", f"{s.id}__{repo.slug}.json")
            if not sc:
                continue
            prov = provenance.provenance_pointer(
                provenance.raw_path("scorecard", f"{s.id}__{repo.slug}.json"))
            for chk in sc.get("checks", []) or []:
                score = chk.get("score")
                if score is not None and score < 0:
                    score = None  # Scorecard -1 = inconclusive
                assessable = chk.get("assessable", True)
                rows.append({
                    "system_id": s.id,
                    "repo": repo.host_full,
                    "check_name": chk.get("name"),
                    "score": score,
                    "assessable": bool(assessable),
                    "reason": chk.get("reason"),
                    "scorecard_version": sc.get("scorecard_version") or ver,
                    "snapshot_date": config.snapshot_date(),
                    "provenance": prov,
                })
    return rows


def build_disclosed_vuln() -> list[dict]:
    rows = provenance.read_interim_json("disclosed_vulns.json") \
        if (config.INTERIM_DIR / "disclosed_vulns.json").exists() else []
    keep = {"system_id", "vuln_id", "source", "published_date", "cvss_version",
            "cvss_score", "severity", "cwe", "owasp_category", "summary", "fix_ref",
            "remediation_days", "match_confidence", "snapshot_date", "provenance"}
    return [{k: r.get(k) for k in keep} for r in rows]


def build_dependency() -> list[dict]:
    rows = provenance.read_interim_json("dependencies.json") \
        if (config.INTERIM_DIR / "dependencies.json").exists() else []
    keep = {"system_id", "package", "ecosystem", "version", "is_direct",
            "vuln_ids", "max_severity", "snapshot_date", "provenance"}
    return [{k: r.get(k) for k in keep} for r in rows]


def build_shared_dependency() -> list[dict]:
    rows = provenance.read_interim_json("shared_dependencies.json") \
        if (config.INTERIM_DIR / "shared_dependencies.json").exists() else []
    keep = {"package", "ecosystem", "systems", "is_vulnerable", "max_severity",
            "snapshot_date"}
    return [{k: r.get(k) for k in keep} for r in rows]


def _release_frequency(releases: list[dict]) -> str | None:
    dates = []
    for r in releases or []:
        d = r.get("published_at")
        if d:
            dates.append(d[:10])
    if len(dates) < 2:
        return f"{len(dates)} releases" if dates else None
    dates.sort()
    span_days = (pd.Timestamp(dates[-1]) - pd.Timestamp(dates[0])).days or 1
    per_year = len(dates) / (span_days / 365.25)
    return f"{per_year:.1f}/yr ({len(dates)} releases)"


def build_descriptor() -> list[dict]:
    rows = []
    for s in config.load_systems():
        source = "codeberg" if s.forge == "codeberg" else "github"
        loc_total = 0
        loc_seen = False
        lang_mix: dict[str, int] = {}
        contributors = 0
        contrib_seen = False
        has_sec = False
        sec_ref = None
        sec_source = None
        latest_commit = None
        all_releases: list[dict] = []
        for repo_str in s.core_repos:
            repo = parse_repo(repo_str)
            meta = provenance.load_or_none(source, f"{s.id}__{repo.slug}.json")
            cloc = provenance.load_or_none("cloc", f"{s.id}__{repo.slug}.json")
            if meta:
                c = meta.get("contributors_count")
                if c is not None:
                    contributors += c
                    contrib_seen = True
                if meta.get("has_security_policy"):
                    has_sec = True
                    if sec_source != "repo_file":
                        sec_source = "repo_file"
                        sec_ref = meta.get("security_policy_path") or sec_ref
                lc = meta.get("latest_commit_date")
                if lc and (latest_commit is None or lc > latest_commit):
                    latest_commit = lc
                all_releases.extend(meta.get("releases", []) or [])
            if cloc:
                for lang, vals in cloc.items():
                    if lang in ("header", "SUM") or not isinstance(vals, dict):
                        continue
                    lang_mix[lang] = lang_mix.get(lang, 0) + vals.get("code", 0)
                total = (cloc.get("SUM", {}) or {}).get("code")
                if total is not None:
                    loc_total += total
                    loc_seen = True
        # External coordinated-disclosure policy (e.g. GNU Health publishes its
        # policy in docs, not a repo SECURITY.md): honour a configured URL so the
        # repo-file probe's false-negative does not understate the posture.
        policy_url = (s.raw or {}).get("security_policy_url")
        if not has_sec and policy_url:
            has_sec = True
            sec_source = "external_docs"
            sec_ref = policy_url
        rows.append({
            "system_id": s.id,
            "loc": loc_total if loc_seen else None,
            "language_mix": lang_mix,
            "repo_count": len(s.core_repos),
            "contributors": contributors if contrib_seen else None,
            "commit_cadence": (f"last commit {latest_commit[:10]}"
                               if latest_commit else None),
            "release_frequency": _release_frequency(all_releases),
            "has_security_policy": has_sec,
            "security_policy_source": sec_source if has_sec else None,
            "security_policy_ref": sec_ref if has_sec else None,
            "has_bug_bounty": False,   # not reliably auto-detectable; see DATASHEET
            "snapshot_date": config.snapshot_date(),
            "provenance": f"data/raw/{source}/{config.snapshot_date()}/",
        })
    return rows


# --------------------------------------------------------------------------- #
# headline summary (the DoD parquet)
# --------------------------------------------------------------------------- #
def build_headline(system, practice, vulns, deps, descr) -> list[dict]:
    pdf = pd.DataFrame(practice)
    vdf = pd.DataFrame(vulns)
    ddf = pd.DataFrame(deps)
    desc_by = {d["system_id"]: d for d in descr}
    rows = []
    for s in system:
        sid = s["system_id"]
        sv_all = vdf[vdf["system_id"] == sid] if not vdf.empty else vdf
        # CVE-channel rows only for the "CVE" counts; vendor/curated reported apart.
        sv = (sv_all[~sv_all["source"].isin(VENDOR_SOURCES)]
              if not sv_all.empty and "source" in sv_all.columns else sv_all)
        sv_other = (sv_all[sv_all["source"].isin(VENDOR_SOURCES)]
                    if not sv_all.empty and "source" in sv_all.columns else sv_all.iloc[0:0])
        sd = ddf[ddf["system_id"] == sid] if not ddf.empty else ddf
        sp = pdf[(pdf["system_id"] == sid) & (pdf["assessable"])] if not pdf.empty else pdf
        sev_counts = (sv["severity"].value_counts().to_dict() if not sv.empty else {})
        rows.append({
            "system_id": sid,
            "display_name": s["display_name"],
            "system_type": s["system_type"],
            "forge": s["forge"],
            "loc": desc_by.get(sid, {}).get("loc"),
            "contributors": desc_by.get(sid, {}).get("contributors"),
            "has_security_policy": desc_by.get(sid, {}).get("has_security_policy"),
            "scorecard_mean": (round(sp["score"].dropna().mean(), 2)
                               if not sp.empty and sp["score"].notna().any() else None),
            "n_cves": int(len(sv)),
            "n_disclosures_noncve": int(len(sv_other)),
            "n_cves_critical": int(sev_counts.get("critical", 0)),
            "n_cves_high": int(sev_counts.get("high", 0)),
            "n_deps": int(len(sd)),
            "n_deps_vulnerable": int((sd["max_severity"] != "none").sum())
                                 if not sd.empty else 0,
            "match_confidence_overall": s["match_confidence_overall"],
            "snapshot_date": config.snapshot_date(),
        })
    return rows


# --------------------------------------------------------------------------- #
# IO + schema validation
# --------------------------------------------------------------------------- #
def _encode(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if col in JSON_COLS:
            df[col] = df[col].apply(lambda v: json.dumps(v) if v is not None else None)
    return df


def _write(name: str, rows: list[dict]):
    df = pd.DataFrame(rows)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    enc = _encode(df)
    enc.to_parquet(config.PROCESSED_DIR / f"{name}.parquet", index=False)
    enc.to_csv(config.PROCESSED_DIR / f"{name}.csv", index=False)
    log.info("wrote processed/%s (%d rows, %d cols)", name, len(df), len(df.columns))
    return df


def validate_against_schema(tables: dict[str, list[dict]]) -> list[str]:
    """Check each entity's rows carry the schema's declared fields. Returns errors."""
    schema = json.loads(config.SCHEMA_JSON.read_text())
    errors: list[str] = []
    for entity, spec in schema["entities"].items():
        required = set(spec["fields"].keys())
        rows = tables.get(entity)
        if rows is None:
            errors.append(f"{entity}: table missing")
            continue
        if not rows:
            continue  # empty (e.g. no CVEs) is allowed; sparsity is a finding
        cols = set(rows[0].keys())
        missing = required - cols
        if missing:
            errors.append(f"{entity}: missing fields {sorted(missing)}")
    return errors


def main() -> int:
    parse_common_args(__doc__)
    tables = {
        "system": build_system(),
        "practice_scores": build_practice_scores(),
        "disclosed_vuln": build_disclosed_vuln(),
        "dependency": build_dependency(),
        "shared_dependency": build_shared_dependency(),
        "descriptor": build_descriptor(),
    }
    errors = validate_against_schema(tables)
    if errors:
        for e in errors:
            log.error("SCHEMA: %s", e)
        raise SystemExit(f"schema validation failed ({len(errors)} errors)")
    log.info("schema validation passed")

    for name, rows in tables.items():
        _write(name, rows)

    headline = build_headline(tables["system"], tables["practice_scores"],
                              tables["disclosed_vuln"], tables["dependency"],
                              tables["descriptor"])
    pd.DataFrame(headline).to_parquet(
        config.PROCESSED_DIR / "ehr_security_dataset.parquet", index=False)
    pd.DataFrame(headline).to_csv(
        config.PROCESSED_DIR / "ehr_security_dataset.csv", index=False)
    log.info("wrote processed/ehr_security_dataset.parquet (%d systems)", len(headline))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
