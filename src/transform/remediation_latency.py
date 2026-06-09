"""Opportunistic remediation latency for disclosed CVEs (Construct B, nullable).

Latency is genuinely hard to determine from public data, so it is computed only
when linkable and left null otherwise -- never imputed. Method:

  * fix_ref  := first OSV/GHSA reference of type FIX (commit/PR/release URL),
                else the earliest "fixed" version string from the advisory.
  * remediation_days := (release date of the fixed version) - (CVE published date),
                in days, when the fixed version maps to a known release tag from the
                acquired release lists. Can be <= 0 when the fix shipped at/before
                disclosure (coordinated disclosure); reported as-is and documented.

Reads + augments data/interim/disclosed_vulns.json in place.
"""
from __future__ import annotations

from datetime import datetime

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.repos import parse_repo

log = get_logger("remediation_latency")


def _parse_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _norm_version(v: str) -> str:
    return (v or "").lstrip("vV").strip()


def _release_dates(system) -> dict[str, datetime]:
    """normalized tag -> earliest release date, across the system's repos/forges."""
    out: dict[str, datetime] = {}
    source = "codeberg" if system.forge == "codeberg" else "github"
    for repo_str in system.core_repos:
        repo = parse_repo(repo_str)
        rec = provenance.load_or_none(source, f"{system.id}__{repo.slug}.json")
        if not rec:
            continue
        for rel in rec.get("releases", []) or []:
            tag = _norm_version(rel.get("tag_name", ""))
            dt = _parse_dt(rel.get("published_at"))
            if tag and dt and (tag not in out or dt < out[tag]):
                out[tag] = dt
    return out


def _osv_index(system_id: str) -> dict[str, dict]:
    osv = provenance.load_or_none("osv", f"{system_id}.json")
    idx: dict[str, dict] = {}
    if osv:
        for adv in osv.get("advisories", []):
            idx[adv.get("id")] = adv
            for alias in adv.get("aliases", []) or []:
                idx[alias] = adv
    return idx


def _fix_info(adv: dict | None) -> tuple[str | None, list[str]]:
    """(fix_ref url, [fixed_versions]) from an OSV advisory."""
    if not adv:
        return None, []
    fix_ref = None
    for ref in adv.get("references", []) or []:
        if (ref.get("type") or "").upper() == "FIX" and ref.get("url"):
            fix_ref = ref["url"]
            break
    fixed: list[str] = []
    for aff in adv.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    return fix_ref, fixed


def main() -> int:
    parse_common_args(__doc__)
    rows = provenance.read_interim_json("disclosed_vulns.json")
    by_system = {s.id: s for s in config.load_systems()}
    rel_cache: dict[str, dict] = {}
    osv_cache: dict[str, dict] = {}

    # Curated/vendor disclosures carry their own fix_ref (and have no NVD/OSV
    # advisory to mine); leave them untouched so we don't clobber it with null.
    CVE_SOURCES = {"nvd", "osv", "ghsa", None}

    n_fixref = n_latency = 0
    for row in rows:
        if row.get("source") not in CVE_SOURCES:
            continue
        sid = row["system_id"]
        system = by_system.get(sid)
        if system is None:
            continue
        osv_idx = osv_cache.setdefault(sid, _osv_index(sid))
        rels = rel_cache.setdefault(sid, _release_dates(system))

        adv = osv_idx.get(row["vuln_id"])
        fix_ref, fixed_versions = _fix_info(adv)
        if not fix_ref and fixed_versions:
            fix_ref = f"fixed-in:{fixed_versions[0]}"
        row["fix_ref"] = fix_ref
        if fix_ref:
            n_fixref += 1

        published = _parse_dt(row.get("published_date"))
        latency = None
        if published and fixed_versions:
            fix_dates = [rels[_norm_version(fv)] for fv in fixed_versions
                         if _norm_version(fv) in rels]
            if fix_dates:
                latency = (min(fix_dates) - published).days
        row["remediation_days"] = latency
        if latency is not None:
            n_latency += 1

    provenance.write_interim_json("disclosed_vulns.json", rows)
    log.info("augmented %d rows: fix_ref on %d, remediation_days on %d (rest null)",
             len(rows), n_fixref, n_latency)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
