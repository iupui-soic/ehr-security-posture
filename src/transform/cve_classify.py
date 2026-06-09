"""Classify disclosed CVEs: CWE -> OWASP category + severity bins (Construct B).

Reads the NVD raw per system (and the per-CVE match_confidence), extracts CVSS
(preferring v4 > v3.1 > v3.0 > v2), the CWE list, and the OWASP Top-10:2021
category (highest-priority match across the CWE list). Emits the base
disclosed-vuln table to data/interim/disclosed_vulns.json; remediation_latency.py
later fills fix_ref + remediation_days.
"""
from __future__ import annotations

import re
from functools import lru_cache

import yaml

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.severity import bin_score, qualitative_to_bin

log = get_logger("cve_classify")

CWE_RE = re.compile(r"CWE-(\d+)")


@lru_cache(maxsize=1)
def _owasp_index() -> dict[int, str]:
    """CWE id -> OWASP category, keeping the highest-priority (A01 first) category."""
    doc = yaml.safe_load((config.CONFIG_DIR / "cwe_owasp_map.yaml").read_text())
    cats = doc["categories"]
    # iterate in declared order (A01..A10); first assignment wins (highest priority)
    idx: dict[int, str] = {}
    for cat, cwes in cats.items():
        for c in cwes:
            idx.setdefault(int(c), cat)
    return idx


def classify_owasp(cwe_ids: list[str]) -> str | None:
    idx = _owasp_index()
    best = None
    for cwe in cwe_ids:
        m = CWE_RE.search(cwe)
        if not m:
            continue
        cat = idx.get(int(m.group(1)))
        if cat and (best is None or cat < best):  # category strings sort A01<A02...
            best = cat
    return best


def _extract_cwes(cve: dict) -> list[str]:
    out: list[str] = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if CWE_RE.search(v):
                out.append(v)
    # dedupe preserving order
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _extract_cvss(metrics: dict) -> tuple[str | None, float | None, str | None]:
    """Return (cvss_version, base_score, severity_bin), best metric available."""
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        e = entries[0]
        data = e.get("cvssData", {}) or {}
        score = data.get("baseScore")
        sev = data.get("baseSeverity") or e.get("baseSeverity")
        sev_bin = qualitative_to_bin(sev) or bin_score(score)
        return ver, score, sev_bin
    return None, None, None


def classify_system(system_id: str) -> list[dict]:
    nvd = provenance.load_or_none("nvd", f"{system_id}.json")
    if not nvd:
        log.warning("no NVD raw for %s (run acquire first); skipping", system_id)
        return []
    prov = provenance.provenance_pointer(
        provenance.raw_path("nvd", f"{system_id}.json"))
    match_meta = nvd.get("match_meta", {})
    rows: list[dict] = []
    for w in nvd.get("vulnerabilities", []):
        cve = w["cve"]
        cid = cve["id"]
        cwes = _extract_cwes(cve)
        ver, score, sev_bin = _extract_cvss(cve.get("metrics", {}) or {})
        rows.append({
            "system_id": system_id,
            "vuln_id": cid,
            "source": "nvd",
            "published_date": cve.get("published"),
            "cvss_version": ver,
            "cvss_score": score,
            "severity": sev_bin,
            "cwe": cwes,
            "owasp_category": classify_owasp(cwes),
            "summary": None,
            "fix_ref": None,            # filled by remediation_latency
            "remediation_days": None,   # filled by remediation_latency
            "match_confidence": match_meta.get(cid, {}).get("match_confidence", "low"),
            "match_method": match_meta.get(cid, {}).get("match_method"),
            "snapshot_date": config.snapshot_date(),
            "provenance": prov,
        })
    return rows


def curated_rows() -> list[dict]:
    """Hand-validated disclosures outside CVE/NVD (config/curated_disclosures.yaml).

    These answer RQ2's "0 CVEs != unexamined": some systems disclose via vendor
    channels (SA, release notes) that a CVE query misses. Kept CVE-separate via the
    `source` field. Severity/score stay null unless the advisory states one.
    """
    path = config.CONFIG_DIR / "curated_disclosures.yaml"
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text()) or {}
    valid = {s.id for s in config.load_systems()}
    out: list[dict] = []
    for d in doc.get("disclosures", []) or []:
        sid = d.get("system_id")
        if sid not in valid:
            log.warning("curated disclosure %s for unknown system %r; skipping",
                        d.get("vuln_id"), sid)
            continue
        out.append({
            "system_id": sid,
            "vuln_id": d["vuln_id"],
            "source": d.get("source", "vendor_SA"),
            "published_date": d.get("published_date"),
            "cvss_version": d.get("cvss_version"),
            "cvss_score": d.get("cvss_score"),
            "severity": d.get("severity"),
            "cwe": list(d.get("cwe", []) or []),
            "owasp_category": d.get("owasp_category"),
            "summary": (d.get("summary") or "").strip() or None,
            "fix_ref": d.get("fix_ref"),
            "remediation_days": d.get("remediation_days"),
            "match_confidence": d.get("match_confidence", "medium"),
            "match_method": "curated",
            "snapshot_date": config.snapshot_date(),
            "provenance": d.get("provenance_url"),
        })
    return out


def main() -> int:
    parse_common_args(__doc__)
    all_rows: list[dict] = []
    for system in config.load_systems():
        rows = classify_system(system.id)
        all_rows.extend(rows)
        mapped = sum(1 for r in rows if r["owasp_category"])
        log.info("%s: %d CVEs (%d OWASP-classified)", system.id, len(rows), mapped)
    curated = curated_rows()
    if curated:
        all_rows.extend(curated)
        by_sys = {}
        for r in curated:
            by_sys[r["system_id"]] = by_sys.get(r["system_id"], 0) + 1
        log.info("merged %d curated non-CVE disclosures: %s", len(curated),
                 ", ".join(f"{k}={v}" for k, v in sorted(by_sys.items())))
    provenance.write_interim_json("disclosed_vulns.json", all_rows)
    log.info("wrote data/interim/disclosed_vulns.json (%d rows)", len(all_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
