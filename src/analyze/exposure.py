"""Clinical-exposure layer: join CISA KEV + FIRST EPSS onto disclosed CVEs (RQ2)
and shared vulnerable-dependency SPOFs (RQ3).

Turns raw vulnerability counts into exploitation exposure:
  * KEV  -- is the CVE *known-exploited in the wild* (CISA catalog)?
  * EPSS -- exploitation probability in the next 30 days (FIRST), as of snapshot.

Inputs (all already archived/derived, offline):
  raw/kev/<date>/known_exploited_vulnerabilities.json
  raw/epss/<date>/epss.json
  interim/disclosed_vulns.json
  interim/shared_dependencies.json
  raw/depvulns/<date>/<system>.json   (package -> GHSA -> CVE aliases)

Outputs:
  data/processed/exploit_exposure.csv          (one row per (scope, CVE))
  data/processed/exploit_exposure_summary.json (headline numbers for the paper)
"""
from __future__ import annotations

import csv
import json

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.logging import get_logger

log = get_logger("exposure")
EPSS_HIGH = 0.5  # EPSS >= 0.5 == >50% modelled 30-day exploitation probability


def _load_kev() -> set[str]:
    kev = provenance.read_json("kev", "known_exploited_vulnerabilities.json")
    return {v["cveID"] for v in kev.get("vulnerabilities", []) if v.get("cveID")}


def _load_epss() -> dict[str, dict]:
    return provenance.read_json("epss", "epss.json").get("scores", {}) or {}


def _dep_cve_index() -> dict[tuple[str, str], set[str]]:
    """(package_name_lower, system_id) -> set of CVE ids for that vulnerable dep."""
    idx: dict[tuple[str, str], set[str]] = {}
    for system in config.load_systems():
        dep = provenance.load_or_none("depvulns", f"{system.id}.json")
        if not dep:
            continue
        details = dep.get("vuln_details") or {}
        for entry in (dep.get("vuln_map") or {}).values():
            name = (entry.get("name") or "").lower()
            cves: set[str] = set()
            for vid in entry.get("vuln_ids", []) or []:
                for alias in (details.get(vid, {}) or {}).get("aliases", []) or []:
                    if str(alias).startswith("CVE-"):
                        cves.add(alias)
            if name and cves:
                idx.setdefault((name, system.id), set()).update(cves)
    return idx


def _exposure(cve: str, kev: set[str], epss: dict[str, dict]) -> dict:
    e = epss.get(cve, {})
    return {
        "in_kev": cve in kev,
        "epss": e.get("epss"),
        "epss_percentile": e.get("percentile"),
    }


def main() -> int:
    parse_common_args(__doc__)
    kev = _load_kev()
    epss = _load_epss()
    dep_idx = _dep_cve_index()
    rows: list[dict] = []

    # --- RQ2: disclosed CVEs ------------------------------------------------
    disclosed = [r for r in provenance.read_interim_json("disclosed_vulns.json")
                 if str(r.get("vuln_id", "")).startswith("CVE-")]
    disclosed_cves: dict[str, set[str]] = {}   # cve -> {systems}
    for r in disclosed:
        disclosed_cves.setdefault(r["vuln_id"], set()).add(r["system_id"])
    for cve, systems in sorted(disclosed_cves.items()):
        exp = _exposure(cve, kev, epss)
        rows.append({"scope": "disclosed", "cve": cve, "package": "",
                     "ecosystem": "", "systems": ";".join(sorted(systems)),
                     **exp})

    disc_kev = sorted(c for c in disclosed_cves if c in kev)
    disc_high = sorted(c for c in disclosed_cves
                       if (epss.get(c, {}).get("epss") or 0) >= EPSS_HIGH)

    # --- RQ3: shared vulnerable-dependency SPOFs ----------------------------
    shared = provenance.read_interim_json("shared_dependencies.json")
    spofs = [n for n in shared
             if (n.get("max_severity") not in (None, "none"))
             and len(n.get("reachable_systems") or []) >= 2]

    spof_detail: list[dict] = []
    for n in spofs:
        pkg = n["package"]
        cves: set[str] = set()
        for sid in n.get("systems", []):
            cves |= dep_idx.get((pkg.lower(), sid), set())
        kev_cves = sorted(c for c in cves if c in kev)
        max_epss = max((epss.get(c, {}).get("epss") or 0) for c in cves) if cves else 0.0
        spof_detail.append({
            "package": pkg, "ecosystem": n.get("ecosystem"),
            "systems": sorted(n.get("systems", [])),
            "reachable_systems": sorted(n.get("reachable_systems", [])),
            "max_severity": n.get("max_severity"),
            "cves": sorted(cves), "kev_cves": kev_cves, "max_epss": round(max_epss, 4),
        })
        for c in sorted(cves):
            exp = _exposure(c, kev, epss)
            rows.append({"scope": "shared_spof", "cve": c, "package": pkg,
                         "ecosystem": n.get("ecosystem"),
                         "systems": ";".join(sorted(n.get("systems", []))), **exp})

    spof_with_kev = [d for d in spof_detail if d["kev_cves"]]
    spof_high_epss = [d for d in spof_detail if d["max_epss"] >= EPSS_HIGH]

    # --- write per-CVE CSV --------------------------------------------------
    out_csv = config.PROCESSED_DIR / "exploit_exposure.csv"
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["scope", "cve", "package", "ecosystem", "systems",
              "in_kev", "epss", "epss_percentile"]
    with out_csv.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # --- summary (headline numbers for the paper) ---------------------------
    summary = {
        "snapshot_date": config.snapshot_date(),
        "kev_catalog_count": len(kev),
        "disclosed": {
            "n_cve": len(disclosed_cves),
            "n_in_kev": len(disc_kev),
            "kev_cves": disc_kev,
            "n_epss_ge_0.5": len(disc_high),
            "epss_ge_0.5_cves": disc_high,
            "max_epss_cve": max(disclosed_cves,
                                key=lambda c: epss.get(c, {}).get("epss") or 0,
                                default=None),
        },
        "shared_spofs": {
            "n_reachable_vuln_deps": len(spof_detail),
            "n_with_kev_cve": len(spof_with_kev),
            "kev_spofs": [{"package": d["package"], "kev_cves": d["kev_cves"],
                           "systems": d["systems"]} for d in spof_with_kev],
            "n_max_epss_ge_0.5": len(spof_high_epss),
            "detail": spof_detail,
        },
    }
    out_json = config.PROCESSED_DIR / "exploit_exposure_summary.json"
    out_json.write_text(json.dumps(summary, indent=2))

    log.info("disclosed: %d CVEs, %d in KEV, %d with EPSS>=%.1f",
             len(disclosed_cves), len(disc_kev), len(disc_high), EPSS_HIGH)
    log.info("shared SPOFs: %d reachable vuln deps, %d carry a KEV CVE, %d with max EPSS>=%.1f",
             len(spof_detail), len(spof_with_kev), len(spof_high_epss), EPSS_HIGH)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
