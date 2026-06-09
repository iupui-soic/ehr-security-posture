"""Enrich/deduplicate disclosed advisories via OSV.dev (Construct B).

OSV mirrors GitHub Security Advisories and normalises affected ranges + fix
references. We use it two ways:

  1. **By id** — for every CVE found in NVD (cve_nvd.py), fetch its OSV record
     (``GET /v1/vulns/{id}``). This deduplicates NVD<->OSV<->GHSA by id and pulls
     fix references / fixed versions that feed remediation-latency (opportunistic).
  2. **By package** — if a system declares its own published packages in
     ``identifiers.osv_packages`` (ecosystem+name), query OSV for advisories about
     those packages to catch GHSA-only advisories that have no CVE.

Runs after cve_nvd.py. No credentials required.
"""
from __future__ import annotations

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, osv_client
from ..common.logging import get_logger

log = get_logger("osv_query")
SOURCE = "osv"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vid}"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _nvd_cve_ids(system_id: str) -> list[str]:
    nvd = provenance.load_or_none("nvd", f"{system_id}.json")
    if not nvd:
        return []
    return [w["cve"]["id"] for w in nvd.get("vulnerabilities", [])]


def _fetch_vuln(client: Client, vid: str) -> dict | None:
    try:
        resp = client.get(OSV_VULN_URL.format(vid=vid))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("OSV vuln fetch failed for %s: %s", vid, exc)
        return None


def _query_package(client: Client, ecosystem: str, name: str) -> list[dict]:
    body = {"package": {"ecosystem": ecosystem, "name": name}}
    try:
        data = client.post_json(OSV_QUERY_URL, body)
        return data.get("vulns", []) or []
    except (requests.RequestException, ValueError) as exc:
        log.warning("OSV package query failed for %s/%s: %s", ecosystem, name, exc)
        return []


def collect_system(client: Client, system) -> dict:
    by_id: dict[str, dict] = {}

    # 1) enrich NVD CVEs by id
    cve_ids = _nvd_cve_ids(system.id)
    for vid in cve_ids:
        rec = _fetch_vuln(client, vid)
        if rec:
            by_id[rec.get("id", vid)] = rec
            for alias in rec.get("aliases", []) or []:
                by_id.setdefault(alias, rec)

    # 2) package-level advisories (GHSA-only) if declared
    osv_packages = (system.raw.get("identifiers", {}) or {}).get("osv_packages", []) or []
    pkg_hits: list[dict] = []
    for pkg in osv_packages:
        eco, nm = pkg.get("ecosystem"), pkg.get("name")
        if not eco or not nm:
            continue
        for v in _query_package(client, eco, nm):
            vid = v.get("id")
            pkg_hits.append({"package": f"{eco}/{nm}", "id": vid})
            if vid and vid not in by_id:
                full = _fetch_vuln(client, vid)
                if full:
                    by_id[vid] = full

    # canonical dedup: prefer GHSA/OSV native id, collapse alias duplicates
    canonical: dict[str, dict] = {}
    for vid, rec in by_id.items():
        cid = rec.get("id", vid)
        canonical[cid] = rec

    return {
        "system_id": system.id,
        "queried_cve_ids": cve_ids,
        "osv_packages": osv_packages,
        "package_hits": pkg_hits,
        "advisories": list(canonical.values()),
        "n_advisories": len(canonical),
        "snapshot_date": config.snapshot_date(),
    }


def main() -> int:
    args = parse_common_args(__doc__)
    client = osv_client()
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        name = f"{system.id}.json"
        if provenance.raw_exists(SOURCE, name) and not args.refresh:
            log.info("skip (cached): %s", name)
            continue
        try:
            rec = collect_system(client, system)
            ptr = provenance.write_json(SOURCE, name, rec)
            log.info("ok %s -> %s (advisories=%d)", system.id, ptr, rec["n_advisories"])
        except (requests.RequestException, ValueError) as exc:
            log.error("FAILED OSV %s: %s", system.id, exc)
            failures.append({"system_id": system.id, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
