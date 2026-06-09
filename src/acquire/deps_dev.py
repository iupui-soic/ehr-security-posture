"""Look up known vulnerabilities for SBOM dependencies (Construct C centerpiece).

For each package in a system's Syft SBOM(s) we query OSV.dev's batch endpoint by
purl (OSV covers every ecosystem here, incl. Packagist/PHP which deps.dev does
not). Vulnerability *details* (severity) are fetched once per id and cached under
data/raw/osv_vulns/ so a dependency shared across systems is scored consistently.
deps.dev enriches vulnerable packages where it supports the ecosystem.

Direct-vs-transitive is derived later from the CycloneDX dependency graph
(transform/dependency_graph.py); this module only produces the vuln mapping.

Runs after sbom_generate.py. No credentials required.
"""
from __future__ import annotations

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, deps_dev_client, osv_client
from ..common.logging import get_logger
from ..common.repos import parse_repo
from ..common.severity import severity_from_osv

log = get_logger("deps_dev")
SOURCE = "depvulns"
VULN_CACHE = "osv_vulns"

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vid}"
BATCH = 500

# purl type -> (OSV ecosystem, deps.dev system or None)
ECOSYSTEM = {
    "maven": ("Maven", "maven"),
    "npm": ("npm", "npm"),
    "pypi": ("PyPI", "pypi"),
    "composer": ("Packagist", None),     # deps.dev has no PHP
    "golang": ("Go", "go"),
    "gem": ("RubyGems", None),
    "cargo": ("crates.io", "cargo"),
    "nuget": ("NuGet", "nuget"),
}


def _purl_type(purl: str) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].split("@", 1)[0]


def _system_components(system) -> dict[str, dict]:
    """Unique packages across the system's SBOMs, keyed by purl (or eco:name@ver)."""
    comps: dict[str, dict] = {}
    for repo_str in system.core_repos:
        repo = parse_repo(repo_str)
        sbom = provenance.load_or_none("sbom", f"{system.id}__{repo.slug}.cyclonedx.json")
        if not sbom:
            continue
        for c in sbom.get("components", []) or []:
            purl = c.get("purl")
            if not purl:
                continue  # skip non-package artifacts (e.g. the manifest file itself)
            ptype = _purl_type(purl)
            eco = ECOSYSTEM.get(ptype, (None, None))[0] if ptype else None
            name, ver = c.get("name"), c.get("version")
            key = purl
            if key not in comps:
                comps[key] = {"purl": purl, "name": name, "version": ver,
                              "ecosystem": eco, "purl_type": ptype}
    return comps


def _osv_batch(client: Client, keys: list[str], comps: dict) -> dict[str, list[str]]:
    """Return {key: [vuln_id,...]} for packages with vulns."""
    hits: dict[str, list[str]] = {}
    # Only query packages with a resolved version: OSV needs an exact version to
    # decide if THIS version is affected. Version-less manifest deps still count
    # for the shared-dependency analysis, but are not vuln-assessed (no overcount).
    keys = [k for k in keys if comps[k].get("version")]
    for i in range(0, len(keys), BATCH):
        chunk = keys[i:i + BATCH]
        queries = []
        for k in chunk:
            c = comps[k]
            if c["purl"]:
                queries.append({"package": {"purl": c["purl"]}})
            elif c["ecosystem"] and c["name"]:
                q = {"package": {"ecosystem": c["ecosystem"], "name": c["name"]}}
                if c["version"]:
                    q["version"] = c["version"]
                queries.append(q)
            else:
                queries.append({})  # keep index alignment; will yield no result
        try:
            data = client.post_json(OSV_BATCH_URL, {"queries": queries})
        except (requests.RequestException, ValueError) as exc:
            log.warning("OSV batch chunk failed (%d-%d): %s", i, i + len(chunk), exc)
            continue
        for k, res in zip(chunk, data.get("results", [])):
            vulns = res.get("vulns", []) or []
            if vulns:
                hits[k] = [v["id"] for v in vulns]
    return hits


def _vuln_detail(client: Client, vid: str) -> dict | None:
    """Fetch + cache an OSV vuln record; return a compact scored summary."""
    cached = provenance.load_or_none(VULN_CACHE, f"{vid}.json")
    if cached is None:
        try:
            resp = client.get(OSV_VULN_URL.format(vid=vid))
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            cached = resp.json()
            provenance.write_json(VULN_CACHE, f"{vid}.json", cached)
        except (requests.RequestException, ValueError) as exc:
            log.warning("OSV vuln detail failed for %s: %s", vid, exc)
            return None
    sev_bin, score, cvss_ver = severity_from_osv(cached)
    return {
        "id": cached.get("id", vid),
        "aliases": cached.get("aliases", []),
        "severity": sev_bin,
        "cvss_score": score,
        "cvss_version": cvss_ver,
        "summary": cached.get("summary"),
    }


def collect_system(osv: Client, dd: Client, system) -> dict:
    comps = _system_components(system)
    keys = list(comps)
    hits = _osv_batch(osv, keys, comps) if keys else {}

    # score unique vuln ids (cached across systems)
    detail: dict[str, dict] = {}
    for ids in hits.values():
        for vid in ids:
            if vid not in detail:
                d = _vuln_detail(osv, vid)
                if d:
                    detail[vid] = d

    vuln_map = {}
    for k, ids in hits.items():
        c = comps[k]
        vuln_map[k] = {**c, "vuln_ids": ids}

    return {
        "system_id": system.id,
        "n_packages": len(comps),
        "n_vulnerable": len(vuln_map),
        "vuln_map": vuln_map,
        "vuln_details": detail,
        "snapshot_date": config.snapshot_date(),
    }


def main() -> int:
    args = parse_common_args(__doc__)
    osv = osv_client()
    dd = deps_dev_client()
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        name = f"{system.id}.json"
        if provenance.raw_exists(SOURCE, name) and not args.refresh:
            log.info("skip (cached): %s", name)
            continue
        try:
            rec = collect_system(osv, dd, system)
            ptr = provenance.write_json(SOURCE, name, rec)
            log.info("ok %s -> %s (packages=%d vulnerable=%d)",
                     system.id, ptr, rec["n_packages"], rec["n_vulnerable"])
        except (requests.RequestException, ValueError) as exc:
            log.error("FAILED depvulns %s: %s", system.id, exc)
            failures.append({"system_id": system.id, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
