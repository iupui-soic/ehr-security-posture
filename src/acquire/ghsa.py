"""Fetch GitHub Security Advisory (GHSA) records (Construct B).

Two complementary sources, deduplicated by GHSA id:

  1. **Repository advisories** -- ``GET /repos/{owner}/{repo}/security-advisories``.
     This is where projects self-publish (OpenEMR and OpenMRS do, heavily); these
     GHSAs are NOT in GitHub's *global* package database, so the global endpoint
     404s for them. This is the authoritative source for app-level advisories and
     carries CWE, CVSS, severity, credits, and references.
  2. **Global advisories** -- ``GET /advisories/{ghsa_id}`` for any GHSA id surfaced
     via OSV that is a package-database advisory.

Runs after osv_query.py. A GITHUB_TOKEN is recommended (rate limits); the data is
public.
"""
from __future__ import annotations

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, github_client
from ..common.logging import get_logger
from ..common.repos import parse_repo

log = get_logger("ghsa")
SOURCE = "ghsa"


def _repo_advisories(client: Client, owner: str, repo: str) -> list[dict]:
    out: list[dict] = []
    try:
        for page in client.paginate(
                f"/repos/{owner}/{repo}/security-advisories",
                params={"per_page": 100, "state": "published"}):
            if isinstance(page, list):
                out.extend(page)
    except requests.RequestException as exc:
        log.warning("repo advisories failed for %s/%s: %s", owner, repo, exc)
    return out


def _ghsa_ids_from_osv(system_id: str) -> list[str]:
    osv = provenance.load_or_none("osv", f"{system_id}.json")
    ids: set[str] = set()
    if osv:
        for adv in osv.get("advisories", []):
            for cand in [adv.get("id", "")] + list(adv.get("aliases", []) or []):
                if cand.startswith("GHSA-"):
                    ids.add(cand)
    return sorted(ids)


def _global_advisory(client: Client, ghsa_id: str) -> dict | None:
    try:
        resp = client.get(f"/advisories/{ghsa_id}")
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        log.warning("global advisory failed for %s: %s", ghsa_id, exc)
    return None


def collect_system(client: Client, system) -> dict:
    by_id: dict[str, dict] = {}

    # 1) repository-level advisories (self-published)
    for repo_str in system.core_repos:
        repo = parse_repo(repo_str)
        if not repo.is_github:
            continue
        for adv in _repo_advisories(client, repo.owner, repo.name):
            gid = adv.get("ghsa_id")
            if gid:
                adv["_source"] = "repo"
                adv["_repo"] = repo.host_full
                by_id[gid] = adv

    # 2) global advisories for GHSA ids from OSV not already covered
    for gid in _ghsa_ids_from_osv(system.id):
        if gid in by_id:
            continue
        g = _global_advisory(client, gid)
        if g:
            g["_source"] = "global"
            by_id[gid] = g

    advisories = list(by_id.values())
    return {
        "system_id": system.id,
        "n_advisories": len(advisories),
        "n_repo_level": sum(1 for a in advisories if a.get("_source") == "repo"),
        "advisories": advisories,
        "snapshot_date": config.snapshot_date(),
    }


def main() -> int:
    args = parse_common_args(__doc__)
    client = github_client()
    if not config.github_token():
        log.warning("GITHUB_TOKEN not set: advisory endpoints limited to 60 req/hr.")
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
            log.info("ok %s -> %s (advisories=%d, repo-level=%d)",
                     system.id, ptr, rec["n_advisories"], rec["n_repo_level"])
        except (requests.RequestException, ValueError) as exc:
            log.error("FAILED GHSA %s: %s", system.id, exc)
            failures.append({"system_id": system.id, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
