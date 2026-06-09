"""Acquire per-repo descriptors for Codeberg-hosted systems (GNU Health).

Mirrors github_meta.py but against the Gitea API (codeberg.org/api/v1). The Gitea
API surface is smaller and some endpoints differ or may be absent; missing data is
recorded as null and never imputed. SECURITY.md presence is probed directly.
"""
from __future__ import annotations

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, codeberg_client
from ..common.logging import get_logger
from ..common.repos import Repo, parse_repo

log = get_logger("codeberg_meta")
SOURCE = "codeberg"

# Common locations a coordinated-disclosure policy may live.
SECURITY_PATHS = ["SECURITY.md", ".gitea/SECURITY.md", "docs/SECURITY.md"]


def _exists(client: Client, repo: Repo, path: str) -> bool:
    try:
        resp = client.get(f"/repos/{repo.full_name}/contents/{path}")
        return resp.status_code == 200
    except requests.RequestException:
        return False


def _paginate_all(client: Client, path: str, limit: int = 50, max_pages: int = 50) -> list:
    out: list = []
    page = 1
    while page <= max_pages:
        resp = client.get(path, params={"page": page, "limit": limit})
        if resp.status_code != 200:
            break
        batch = resp.json()
        if not isinstance(batch, list) or not batch:
            break
        out.extend(batch)
        if len(batch) < limit:
            break
        page += 1
    return out


def _contributors_count(client: Client, repo: Repo) -> int | None:
    # Gitea exposes a contributors endpoint on newer versions; tolerate absence.
    try:
        resp = client.get(f"/repos/{repo.full_name}/contributors")
        if resp.status_code == 200 and isinstance(resp.json(), list):
            return len(resp.json())
    except requests.RequestException:
        pass
    return None


def _latest_commit_date(client: Client, repo: Repo) -> str | None:
    try:
        resp = client.get(f"/repos/{repo.full_name}/commits", params={"limit": 1})
        if resp.status_code == 200 and resp.json():
            c = resp.json()[0]
            return (c.get("commit", {}).get("committer", {}) or {}).get("date")
    except (requests.RequestException, ValueError, KeyError, IndexError):
        pass
    return None


def collect_repo(client: Client, repo: Repo) -> dict:
    repo_obj = client.get_json(f"/repos/{repo.full_name}")
    try:
        languages = client.get_json(f"/repos/{repo.full_name}/languages")
    except (requests.RequestException, ValueError):
        languages = {}
    releases = _paginate_all(client, f"/repos/{repo.full_name}/releases")
    sec_path = next((p for p in SECURITY_PATHS if _exists(client, repo, p)), None)
    return {
        "system_repo": repo.host_full,
        "full_name": repo.full_name,
        "repo": repo_obj,
        "languages": languages,
        "releases": releases,
        "release_count": len(releases),
        "contributors_count": _contributors_count(client, repo),
        "latest_commit_date": _latest_commit_date(client, repo),
        "has_security_policy": sec_path is not None,
        "security_policy_path": sec_path,
        "snapshot_date": config.snapshot_date(),
    }


def main() -> int:
    args = parse_common_args(__doc__)
    client = codeberg_client()
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        if system.forge != "codeberg":
            continue
        for repo_str in system.core_repos:
            repo = parse_repo(repo_str)
            name = f"{system.id}__{repo.slug}.json"
            if provenance.raw_exists(SOURCE, name) and not args.refresh:
                log.info("skip (cached): %s", name)
                continue
            try:
                rec = collect_repo(client, repo)
                rec["system_id"] = system.id
                ptr = provenance.write_json(SOURCE, name, rec)
                log.info("ok %s -> %s (contrib=%s, releases=%d, security=%s)",
                         repo.full_name, ptr, rec["contributors_count"],
                         rec["release_count"], rec["has_security_policy"])
            except (requests.RequestException, ValueError) as exc:
                log.error("FAILED %s: %s", repo.full_name, exc)
                failures.append({"system_id": system.id,
                                 "repo": repo.host_full, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
        log.warning("%d repo(s) failed; logged to _failures.json", len(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
