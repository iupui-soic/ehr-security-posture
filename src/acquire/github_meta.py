"""Acquire per-repo descriptors from the GitHub REST API (Construct D context).

For every GitHub-hosted core repo we archive: the repo object, language bytes,
release list, contributor count, latest-commit date, and community-profile signals.
Security-policy presence is probed directly via the contents API (the community
profile's files.security field is unreliable — it returns null even when SECURITY.md
exists at the repo root). All responses are archived verbatim under
data/raw/github/<date>/ for provenance and idempotent re-runs.

GNU Health lives on Codeberg and is handled by codeberg_meta.py.
"""
from __future__ import annotations

import re

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, github_client
from ..common.logging import get_logger
from ..common.repos import Repo, parse_repo

log = get_logger("github_meta")
SOURCE = "github"

# Standard locations GitHub recognizes for a coordinated-disclosure policy,
# both in the repo itself and in the org-level `.github` default-files repo.
SECURITY_PATHS = ["SECURITY.md", "docs/SECURITY.md", ".github/SECURITY.md"]


def _contributor_count(client: Client, repo: Repo) -> int | None:
    """Total contributors via the Link rel=last trick (cheap, 1 request)."""
    try:
        resp = client.get(f"/repos/{repo.full_name}/contributors",
                          params={"per_page": 1, "anon": "true"})
        if resp.status_code != 200:
            return None
        last = resp.links.get("last", {}).get("url")
        if last:
            m = re.search(r"[?&]page=(\d+)", last)
            if m:
                return int(m.group(1))
        return len(resp.json())
    except (requests.RequestException, ValueError) as exc:
        log.warning("contributor count failed for %s: %s", repo.full_name, exc)
        return None


def _latest_commit_date(client: Client, repo: Repo, default_branch: str) -> str | None:
    try:
        data = client.get_json(f"/repos/{repo.full_name}/commits",
                               params={"per_page": 1, "sha": default_branch})
        if data:
            return data[0]["commit"]["committer"]["date"]
    except (requests.RequestException, ValueError, KeyError, IndexError) as exc:
        log.warning("latest commit failed for %s: %s", repo.full_name, exc)
    return None


def _community_profile(client: Client, repo: Repo) -> dict | None:
    try:
        resp = client.get(f"/repos/{repo.full_name}/community/profile")
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        log.warning("community profile failed for %s: %s", repo.full_name, exc)
    return None


def _file_exists(client: Client, full_name: str, path: str) -> bool:
    try:
        return client.get(f"/repos/{full_name}/contents/{path}").status_code == 200
    except requests.RequestException:
        return False


def _security_policy(client: Client, repo: Repo) -> tuple[bool, str | None]:
    """Locate a coordinated-disclosure policy by probing the contents API directly.

    Checks the repo's standard locations first, then falls back to the org-level
    `<owner>/.github` default-files repo — mirroring how GitHub itself resolves a
    security policy. Preferred over the community-profile files.security field,
    which returns null even when SECURITY.md is present at the repo root.
    Returns (has_policy, path) where path is null when none is found.
    """
    for p in SECURITY_PATHS:
        if _file_exists(client, repo.full_name, p):
            return True, p
    org_repo = f"{repo.owner}/.github"
    for p in SECURITY_PATHS:
        if _file_exists(client, org_repo, p):
            return True, f"{org_repo}/{p}"
    return False, None


def collect_repo(client: Client, repo: Repo) -> dict:
    repo_obj = client.get_json(f"/repos/{repo.full_name}")
    languages = client.get_json(f"/repos/{repo.full_name}/languages")
    releases = list(_paginate_all(client, f"/repos/{repo.full_name}/releases"))
    profile = _community_profile(client, repo)
    has_sec, sec_path = _security_policy(client, repo)
    record = {
        "system_repo": repo.host_full,
        "full_name": repo.full_name,
        "repo": repo_obj,
        "languages": languages,
        "releases": releases,
        "release_count": len(releases),
        "contributors_count": _contributor_count(client, repo),
        "latest_commit_date": _latest_commit_date(
            client, repo, repo_obj.get("default_branch", "main")),
        "community_profile": profile,
        "has_security_policy": has_sec,
        "security_policy_path": sec_path,
        "snapshot_date": config.snapshot_date(),
    }
    return record


def _paginate_all(client: Client, path: str, params: dict | None = None) -> list:
    out: list = []
    base = dict(params or {})
    base.setdefault("per_page", 100)
    for page in client.paginate(path, params=base):
        if isinstance(page, list):
            out.extend(page)
        else:
            out.append(page)
    return out


def main() -> int:
    args = parse_common_args(__doc__)
    client = github_client()
    if not config.github_token():
        log.warning("GITHUB_TOKEN not set: unauthenticated GitHub limit is 60 req/hr; "
                    "acquisition will likely rate-limit. Set it in .env.")

    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        if system.forge != "github":
            log.info("skip %s (forge=%s, handled elsewhere)", system.id, system.forge)
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
                log.info("ok %s -> %s (contrib=%s, releases=%d)",
                         repo.full_name, ptr, rec["contributors_count"],
                         rec["release_count"])
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
